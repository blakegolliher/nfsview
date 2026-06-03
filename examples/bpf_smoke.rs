//! Smoke test for the eBPF latency enricher.
//!
//! Loads the BPF programs, generates a small amount of NFS read traffic
//! against any NFS mount it can find, and prints the resulting per-op
//! latency snapshot. Intended to be run with sudo since attaching BPF
//! requires CAP_BPF.
//!
//!     cargo build --features=ebpf --example bpf_smoke
//!     sudo ./target/debug/examples/bpf_smoke
//!
//! Exit code 0 means probes attached, traffic was generated, and at least
//! one READ sample was observed. Non-zero indicates a real failure.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};

use nfsview::sampler::ebpf::Enricher;

fn main() -> Result<()> {
    let mounts = nfs_mounts()?;
    if mounts.is_empty() {
        return Err(anyhow!("no NFS mounts found in /proc/mounts"));
    }
    println!("found {} NFS mount(s):", mounts.len());
    for m in &mounts {
        println!("  {}", m.display());
    }

    println!("attaching BPF probes...");
    let mut enricher = Enricher::try_new()?;
    println!("attached.");

    // Best-effort cache drop so subsequent reads actually hit the wire.
    if let Err(e) = std::fs::write("/proc/sys/vm/drop_caches", "3\n") {
        eprintln!("warn: could not drop caches ({e}); cached reads may not fire READ probes");
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_w = stop.clone();
    let mounts_w = mounts.clone();
    let worker = thread::spawn(move || generate_read_traffic(&mounts_w, &stop_w));
    let drop_stop = stop.clone();
    let drop_thread = thread::spawn(move || {
        while !drop_stop.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(700));
            let _ = std::fs::write("/proc/sys/vm/drop_caches", "1\n");
        }
    });

    let mut total_seen: u64 = 0;
    let start = Instant::now();
    for tick in 0..6 {
        thread::sleep(Duration::from_secs(1));
        let per_dev = enricher.snapshot()?;
        let tick_total: u64 = per_dev.values().map(|b| b.total_samples).sum();
        total_seen += tick_total;
        if per_dev.is_empty() {
            println!("tick {tick}: no new samples this interval");
            continue;
        }
        println!(
            "tick {tick} (+{:.1}s): {} new samples across {} dev(s)",
            start.elapsed().as_secs_f64(),
            tick_total,
            per_dev.len()
        );
        for (dev, b) in &per_dev {
            println!("  dev=0x{dev:x} ({} op(s), {} samples)", b.per_op.len(), b.total_samples);
            for op in &b.per_op {
                let d = &op.dist;
                println!(
                    "    {:7} samples={:6}  p50={}  p99={}  p99.9={}  max={}",
                    op.op,
                    d.samples,
                    fmt_ns(d.p50_ns),
                    fmt_ns(d.p99_ns),
                    fmt_ns(d.p999_ns),
                    fmt_ns(d.max_ns)
                );
            }
        }
    }

    stop.store(true, Ordering::Relaxed);
    let _ = worker.join();
    let _ = drop_thread.join();

    if total_seen == 0 {
        return Err(anyhow!(
            "probes attached but no samples observed — check that read traffic actually traverses NFS"
        ));
    }
    println!("\nOK: {total_seen} total samples observed across the 6s window.");
    Ok(())
}

fn nfs_mounts() -> Result<Vec<PathBuf>> {
    let raw = std::fs::read_to_string("/proc/mounts")?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let mut fields = line.split_whitespace();
        let _src = fields.next();
        let target = fields.next();
        let fstype = fields.next();
        if let (Some(t), Some(fs)) = (target, fstype)
            && (fs == "nfs" || fs == "nfs4")
        {
            out.push(PathBuf::from(t));
        }
    }
    Ok(out)
}

/// Walk each NFS mount up to a few levels deep, reading file contents
/// to drive `nfs_initiate_read` probes. Stops as soon as `stop` flips.
fn generate_read_traffic(mounts: &[PathBuf], stop: &AtomicBool) {
    let mut files: Vec<PathBuf> = Vec::new();
    for m in mounts {
        collect_files(m, 4, 200, &mut files);
        if files.len() >= 200 {
            break;
        }
    }
    if files.is_empty() {
        eprintln!("warn: no readable files found under NFS mounts");
        return;
    }
    eprintln!("traffic: looping over {} files", files.len());

    let mut buf = vec![0u8; 64 * 1024];
    use std::io::Read;
    while !stop.load(Ordering::Relaxed) {
        for f in &files {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            let Ok(mut fh) = std::fs::File::open(f) else {
                continue;
            };
            // Read in chunks; many small reads are fine for a smoke test.
            while let Ok(n) = fh.read(&mut buf) {
                if n == 0 {
                    break;
                }
            }
        }
    }
}

fn collect_files(root: &std::path::Path, depth: usize, cap: usize, out: &mut Vec<PathBuf>) {
    if out.len() >= cap || depth == 0 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for e in entries.flatten() {
        if out.len() >= cap {
            return;
        }
        let p = e.path();
        let Ok(meta) = e.metadata() else { continue };
        if meta.is_dir() {
            collect_files(&p, depth - 1, cap, out);
        } else if meta.is_file() && meta.len() > 0 {
            out.push(p);
        }
    }
}

fn fmt_ns(ns: u64) -> String {
    if ns == 0 {
        return "-".into();
    }
    if ns >= 1_000_000_000 {
        format!("{:.1}s", (ns as f64) / 1e9)
    } else if ns >= 1_000_000 {
        format!("{:.1}ms", (ns as f64) / 1e6)
    } else if ns >= 1_000 {
        format!("{:.1}us", (ns as f64) / 1e3)
    } else {
        format!("{ns}ns")
    }
}
