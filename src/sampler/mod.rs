use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::Result;

use crate::model::derive::host_from_device;
use crate::model::types::{MountCounters, MountDerived, MountView, OpDerived, Snapshot};

pub mod dns;
#[cfg(feature = "ebpf")]
pub mod ebpf;
pub mod hist;
pub mod mounts;
pub mod mountstats;
pub mod rpc;
pub mod sockets;

/// Runtime selection of the latency backend, independent of which backends
/// were compiled in. `Auto` uses eBPF when the feature is built and attach
/// succeeds, otherwise falls back to /proc. `Proc` forces /proc only even on
/// an eBPF-enabled build. `Ebpf` insists on eBPF and surfaces a louder warning
/// when it can't attach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    #[default]
    Auto,
    Proc,
    Ebpf,
}

#[derive(Debug, Clone)]
pub struct SamplerConfig {
    pub interval: Arc<AtomicU64>,
    pub no_dns: bool,
    pub remote_ports: Vec<u16>,
    pub backend: Backend,
}

pub fn spawn_sampler(cfg: SamplerConfig) -> Receiver<Result<Snapshot>> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut prev: Option<(SystemTime, Vec<MountCounters>)> = None;
        let mut dns_cache = dns::DnsCache::new(Duration::from_secs(60));

        // Stash the eBPF startup outcome here. We can't print to stderr
        // from this thread because the TUI has already taken the alt
        // screen — that would corrupt rendered frames. Instead we route
        // through `partial_errors` on the very first snapshot so the
        // status bar surfaces it normally.
        #[cfg(feature = "ebpf")]
        let (mut enricher, mut pending_ebpf_error): (Option<ebpf::Enricher>, Option<String>) =
            if cfg.backend == Backend::Proc {
                (None, None)
            } else {
                match ebpf::Enricher::try_new() {
                    Ok(e) => (Some(e), None),
                    // Keep the "ebpf disabled:" wording for Auto (documented in
                    // the README troubleshooting section); make Ebpf louder
                    // since the user explicitly asked for it.
                    Err(e) if cfg.backend == Backend::Ebpf => {
                        (None, Some(format!("ebpf backend requested but unavailable: {e:#}")))
                    }
                    Err(e) => (None, Some(format!("ebpf disabled: {e:#}"))),
                }
            };

        loop {
            let now = SystemTime::now();
            let mounts = match mountstats::read_mountstats() {
                Ok(v) => v,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    thread::sleep(Duration::from_millis(cfg.interval.load(Ordering::Relaxed)));
                    continue;
                }
            };
            let mut partial_errors: Vec<String> = Vec::new();
            let mount_opts = fallback("mounts", &mut partial_errors, mounts::read_mount_options());
            let mount_devs = fallback("mountinfo", &mut partial_errors, mounts::read_mount_devs());
            let rpc = fallback("rpc", &mut partial_errors, rpc::read_rpc_client());
            let sockets = fallback(
                "sockets",
                &mut partial_errors,
                sockets::read_observed_nfs(&cfg.remote_ports),
            );

            // Pull the per-dev BPF snapshot before the mount loop so each
            // MountView can carry its own latency split. The host-wide view
            // is gone — the Hist tab follows the selected mount instead.
            #[cfg(feature = "ebpf")]
            let per_dev_bpf: HashMap<u32, crate::model::types::BpfLatency> = match enricher.as_mut() {
                Some(e) => match e.snapshot() {
                    Ok(b) => b,
                    Err(err) => {
                        partial_errors.push(format!("ebpf: {err:#}"));
                        HashMap::new()
                    }
                },
                None => HashMap::new(),
            };
            #[cfg(feature = "ebpf")]
            let bpf_attached = enricher.is_some();
            #[cfg(feature = "ebpf")]
            if let Some(msg) = pending_ebpf_error.take() {
                partial_errors.push(msg);
            }
            #[cfg(not(feature = "ebpf"))]
            let per_dev_bpf: HashMap<u32, crate::model::types::BpfLatency> = HashMap::new();
            #[cfg(not(feature = "ebpf"))]
            let bpf_attached = false;

            let dt_secs = prev
                .as_ref()
                .and_then(|(ts, _)| now.duration_since(*ts).ok())
                .map(|d| d.as_secs_f64())
                .unwrap_or((cfg.interval.load(Ordering::Relaxed) as f64) / 1000.0);

            let prev_map: HashMap<&str, &MountCounters> = prev
                .as_ref()
                .map(|(_, p)| p.iter().map(|m| (m.mountpoint.as_str(), m)).collect())
                .unwrap_or_default();

            let mut views = Vec::new();
            for mut m in mounts {
                if let Some(extra) = mount_opts.get(&m.mountpoint) {
                    for (k, v) in extra {
                        m.options.entry(k.clone()).or_insert(v.clone());
                    }
                    if m.nconnect.is_none() {
                        m.nconnect = extra.get("nconnect").and_then(|v| v.parse::<u32>().ok());
                    }
                }
                m.st_dev = mount_devs.get(&m.mountpoint).copied();

                let host = host_from_device(&m.device).unwrap_or_default();
                let resolved = if cfg.no_dns { Vec::new() } else { dns_cache.resolve(host) };
                let mut match_ips = Vec::new();
                if let Some(ip) = m.addr {
                    match_ips.push(ip);
                }
                for ip in resolved.iter().copied() {
                    if !match_ips.contains(&ip) {
                        match_ips.push(ip);
                    }
                }

                let mut observed_by_ip = Vec::new();
                let mut observed_total = 0u64;
                for ip in match_ips {
                    if let Some(c) = sockets.by_remote_ip.get(&ip).copied() {
                        observed_total += c;
                        observed_by_ip.push((ip, c));
                    }
                }

                let mut derived = derive_rates(&m, prev_map.get(m.mountpoint.as_str()).copied(), dt_secs, observed_total, observed_by_ip);
                derived.bpf = m.st_dev.and_then(|d| per_dev_bpf.get(&d).cloned());
                views.push(MountView {
                    counters: m,
                    derived,
                    resolved_ips: resolved,
                });
            }

            let prev_counters = views.iter().map(|v| v.counters.clone()).collect::<Vec<_>>();

            let snap = Snapshot {
                ts: now,
                dt_secs,
                mounts: views,
                rpc,
                raw_tcp_matches: sockets.raw_matches,
                partial_errors,
                bpf_attached,
            };

            let _ = tx.send(Ok(snap));
            prev = Some((now, prev_counters));
            thread::sleep(Duration::from_millis(cfg.interval.load(Ordering::Relaxed)));
        }
    });
    rx
}

fn derive_rates(
    curr: &MountCounters,
    prev: Option<&MountCounters>,
    dt_secs: f64,
    observed_conns: u64,
    observed_by_ip: Vec<(IpAddr, u64)>,
) -> MountDerived {
    if dt_secs <= 0.0 {
        return MountDerived::default();
    }

    let mut read_bps = 0.0;
    let mut write_bps = 0.0;
    let mut ops_per_sec = 0.0;
    let mut rtt_sum = 0.0;
    let mut exe_sum = 0.0;
    let mut cnt: usize = 0;
    let mut per_op = Vec::new();
    let mut total_delta_calls = 0u64;

    for (name, op) in &curr.ops {
        let prev_op = prev.and_then(|p| p.ops.get(name));
        total_delta_calls += delta_u64(prev_op.map(|x| x.calls), op.calls);
    }

    for (name, op) in &curr.ops {
        let prev_op = prev.and_then(|p| p.ops.get(name));
        let delta_calls = delta_u64(prev_op.map(|x| x.calls), op.calls);
        let delta_sent = delta_u64(prev_op.map(|x| x.bytes_sent), op.bytes_sent);
        let delta_recv = delta_u64(prev_op.map(|x| x.bytes_recv), op.bytes_recv);
        let delta_bytes = delta_sent + delta_recv;
        let delta_rtt = delta_f64(prev_op.map(|x| x.rtt_ms_total), op.rtt_ms_total);
        let delta_exe = delta_f64(prev_op.map(|x| x.exe_ms_total), op.exe_ms_total);

        // For READ the payload is bytes_recv (server -> client);
        // for WRITE the payload is bytes_sent (client -> server).
        if name == "READ" {
            read_bps = (delta_recv as f64) / dt_secs;
        }
        if name == "WRITE" {
            write_bps = (delta_sent as f64) / dt_secs;
        }
        ops_per_sec += (delta_calls as f64) / dt_secs;

        if delta_calls > 0 {
            rtt_sum += delta_rtt / delta_calls as f64;
            exe_sum += delta_exe / delta_calls as f64;
            cnt += 1;
        }

        per_op.push(OpDerived {
            op: name.clone(),
            ops_per_sec: (delta_calls as f64) / dt_secs,
            bytes_per_sec: (delta_bytes as f64) / dt_secs,
            share_pct: if total_delta_calls > 0 {
                (delta_calls as f64) * 100.0 / (total_delta_calls as f64)
            } else {
                0.0
            },
            avg_rtt_ms: (delta_calls > 0).then_some(delta_rtt / delta_calls as f64),
            avg_exe_ms: (delta_calls > 0).then_some(delta_exe / delta_calls as f64),
        });
    }

    per_op.sort_by(|a, b| b.ops_per_sec.partial_cmp(&a.ops_per_sec).unwrap_or(std::cmp::Ordering::Equal));

    MountDerived {
        read_bps,
        write_bps,
        ops_per_sec,
        avg_rtt_ms: (cnt > 0).then(|| rtt_sum / cnt as f64),
        avg_exe_ms: (cnt > 0).then(|| exe_sum / cnt as f64),
        observed_conns,
        observed_by_ip,
        per_op,
        bpf: None,
    }
}

fn fallback<T: Default>(label: &str, errors: &mut Vec<String>, r: Result<T>) -> T {
    r.unwrap_or_else(|e| {
        errors.push(format!("{label}: {e:#}"));
        T::default()
    })
}

fn delta_u64(prev: Option<u64>, curr: u64) -> u64 {
    prev.map_or(0, |p| curr.saturating_sub(p))
}

fn delta_f64(prev: Option<f64>, curr: f64) -> f64 {
    prev.map_or(0.0, |p| (curr - p).max(0.0))
}

#[cfg(test)]
mod tests {
    use super::{delta_u64, derive_rates};
    use crate::model::types::{MountCounters, OpCounters};
    use std::collections::HashMap;

    #[test]
    fn delta_handles_reset() {
        assert_eq!(delta_u64(Some(10), 4), 0);
        assert_eq!(delta_u64(Some(10), 15), 5);
    }

    #[test]
    fn derive_rates_basic() {
        let mut prev_ops = HashMap::new();
        prev_ops.insert(
            "READ".to_string(),
            OpCounters { op: "READ".to_string(), calls: 10, bytes_sent: 280, bytes_recv: 1000, rtt_ms_total: 50.0, exe_ms_total: 70.0 },
        );
        let prev = MountCounters {
            device: "s:/e".to_string(), mountpoint: "/m".to_string(), fstype: "nfs4".to_string(),
            vers: None, proto: None, nconnect: None, addr: None, clientaddr: None, st_dev: None, options: HashMap::new(), ops: prev_ops, raw_block: String::new(),
        };

        let mut curr_ops = HashMap::new();
        curr_ops.insert(
            "READ".to_string(),
            OpCounters { op: "READ".to_string(), calls: 20, bytes_sent: 560, bytes_recv: 3000, rtt_ms_total: 150.0, exe_ms_total: 170.0 },
        );
        let curr = MountCounters {
            device: "s:/e".to_string(), mountpoint: "/m".to_string(), fstype: "nfs4".to_string(),
            vers: None, proto: None, nconnect: None, addr: None, clientaddr: None, st_dev: None, options: HashMap::new(), ops: curr_ops, raw_block: String::new(),
        };

        let d = derive_rates(&curr, Some(&prev), 2.0, 0, vec![]);
        // 2000 bytes_recv delta over 2s = 1000 B/s
        assert_eq!(d.read_bps, 1000.0);
        assert!(d.ops_per_sec > 0.0);
        assert_eq!(d.avg_exe_ms, Some(10.0));
        assert_eq!(d.avg_rtt_ms, Some(10.0));
    }

    #[test]
    fn derive_rates_uses_bytes_sent_for_write() {
        let mut prev_ops = HashMap::new();
        prev_ops.insert(
            "WRITE".to_string(),
            OpCounters { op: "WRITE".to_string(), calls: 5, bytes_sent: 4096, bytes_recv: 140, rtt_ms_total: 10.0, exe_ms_total: 15.0 },
        );
        let prev = MountCounters {
            device: "s:/e".to_string(), mountpoint: "/m".to_string(), fstype: "nfs4".to_string(),
            vers: None, proto: None, nconnect: None, addr: None, clientaddr: None, st_dev: None, options: HashMap::new(), ops: prev_ops, raw_block: String::new(),
        };

        let mut curr_ops = HashMap::new();
        curr_ops.insert(
            "WRITE".to_string(),
            OpCounters { op: "WRITE".to_string(), calls: 10, bytes_sent: 1052672, bytes_recv: 280, rtt_ms_total: 30.0, exe_ms_total: 45.0 },
        );
        let curr = MountCounters {
            device: "s:/e".to_string(), mountpoint: "/m".to_string(), fstype: "nfs4".to_string(),
            vers: None, proto: None, nconnect: None, addr: None, clientaddr: None, st_dev: None, options: HashMap::new(), ops: curr_ops, raw_block: String::new(),
        };

        let d = derive_rates(&curr, Some(&prev), 1.0, 0, vec![]);
        // (1052672 - 4096) bytes_sent delta over 1s
        assert_eq!(d.write_bps, 1_048_576.0);
        assert_eq!(d.read_bps, 0.0);
    }
}
