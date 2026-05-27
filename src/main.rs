use std::fs;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};

use nfs_top::app::App;
use nfs_top::model::types::{SortKey, UnitsMode};
use nfs_top::sampler::{spawn_sampler, Backend, SamplerConfig};
#[cfg(feature = "crossterm")]
use nfs_top::tui;

#[derive(Parser, Debug)]
#[command(name = "nfs-top", version)]
struct Cli {
    #[arg(long, default_value_t = 1000)]
    interval_ms: u64,
    #[arg(long, default_value_t = 120)]
    history: usize,
    #[arg(long, visible_alias = "mp", default_value = "")]
    mount: String,
    #[arg(long, value_enum, default_value_t = SortArg::Ops)]
    sort: SortArg,
    #[arg(long, value_enum, default_value_t = UnitsArg::Auto)]
    units: UnitsArg,
    #[arg(long, default_value_t = false)]
    no_dns: bool,
    #[arg(long)]
    raw_dump: Option<String>,
    #[arg(long, default_value = "2049,20049")]
    remote_ports: String,
    #[arg(long, value_enum, default_value_t = BackendArg::Auto)]
    backend: BackendArg,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SortArg {
    Read,
    Write,
    Ops,
    Rtt,
    Exe,
    Mount,
    Nconnect,
    Obsconn,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum UnitsArg {
    Auto,
    M,
    G,
    T,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum BackendArg {
    Auto,
    Proc,
    Ebpf,
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{e:#}");
            2
        }
    };
    std::process::exit(code);
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let ports = parse_ports(&cli.remote_ports)?;

    if fs::metadata("/proc/self/mountstats").is_err() {
        return Err(anyhow!("/proc/self/mountstats unreadable"));
    }

    let units = match cli.units {
        UnitsArg::Auto => UnitsMode::Auto,
        UnitsArg::M => UnitsMode::MiB,
        UnitsArg::G => UnitsMode::GiB,
        UnitsArg::T => UnitsMode::TiB,
    };
    let sort = match cli.sort {
        SortArg::Read => SortKey::Read,
        SortArg::Write => SortKey::Write,
        SortArg::Ops => SortKey::Ops,
        SortArg::Rtt => SortKey::Rtt,
        SortArg::Exe => SortKey::Exe,
        SortArg::Mount => SortKey::Mount,
        SortArg::Nconnect => SortKey::Nconnect,
        SortArg::Obsconn => SortKey::ObsConn,
    };

    let backend = match cli.backend {
        BackendArg::Auto => Backend::Auto,
        BackendArg::Proc => Backend::Proc,
        BackendArg::Ebpf => Backend::Ebpf,
    };
    #[cfg(not(feature = "ebpf"))]
    if backend == Backend::Ebpf {
        return Err(anyhow!(
            "--backend=ebpf requires a build with the `ebpf` cargo feature; this \
             binary was built without it (use --backend=auto or rebuild with --features=ebpf)"
        ));
    }

    let interval = Arc::new(AtomicU64::new(cli.interval_ms));
    let rx = spawn_sampler(SamplerConfig {
        interval: Arc::clone(&interval),
        no_dns: cli.no_dns,
        remote_ports: ports,
        backend,
    });

    if let Some(path) = cli.raw_dump {
        let snap = rx.recv().context("waiting for sampler")??;
        fs::write(path, format!("{snap:#?}"))?;
        return Ok(());
    }

    #[cfg(feature = "crossterm")]
    {
        let mut app = App::new(cli.history, units, interval, sort, cli.mount);
        return tui::run(&mut app, rx);
    }

    #[cfg(not(feature = "crossterm"))]
    {
        let _ = (cli.history, units, sort);
        let snap = rx.recv().context("waiting for sampler")??;
        println!("nfs-top built without crossterm; sample mounts: {}", snap.mounts.len());
        Ok(())
    }
}

fn parse_ports(s: &str) -> Result<Vec<u16>> {
    let mut v = Vec::new();
    for p in s.split(',') {
        let n = p.trim().parse::<u16>().with_context(|| format!("invalid port: {p}"))?;
        v.push(n);
    }
    if v.is_empty() {
        return Err(anyhow!("no ports specified"));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_defaults_to_auto() {
        let cli = Cli::try_parse_from(["nfs-top"]).unwrap();
        assert!(matches!(cli.backend, BackendArg::Auto));
    }

    #[test]
    fn backend_accepts_proc_and_ebpf() {
        let cli = Cli::try_parse_from(["nfs-top", "--backend", "proc"]).unwrap();
        assert!(matches!(cli.backend, BackendArg::Proc));
        let cli = Cli::try_parse_from(["nfs-top", "--backend", "ebpf"]).unwrap();
        assert!(matches!(cli.backend, BackendArg::Ebpf));
    }

    #[test]
    fn backend_rejects_unknown_value() {
        assert!(Cli::try_parse_from(["nfs-top", "--backend", "bogus"]).is_err());
    }
}
