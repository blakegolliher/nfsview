use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitsMode {
    Auto,
    MiB,
    GiB,
    TiB,
}

impl UnitsMode {
    pub fn label(self) -> &'static str {
        match self {
            UnitsMode::Auto => "AUTO",
            UnitsMode::MiB => "MiB",
            UnitsMode::GiB => "GiB",
            UnitsMode::TiB => "TiB",
        }
    }
}

#[derive(Debug, Clone)]
pub struct OpCounters {
    pub op: String,
    pub calls: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub rtt_ms_total: f64,
    pub exe_ms_total: f64,
}

#[derive(Debug, Clone)]
pub struct MountCounters {
    pub device: String,
    pub mountpoint: String,
    pub fstype: String,
    pub vers: Option<String>,
    pub proto: Option<String>,
    pub nconnect: Option<u32>,
    pub addr: Option<IpAddr>,
    pub clientaddr: Option<IpAddr>,
    /// Kernel `super_block.s_dev` for this mount, packed as `MKDEV(major,
    /// minor) = (major << 20) | minor` to match what BPF reads from the
    /// inode chain. `None` means /proc/self/mountinfo wasn't readable or
    /// didn't list this mountpoint. Used to cross-reference per-dev BPF
    /// histogram buckets back to a mount.
    pub st_dev: Option<u32>,
    pub options: HashMap<String, String>,
    pub ops: HashMap<String, OpCounters>,
    pub raw_block: String,
}

#[derive(Debug, Clone, Default)]
pub struct MountDerived {
    pub read_bps: f64,
    pub write_bps: f64,
    pub ops_per_sec: f64,
    pub avg_rtt_ms: Option<f64>,
    pub avg_exe_ms: Option<f64>,
    pub observed_conns: u64,
    pub observed_by_ip: Vec<(IpAddr, u64)>,
    pub per_op: Vec<OpDerived>,
    pub bpf: Option<BpfLatency>,
}

/// Bucket-aligned latency distribution.
///
/// Buckets are powers of two in nanoseconds: bucket `i` covers
/// `[2^i, 2^(i+1))`, with bucket 0 extended to also capture ns=0 since
/// the BPF binner folds anything below 2 into bucket 0. Reported
/// percentiles are upper bounds — the value returned for `p99_ns` is
/// the upper edge of the bucket containing the 99th percentile sample,
/// so the *true* p99 is at most that value.
#[derive(Debug, Clone, Default)]
pub struct LatencyDist {
    pub samples: u64,
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub p9999_ns: u64,
    pub p99999_ns: u64,
    pub max_ns: u64,
}

/// Per-op latency entry. Carries both the summarized percentiles and the
/// raw bucket counts so the UI can render an honest distribution shape
/// (not just the percentile-based rank pattern).
#[derive(Debug, Clone)]
pub struct BpfOpLatency {
    pub op: String,
    pub dist: LatencyDist,
    /// Per-tick delta count per log2 bucket. `buckets[i]` is the number
    /// of samples that fell into `[2^i, 2^(i+1))` ns this interval.
    pub buckets: Vec<u64>,
}

/// Optional eBPF-derived latency snapshot for a mount.
///
/// Populated only when the `ebpf` feature is built in and the kernel-side
/// probes successfully attached. A `None` value on `MountDerived.bpf` means
/// "no data" — never "zero samples". Consumers must treat this as an
/// optional decoration on top of the existing /proc-derived fields.
#[derive(Debug, Clone, Default)]
pub struct BpfLatency {
    /// Per-op latency distributions, sorted by descending sample count.
    pub per_op: Vec<BpfOpLatency>,
    /// Total samples folded across all ops, for the bottom-bar indicator.
    pub total_samples: u64,
}

#[derive(Debug, Clone)]
pub struct OpDerived {
    pub op: String,
    pub ops_per_sec: f64,
    pub bytes_per_sec: f64,
    pub share_pct: f64,
    pub avg_rtt_ms: Option<f64>,
    pub avg_exe_ms: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct MountView {
    pub counters: MountCounters,
    pub derived: MountDerived,
    pub resolved_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct ServerAgg {
    pub addr: Option<IpAddr>,
    pub hostname: String,
    pub mounts: Vec<String>,
    pub read_bps: f64,
    pub write_bps: f64,
    pub ops_per_sec: f64,
    pub avg_rtt_ms: Option<f64>,
    pub avg_exe_ms: Option<f64>,
    pub observed_conns: u64,
    /// Configured `nconnect=` from the mount options (max across this
    /// server's mounts). The number of TCP connections the client was told
    /// to open — reliable from mountstats, unlike `observed_conns` which
    /// needs the server addr to match live sockets.
    pub nconnect: Option<u32>,
    pub per_op: Vec<OpDerived>,
}

#[derive(Debug, Clone, Default)]
pub struct RpcClientCounters {
    pub raw: String,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub ts: SystemTime,
    pub dt_secs: f64,
    pub mounts: Vec<MountView>,
    pub rpc: RpcClientCounters,
    pub raw_tcp_matches: Vec<String>,
    pub partial_errors: Vec<String>,
    /// True when the eBPF probes are loaded and attached. Lets the UI
    /// distinguish "backend down" from "backend up but no samples for the
    /// selected mount this tick" — per-mount data lives on
    /// `MountDerived.bpf`.
    pub bpf_attached: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Read,
    Write,
    Ops,
    Rtt,
    Exe,
    Mount,
    Nconnect,
    ObsConn,
}

impl SortKey {
    pub fn next(self) -> Self {
        match self {
            SortKey::Read => SortKey::Write,
            SortKey::Write => SortKey::Ops,
            SortKey::Ops => SortKey::Rtt,
            SortKey::Rtt => SortKey::Exe,
            SortKey::Exe => SortKey::Mount,
            SortKey::Mount => SortKey::Nconnect,
            SortKey::Nconnect => SortKey::ObsConn,
            SortKey::ObsConn => SortKey::Read,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SortKey::Read => "read",
            SortKey::Write => "write",
            SortKey::Ops => "ops",
            SortKey::Rtt => "rtt",
            SortKey::Exe => "exe",
            SortKey::Mount => "mount",
            SortKey::Nconnect => "nconnect",
            SortKey::ObsConn => "obsconn",
        }
    }
}
