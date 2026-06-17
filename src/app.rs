use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::SystemTime;

use std::net::IpAddr;

use crate::model::derive::host_from_device;
use crate::model::types::{BpfLatency, BpfOpLatency, MountView, OpDerived, ServerAgg, Snapshot, SortKey, UnitsMode};
use crate::util::ringbuf::RingBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Servers,
    RpcMix,
    Trends,
    Hist,
    Connections,
    Raw,
    Help,
}

impl Tab {
    pub fn titles() -> [&'static str; 7] {
        ["Servers", "RPC Mix", "Trends", "Hist", "Connections", "Raw", "Help"]
    }

    pub fn next(self) -> Self {
        match self {
            Tab::Servers => Tab::RpcMix,
            Tab::RpcMix => Tab::Trends,
            Tab::Trends => Tab::Hist,
            Tab::Hist => Tab::Connections,
            Tab::Connections => Tab::Raw,
            Tab::Raw => Tab::Help,
            Tab::Help => Tab::Servers,
        }
    }

    pub fn prev(self) -> Self {
        match self {
            Tab::Servers => Tab::Help,
            Tab::RpcMix => Tab::Servers,
            Tab::Trends => Tab::RpcMix,
            Tab::Hist => Tab::Trends,
            Tab::Connections => Tab::Hist,
            Tab::Raw => Tab::Connections,
            Tab::Help => Tab::Raw,
        }
    }

    pub fn idx(self) -> usize {
        match self {
            Tab::Servers => 0,
            Tab::RpcMix => 1,
            Tab::Trends => 2,
            Tab::Hist => 3,
            Tab::Connections => 4,
            Tab::Raw => 5,
            Tab::Help => 6,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PercentileMode {
    All,
    Avg,
    P90,
    P95,
    P99,
}

impl PercentileMode {
    pub fn next(self) -> Self {
        match self {
            PercentileMode::All => PercentileMode::Avg,
            PercentileMode::Avg => PercentileMode::P90,
            PercentileMode::P90 => PercentileMode::P95,
            PercentileMode::P95 => PercentileMode::P99,
            PercentileMode::P99 => PercentileMode::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            PercentileMode::All => "all",
            PercentileMode::Avg => "avg",
            PercentileMode::P90 => "p90",
            PercentileMode::P95 => "p95",
            PercentileMode::P99 => "p99",
        }
    }
}

#[derive(Debug)]
pub struct MountHistory {
    pub read_bps: RingBuf<f64>,
    pub write_bps: RingBuf<f64>,
    pub read_lat_ms: RingBuf<f64>,
    pub write_lat_ms: RingBuf<f64>,
}

impl MountHistory {
    fn new(history: usize) -> Self {
        Self {
            read_bps: RingBuf::new(history),
            write_bps: RingBuf::new(history),
            read_lat_ms: RingBuf::new(history),
            write_lat_ms: RingBuf::new(history),
        }
    }
}

#[derive(Debug)]
pub struct ServerHistory {
    pub read_bps: RingBuf<f64>,
    pub write_bps: RingBuf<f64>,
    pub ops: RingBuf<f64>,
    pub rtt_ms: RingBuf<f64>,
}

impl ServerHistory {
    fn new(history: usize) -> Self {
        Self {
            read_bps: RingBuf::new(history),
            write_bps: RingBuf::new(history),
            ops: RingBuf::new(history),
            rtt_ms: RingBuf::new(history),
        }
    }
}

pub struct App {
    pub tab: Tab,
    pub selected: usize,
    pub server_selected: usize,
    /// Stable identity of the selected mount (its mountpoint). When the
    /// per-tick re-sort changes row order, we relocate `selected` by this key
    /// so the highlight tracks the same mount instead of whatever happens to
    /// land at that row index.
    selected_mount_key: Option<String>,
    /// Stable identity of the selected server (its address). Same role as
    /// `selected_mount_key` for the Servers tab.
    selected_server_key: Option<Option<IpAddr>>,
    /// Stable identity of the highlighted op on the Hist tab. Per-tick the
    /// BPF aggregator re-sorts ops by sample count, so a positional index
    /// would visibly drift; we anchor by op name and recompute the row each
    /// render.
    selected_op_key: Option<String>,
    pub paused: bool,
    pub filter: String,
    filter_lower: String,
    pub sort: SortKey,
    pub units: UnitsMode,
    pub interval: Arc<AtomicU64>,
    pub snapshot: Option<Snapshot>,
    pub read_hist: RingBuf<f64>,
    pub write_hist: RingBuf<f64>,
    pub ops_hist: RingBuf<f64>,
    pub rtt_hist: RingBuf<f64>,
    pub cumulative_read_bytes: f64,
    pub cumulative_write_bytes: f64,
    pub last_error: Option<String>,
    pub last_sample: Option<SystemTime>,
    pub percentile_mode: PercentileMode,
    history_len: usize,
    mount_histories: HashMap<String, MountHistory>,
    server_histories: HashMap<Option<IpAddr>, ServerHistory>,
    /// Indices into snapshot.mounts in display (sorted+filtered) order.
    /// Recomputed only on ingest or sort change.
    cached_visible_idx: Vec<usize>,
    /// Per-server aggregates in display (sorted) order. Recomputed only on
    /// ingest or sort change. UI reads via `aggregate_servers()`.
    cached_servers: Vec<ServerAgg>,
}

impl App {
    pub fn new(history: usize, units: UnitsMode, interval: Arc<AtomicU64>, sort: SortKey, filter: String) -> Self {
        let filter_lower = filter.to_lowercase();
        Self {
            tab: Tab::Servers,
            selected: 0,
            server_selected: 0,
            selected_mount_key: None,
            selected_server_key: None,
            selected_op_key: None,
            paused: false,
            filter,
            filter_lower,
            sort,
            units,
            interval,
            last_error: None,
            snapshot: None,
            read_hist: RingBuf::new(history),
            write_hist: RingBuf::new(history),
            ops_hist: RingBuf::new(history),
            rtt_hist: RingBuf::new(history),
            cumulative_read_bytes: 0.0,
            cumulative_write_bytes: 0.0,
            last_sample: None,
            percentile_mode: PercentileMode::All,
            history_len: history,
            mount_histories: HashMap::new(),
            server_histories: HashMap::new(),
            cached_visible_idx: Vec::new(),
            cached_servers: Vec::new(),
        }
    }

    pub fn reset_baseline(&mut self) {
        self.read_hist.clear();
        self.write_hist.clear();
        self.ops_hist.clear();
        self.rtt_hist.clear();
        self.cumulative_read_bytes = 0.0;
        self.cumulative_write_bytes = 0.0;
        self.mount_histories.clear();
        self.server_histories.clear();
    }

    pub fn ingest(&mut self, snap: Snapshot) {
        if self.paused {
            return;
        }
        self.update_global_history(&snap);
        self.update_mount_history(&snap.mounts);
        self.cached_servers = Self::aggregate_servers_from(&snap.mounts, self.sort);
        self.update_server_history();
        self.cached_visible_idx = self.compute_visible_indices(&snap.mounts);
        self.last_sample = Some(snap.ts);
        self.snapshot = Some(snap);
        self.resync_selections();
    }

    fn update_global_history(&mut self, snap: &Snapshot) {
        let mut total_read = 0.0;
        let mut total_write = 0.0;
        let mut total_ops = 0.0;
        let mut total_rtt = 0.0;
        let mut rtt_count = 0usize;
        for m in snap.mounts.iter().filter(|m| self.matches_filter(m)) {
            total_read += m.derived.read_bps;
            total_write += m.derived.write_bps;
            total_ops += m.derived.ops_per_sec;
            if let Some(rtt) = m.derived.avg_rtt_ms {
                total_rtt += rtt;
                rtt_count += 1;
            }
        }
        self.read_hist.push(total_read);
        self.write_hist.push(total_write);
        self.ops_hist.push(total_ops);
        self.rtt_hist.push(if rtt_count > 0 { total_rtt / rtt_count as f64 } else { 0.0 });
        if snap.dt_secs > 0.0 && snap.dt_secs.is_finite() {
            self.cumulative_read_bytes += total_read * snap.dt_secs;
            self.cumulative_write_bytes += total_write * snap.dt_secs;
        }
    }

    fn update_mount_history(&mut self, mounts: &[MountView]) {
        for m in mounts {
            let h = self
                .mount_histories
                .entry(m.counters.mountpoint.clone())
                .or_insert_with(|| MountHistory::new(self.history_len));
            h.read_bps.push(m.derived.read_bps);
            h.write_bps.push(m.derived.write_bps);
            h.read_lat_ms.push(op_lat(&m.derived.per_op, "READ"));
            h.write_lat_ms.push(op_lat(&m.derived.per_op, "WRITE"));
        }
    }

    fn update_server_history(&mut self) {
        for srv in &self.cached_servers {
            let h = self
                .server_histories
                .entry(srv.addr)
                .or_insert_with(|| ServerHistory::new(self.history_len));
            h.read_bps.push(srv.read_bps);
            h.write_bps.push(srv.write_bps);
            h.ops.push(srv.ops_per_sec);
            h.rtt_ms.push(srv.avg_rtt_ms.unwrap_or(0.0));
        }
    }

    fn compute_visible_indices(&self, mounts: &[MountView]) -> Vec<usize> {
        let mut idx: Vec<usize> = mounts
            .iter()
            .enumerate()
            .filter(|(_, m)| self.matches_filter(m))
            .map(|(i, _)| i)
            .collect();
        idx.sort_by(|&a, &b| self.compare_mounts(&mounts[a], &mounts[b]));
        idx
    }

    /// Re-anchor `selected` / `server_selected` to the mount/server they were
    /// pointing at before the latest re-sort. If the previously-selected item
    /// is gone (or no key is set yet), clamp the index into range and prime
    /// the key from whatever now sits at that row.
    fn resync_selections(&mut self) {
        let mount_key = self.selected_mount_key.clone();
        let new_mount_idx = mount_key
            .as_deref()
            .and_then(|k| self.position_of_mount(k));
        match new_mount_idx {
            Some(pos) => self.selected = pos,
            None => {
                self.selected = self.selected.min(self.cached_visible_idx.len().saturating_sub(1));
                self.selected_mount_key = self.current_mount_key();
            }
        }

        let server_key = self.selected_server_key;
        let new_server_idx = server_key.and_then(|k| self.cached_servers.iter().position(|s| s.addr == k));
        match new_server_idx {
            Some(pos) => self.server_selected = pos,
            None => {
                self.server_selected = self.server_selected.min(self.cached_servers.len().saturating_sub(1));
                self.selected_server_key = self.cached_servers.get(self.server_selected).map(|s| s.addr);
            }
        }
    }

    fn position_of_mount(&self, mountpoint: &str) -> Option<usize> {
        let snap = self.snapshot.as_ref()?;
        self.cached_visible_idx
            .iter()
            .position(|&i| snap.mounts.get(i).map(|m| m.counters.mountpoint.as_str()) == Some(mountpoint))
    }

    fn current_mount_key(&self) -> Option<String> {
        self.selected_mount().map(|m| m.counters.mountpoint.clone())
    }

    /// Move the mounts-pane highlight by `delta` rows and pin the new row's
    /// mountpoint as the selection anchor. Negative deltas move up.
    pub fn move_mount_selection(&mut self, delta: i32) {
        self.selected = step_index(self.selected, delta, self.cached_visible_idx.len());
        self.selected_mount_key = self.current_mount_key();
    }

    /// Move the servers-pane highlight by `delta` rows and pin the new row's
    /// address as the selection anchor. Negative deltas move up.
    pub fn move_server_selection(&mut self, delta: i32) {
        self.server_selected = step_index(self.server_selected, delta, self.cached_servers.len());
        self.selected_server_key = self.selected_server().map(|s| s.addr);
    }

    /// Move the Hist tab's selected op by `delta` rows. No-op when the
    /// selected mount has no BPF data this tick. Negative deltas move up.
    pub fn move_hist_selection(&mut self, delta: i32) {
        let Some(bpf) = self.selected_mount_bpf() else { return };
        if bpf.per_op.is_empty() {
            return;
        }
        let cur = self
            .selected_op_key
            .as_deref()
            .and_then(|k| bpf.per_op.iter().position(|o| o.op == k))
            .unwrap_or(0);
        let new = step_index(cur, delta, bpf.per_op.len());
        self.selected_op_key = Some(bpf.per_op[new].op.clone());
    }

    /// BPF latency for the currently selected mount, or `None` when no
    /// mount is selected or the mount saw no samples this tick.
    pub fn selected_mount_bpf(&self) -> Option<&BpfLatency> {
        self.selected_mount()?.derived.bpf.as_ref()
    }

    /// Resolve the selection anchor against the selected mount's BPF
    /// snapshot. Returns the row index and op for the Hist-tab highlight
    /// and sparkline. Falls back to row 0 when no anchor is set yet or
    /// when the previously-selected op stopped reporting samples.
    pub fn selected_bpf_op(&self) -> Option<(usize, &BpfOpLatency)> {
        let bpf = self.selected_mount_bpf()?;
        if bpf.per_op.is_empty() {
            return None;
        }
        let idx = self
            .selected_op_key
            .as_deref()
            .and_then(|k| bpf.per_op.iter().position(|o| o.op == k))
            .unwrap_or(0);
        Some((idx, &bpf.per_op[idx]))
    }

    /// Cycle the sort key. Re-sorts the cached visible mounts and server
    /// aggregates so the next render reflects the new order without waiting
    /// for the next sample.
    pub fn cycle_sort(&mut self) {
        self.sort = self.sort.next();
        let sort = self.sort;
        if let Some(snap) = self.snapshot.as_ref() {
            let mounts = &snap.mounts;
            self.cached_visible_idx
                .sort_by(|&a, &b| compare_mounts_by(&mounts[a], &mounts[b], sort));
        }
        sort_servers(&mut self.cached_servers, sort);
        self.resync_selections();
    }

    pub fn visible_mounts(&self) -> Vec<&MountView> {
        let Some(snap) = self.snapshot.as_ref() else { return Vec::new() };
        self.cached_visible_idx
            .iter()
            .filter_map(|&i| snap.mounts.get(i))
            .collect()
    }

    fn compare_mounts(&self, a: &MountView, b: &MountView) -> Ordering {
        compare_mounts_by(a, b, self.sort)
    }

    pub fn selected_mount(&self) -> Option<&MountView> {
        let snap = self.snapshot.as_ref()?;
        let &idx = self.cached_visible_idx.get(self.selected)?;
        snap.mounts.get(idx)
    }

    pub fn selected_mount_history(&self) -> Option<&MountHistory> {
        let mount = self.selected_mount()?;
        self.mount_histories.get(&mount.counters.mountpoint)
    }

    fn aggregate_servers_from(mounts: &[MountView], sort: SortKey) -> Vec<ServerAgg> {
        let mut by_addr: HashMap<Option<IpAddr>, Vec<&MountView>> = HashMap::new();
        for m in mounts {
            by_addr.entry(m.counters.addr).or_default().push(m);
        }
        let mut servers: Vec<ServerAgg> = by_addr
            .into_iter()
            .map(|(addr, group)| build_server_agg(addr, &group))
            .collect();
        sort_servers(&mut servers, sort);
        servers
    }

    pub fn aggregate_servers(&self) -> &[ServerAgg] {
        &self.cached_servers
    }

    pub fn selected_server(&self) -> Option<&ServerAgg> {
        self.cached_servers.get(self.server_selected)
    }

    pub fn selected_server_history(&self) -> Option<&ServerHistory> {
        let srv = self.selected_server()?;
        self.server_histories.get(&srv.addr)
    }

    pub fn interval_ms(&self) -> u64 {
        self.interval.load(AtomicOrdering::Relaxed)
    }

    pub fn increase_interval(&self) {
        let cur = self.interval.load(AtomicOrdering::Relaxed);
        self.interval.store((cur + 100).min(10_000), AtomicOrdering::Relaxed);
    }

    pub fn decrease_interval(&self) {
        let cur = self.interval.load(AtomicOrdering::Relaxed);
        self.interval.store(cur.saturating_sub(100).max(100), AtomicOrdering::Relaxed);
    }

    fn matches_filter(&self, m: &MountView) -> bool {
        if self.filter_lower.is_empty() {
            return true;
        }
        let q = &self.filter_lower;
        m.counters.mountpoint.to_lowercase().contains(q) || m.counters.device.to_lowercase().contains(q)
    }
}

fn step_index(idx: usize, delta: i32, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let max = (len - 1) as i64;
    (idx as i64 + delta as i64).clamp(0, max) as usize
}

fn compare_mounts_by(a: &MountView, b: &MountView, sort: SortKey) -> Ordering {
    match sort {
        SortKey::Read => b.derived.read_bps.partial_cmp(&a.derived.read_bps).unwrap_or(Ordering::Equal),
        SortKey::Write => b.derived.write_bps.partial_cmp(&a.derived.write_bps).unwrap_or(Ordering::Equal),
        SortKey::Ops => b.derived.ops_per_sec.partial_cmp(&a.derived.ops_per_sec).unwrap_or(Ordering::Equal),
        SortKey::Rtt => b.derived.avg_rtt_ms.partial_cmp(&a.derived.avg_rtt_ms).unwrap_or(Ordering::Equal),
        SortKey::Exe => b.derived.avg_exe_ms.partial_cmp(&a.derived.avg_exe_ms).unwrap_or(Ordering::Equal),
        SortKey::Mount => a.counters.mountpoint.cmp(&b.counters.mountpoint),
        SortKey::Nconnect => b.counters.nconnect.cmp(&a.counters.nconnect),
        SortKey::ObsConn => b.derived.observed_conns.cmp(&a.derived.observed_conns),
    }
}

fn op_lat(per_op: &[OpDerived], op_name: &str) -> f64 {
    per_op
        .iter()
        .find(|o| o.op == op_name)
        .and_then(|o| o.avg_rtt_ms)
        .unwrap_or(0.0)
}

/// Ops-weighted mean: each (value, weight) contributes value*weight to the sum
/// when value is Some. Returns None if the total weight is zero.
fn ops_weighted_mean<I>(items: I) -> Option<f64>
where
    I: IntoIterator<Item = (Option<f64>, f64)>,
{
    let (sum, weight) = items.into_iter().fold((0.0_f64, 0.0_f64), |(s, w), (v, wt)| match v {
        Some(x) => (s + x * wt, w + wt),
        None => (s, w),
    });
    (weight > 0.0).then_some(sum / weight)
}

#[derive(Default)]
struct OpAccum {
    ops_sum: f64,
    bytes_sum: f64,
    rtt_weighted_sum: f64,
    rtt_weight: f64,
    exe_weighted_sum: f64,
    exe_weight: f64,
}

fn build_server_agg(addr: Option<IpAddr>, group: &[&MountView]) -> ServerAgg {
    let read_bps: f64 = group.iter().map(|m| m.derived.read_bps).sum();
    let write_bps: f64 = group.iter().map(|m| m.derived.write_bps).sum();
    let ops_per_sec: f64 = group.iter().map(|m| m.derived.ops_per_sec).sum();
    let observed_conns: u64 = group.iter().map(|m| m.derived.observed_conns).sum();
    let nconnect: Option<u32> = group.iter().filter_map(|m| m.counters.nconnect).max();

    let avg_rtt_ms = ops_weighted_mean(group.iter().map(|m| (m.derived.avg_rtt_ms, m.derived.ops_per_sec)));
    let avg_exe_ms = ops_weighted_mean(group.iter().map(|m| (m.derived.avg_exe_ms, m.derived.ops_per_sec)));

    let mut op_map: HashMap<String, OpAccum> = HashMap::new();
    for m in group {
        for op in &m.derived.per_op {
            let e = op_map.entry(op.op.clone()).or_default();
            e.ops_sum += op.ops_per_sec;
            e.bytes_sum += op.bytes_per_sec;
            if let Some(rtt) = op.avg_rtt_ms {
                e.rtt_weighted_sum += rtt * op.ops_per_sec;
                e.rtt_weight += op.ops_per_sec;
            }
            if let Some(exe) = op.avg_exe_ms {
                e.exe_weighted_sum += exe * op.ops_per_sec;
                e.exe_weight += op.ops_per_sec;
            }
        }
    }
    let total_ops_for_share: f64 = op_map.values().map(|v| v.ops_sum).sum();
    let mut per_op: Vec<OpDerived> = op_map
        .into_iter()
        .map(|(op, a)| OpDerived {
            op,
            ops_per_sec: a.ops_sum,
            bytes_per_sec: a.bytes_sum,
            share_pct: if total_ops_for_share > 0.0 { a.ops_sum / total_ops_for_share * 100.0 } else { 0.0 },
            avg_rtt_ms: (a.rtt_weight > 0.0).then_some(a.rtt_weighted_sum / a.rtt_weight),
            avg_exe_ms: (a.exe_weight > 0.0).then_some(a.exe_weighted_sum / a.exe_weight),
        })
        .collect();
    per_op.sort_by(|a, b| b.ops_per_sec.partial_cmp(&a.ops_per_sec).unwrap_or(Ordering::Equal));

    let hostname = group
        .first()
        .and_then(|m| host_from_device(&m.counters.device))
        .unwrap_or("unknown")
        .to_string();
    let mounts: Vec<String> = group.iter().map(|m| m.counters.mountpoint.clone()).collect();

    ServerAgg {
        addr,
        hostname,
        mounts,
        read_bps,
        write_bps,
        ops_per_sec,
        avg_rtt_ms,
        avg_exe_ms,
        observed_conns,
        nconnect,
        per_op,
    }
}

fn sort_servers(servers: &mut [ServerAgg], sort: SortKey) {
    servers.sort_by(|a, b| match sort {
        SortKey::Read => b.read_bps.partial_cmp(&a.read_bps).unwrap_or(Ordering::Equal),
        SortKey::Write => b.write_bps.partial_cmp(&a.write_bps).unwrap_or(Ordering::Equal),
        SortKey::Ops => b.ops_per_sec.partial_cmp(&a.ops_per_sec).unwrap_or(Ordering::Equal),
        SortKey::Rtt => b.avg_rtt_ms.partial_cmp(&a.avg_rtt_ms).unwrap_or(Ordering::Equal),
        SortKey::Exe => b.avg_exe_ms.partial_cmp(&a.avg_exe_ms).unwrap_or(Ordering::Equal),
        SortKey::ObsConn => b.observed_conns.cmp(&a.observed_conns),
        // No meaningful per-server ordering for Mount/Nconnect; fall back to Ops.
        SortKey::Mount | SortKey::Nconnect => {
            b.ops_per_sec.partial_cmp(&a.ops_per_sec).unwrap_or(Ordering::Equal)
        }
    });
}
