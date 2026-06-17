//! eBPF latency histogram tab.
//!
//! Renders per-op p50..p99.999 + a log-scale bucket sparkline for the
//! currently selected mount. Populated from
//! `MountDerived.bpf`. Visible whenever the binary is built with the
//! `ebpf` feature; on builds or hosts without working probes — or when
//! the selected mount has seen no samples this tick — the tab shows a
//! single explanatory line.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::App;
use crate::model::types::{BpfLatency, BpfOpLatency};
use crate::ui::{panel, ACCENT_A};

pub fn draw(f: &mut Frame<'_>, area: Rect, app: &App) {
    let title = match app.selected_mount() {
        Some(m) => format!(
            "Latency histogram (eBPF) — {} — j/k to select op",
            m.counters.mountpoint
        ),
        None => "Latency histogram (eBPF) — j/k to select op".to_string(),
    };
    let block = panel(&title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let bpf = match app.selected_mount_bpf() {
        Some(b) if !b.per_op.is_empty() => b,
        _ => {
            let msg = empty_message(app);
            f.render_widget(Paragraph::new(msg).style(Style::default().fg(Color::Gray)), inner);
            return;
        }
    };

    let selected_idx = app.selected_bpf_op().map(|(i, _)| i).unwrap_or(0);

    // 1 header + N data rows + totals (1 line) + sparkline (>=5 lines).
    // The sparkline floor protects the distribution view on smaller
    // terminals once the op table grows past the RW-only set.
    let table_h = (bpf.per_op.len() as u16) + 1;
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(table_h),
            Constraint::Length(1),
            Constraint::Min(5),
        ])
        .split(inner);

    f.render_widget(percentile_table(bpf, selected_idx), parts[0]);
    let totals = format!("{} samples this tick", fmt_count(bpf.total_samples));
    f.render_widget(
        Paragraph::new(totals).style(Style::default().fg(Color::DarkGray)),
        parts[1],
    );

    if let Some(op) = bpf.per_op.get(selected_idx) {
        f.render_widget(distribution_line(op), parts[2]);
    }
}

fn empty_message(app: &App) -> Line<'static> {
    let attached = app
        .snapshot
        .as_ref()
        .map(|s| s.bpf_attached)
        .unwrap_or(false);
    let has_mount = app.selected_mount().is_some();
    let msg: String = if !cfg!(feature = "ebpf") {
        "Built without --features=ebpf. Rebuild with `cargo build --features=ebpf` to enable per-op latency histograms.".into()
    } else if !attached {
        "eBPF backend not active — needs CAP_BPF and a kernel with NFS BTF (RHEL 9+). Run with sudo or `setcap cap_bpf,cap_sys_resource=ep`. (Check the status bar for the load error.)".into()
    } else if !has_mount {
        "eBPF probes attached — no NFS mount selected.".into()
    } else {
        match app.selected_mount() {
            Some(m) => format!(
                "eBPF probes attached — no samples for {} this tick.",
                m.counters.mountpoint
            ),
            None => "eBPF probes attached — waiting for NFS RPC traffic.".into(),
        }
    };
    Line::from(vec![Span::styled(msg, Style::default().fg(Color::Gray))])
}

fn percentile_table(bpf: &BpfLatency, selected_idx: usize) -> Table<'static> {
    let header_cells = ["op", "samples", "p50", "p90", "p99", "p99.9", "p99.99", "p99.999", "max"]
        .into_iter()
        .map(|h| Cell::from(h).style(Style::default().fg(ACCENT_A).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).height(1);

    let rows: Vec<Row> = bpf
        .per_op
        .iter()
        .enumerate()
        .map(|(i, op)| {
            let row = row_for_op(op);
            if i == selected_idx {
                row.style(Style::default().fg(Color::Black).bg(ACCENT_A))
            } else {
                row
            }
        })
        .collect();

    let widths = [
        Constraint::Length(8),
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(9),
    ];

    Table::new(rows, widths).header(header).column_spacing(1)
}

fn row_for_op(op: &BpfOpLatency) -> Row<'static> {
    let d = &op.dist;
    Row::new(vec![
        Cell::from(op.op.clone()),
        Cell::from(fmt_count(d.samples)),
        Cell::from(fmt_ns(d.p50_ns)),
        Cell::from(fmt_ns(d.p90_ns)),
        Cell::from(fmt_ns(d.p99_ns)),
        Cell::from(fmt_ns(d.p999_ns)),
        Cell::from(fmt_ns(d.p9999_ns)),
        Cell::from(fmt_ns(d.p99999_ns)),
        Cell::from(fmt_ns(d.max_ns)),
    ])
}

/// Shape of the highest-throughput op's distribution. One character per
/// log2 bucket, height encodes log(count) so a single dominant bucket
/// renders flat-topped while a long tail spreads visibly to the right.
fn distribution_line(top: &BpfOpLatency) -> Paragraph<'static> {
    let (chars, low_idx, high_idx) = bucket_sparkline(&top.buckets);
    let header = format!(
        "{} distribution  ({} → {})",
        top.op,
        fmt_ns(bucket_lower_ns(low_idx)),
        fmt_ns(bucket_upper_ns(high_idx)),
    );
    let lines = vec![
        Line::from(Span::styled(header, Style::default().fg(Color::Gray))),
        Line::from(Span::styled(chars, Style::default().fg(ACCENT_A))),
    ];
    Paragraph::new(lines)
}

/// Build a sparkline from raw per-bucket counts. Trims to the populated
/// window `[lo, hi]` so the visualization scales to where the samples
/// actually are. Heights are log2(count + 1) normalized to the glyph
/// range — a single hot bucket reads tall, a flat distribution reads
/// uniform, a bimodal one shows two visible peaks.
fn bucket_sparkline(buckets: &[u64]) -> (String, usize, usize) {
    const SPARK: [char; 8] = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇'];
    let lo = buckets.iter().position(|&c| c > 0).unwrap_or(0);
    let hi = buckets.iter().rposition(|&c| c > 0).unwrap_or(lo);
    let max = buckets[lo..=hi].iter().copied().max().unwrap_or(1).max(1);
    let max_log = ((max + 1) as f64).log2();
    let s: String = buckets[lo..=hi]
        .iter()
        .map(|&c| {
            if c == 0 {
                return ' ';
            }
            let scaled = ((c + 1) as f64).log2() / max_log;
            let h = (scaled * (SPARK.len() as f64 - 1.0)).round() as usize;
            SPARK[h.min(SPARK.len() - 1).max(1)]
        })
        .collect();
    (s, lo, hi)
}

fn bucket_lower_ns(i: usize) -> u64 {
    if i == 0 {
        0
    } else if i >= 63 {
        1u64 << 63
    } else {
        1u64 << i
    }
}

fn bucket_upper_ns(i: usize) -> u64 {
    if i >= 63 {
        u64::MAX
    } else {
        1u64 << (i + 1)
    }
}

fn fmt_count(n: u64) -> String {
    match n {
        0..=9_999 => format!("{n}"),
        10_000..=999_999 => format!("{:.1}K", (n as f64) / 1e3),
        1_000_000..=999_999_999 => format!("{:.1}M", (n as f64) / 1e6),
        _ => format!("{:.1}G", (n as f64) / 1e9),
    }
}

fn fmt_ns(ns: u64) -> String {
    if ns == 0 {
        return "-".to_string();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_ns_human_units() {
        assert_eq!(fmt_ns(0), "-");
        assert_eq!(fmt_ns(500), "500ns");
        assert_eq!(fmt_ns(1_500), "1.5us");
        assert_eq!(fmt_ns(1_500_000), "1.5ms");
        assert_eq!(fmt_ns(2_500_000_000), "2.5s");
    }

    #[test]
    fn fmt_count_thousands_and_millions() {
        assert_eq!(fmt_count(42), "42");
        assert_eq!(fmt_count(12_345), "12.3K");
        assert_eq!(fmt_count(1_500_000), "1.5M");
    }

    #[test]
    fn sparkline_tracks_distribution_shape() {
        // Single hot bucket: lo == hi, exactly one wide character.
        let mut single = vec![0u64; 64];
        single[10] = 1000;
        let (s, lo, hi) = bucket_sparkline(&single);
        assert_eq!((lo, hi), (10, 10));
        assert_eq!(s.chars().count(), 1);

        // Bimodal: two peaks at buckets 8 and 16, valley between.
        let mut bimodal = vec![0u64; 64];
        bimodal[8] = 500;
        bimodal[16] = 500;
        let (s, lo, hi) = bucket_sparkline(&bimodal);
        assert_eq!((lo, hi), (8, 16));
        let chars: Vec<char> = s.chars().collect();
        assert_eq!(chars.len(), 9);
        assert_ne!(chars[0], ' ');
        assert_eq!(chars[1], ' '); // valley
        assert_ne!(chars[8], ' ');

        // Long tail: heavy at bucket 10, single sample at bucket 20.
        let mut tail = vec![0u64; 64];
        tail[10] = 10_000;
        tail[20] = 1;
        let (s, lo, hi) = bucket_sparkline(&tail);
        assert_eq!((lo, hi), (10, 20));
        let chars: Vec<char> = s.chars().collect();
        // Tall start, mostly empty middle, short tip at the end.
        assert_eq!(chars.len(), 11);
        assert_ne!(chars[0], ' ');
        assert_ne!(chars[10], ' ');
    }

    #[test]
    fn empty_buckets_dont_panic() {
        let empty = vec![0u64; 64];
        let (s, lo, hi) = bucket_sparkline(&empty);
        assert_eq!((lo, hi), (0, 0));
        assert_eq!(s, " ");
    }
}
