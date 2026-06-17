use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Chart, Dataset, GraphType, Paragraph};
use ratatui::Frame;

use crate::app::{App, PercentileMode};
use crate::ui::{draw_line_card, panel, BG, ACCENT_A, ACCENT_B, WARN};
use crate::util::format::{fmt_ms, fmt_rate};

pub fn draw(f: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let grid = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
        .split(area);
    let row1 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
        .split(grid[0]);
    let row2 = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
        .split(grid[1]);

    if let Some(m) = app.selected_mount() {
        if let Some(hist) = app.selected_mount_history() {
            let read = hist.read_bps.iter().copied().collect::<Vec<_>>();
            let write = hist.write_bps.iter().copied().collect::<Vec<_>>();
            draw_line_card(
                f,
                row1[0],
                "Read Throughput",
                &read,
                &fmt_rate(m.derived.read_bps, app.units),
                ACCENT_A,
            );
            draw_line_card(
                f,
                row1[1],
                "Write Throughput",
                &write,
                &fmt_rate(m.derived.write_bps, app.units),
                ACCENT_B,
            );

            let read_lat = hist.read_lat_ms.iter().copied().collect::<Vec<_>>();
            let write_lat = hist.write_lat_ms.iter().copied().collect::<Vec<_>>();
            draw_latency_panel(
                f,
                row2[0],
                "Read Latency (est.)",
                &read_lat,
                m.derived
                    .per_op
                    .iter()
                    .find(|o| o.op == "READ")
                    .and_then(|o| o.avg_rtt_ms),
                app.percentile_mode,
                ACCENT_A,
            );
            draw_latency_panel(
                f,
                row2[1],
                "Write Latency (est.)",
                &write_lat,
                m.derived
                    .per_op
                    .iter()
                    .find(|o| o.op == "WRITE")
                    .and_then(|o| o.avg_rtt_ms),
                app.percentile_mode,
                ACCENT_B,
            );
        } else {
            f.render_widget(Paragraph::new("No trend history yet for selected mount").block(panel("Trends")), area);
        }
    } else {
        f.render_widget(Paragraph::new("No mount selected").block(panel("Trends")), area);
    }
}

fn draw_latency_panel(
    f: &mut Frame<'_>,
    area: Rect,
    title: &str,
    base_series: &[f64],
    current_avg: Option<f64>,
    mode: PercentileMode,
    color: Color,
) {
    match mode {
        PercentileMode::All => {
            let header_title = format!("{} {}", title, fmt_ms(current_avg));
            let block = panel(&header_title);
            let inner = block.inner(area);
            f.render_widget(block, area);

            let parts = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Min(3)])
                .split(inner);

            let avg_data = to_chart_data(base_series);
            let p90_series = percentile_series(base_series, 0.90);
            let p95_series = percentile_series(base_series, 0.95);
            let p99_series = percentile_series(base_series, 0.99);
            let p90_data = to_chart_data(&p90_series);
            let p95_data = to_chart_data(&p95_series);
            let p99_data = to_chart_data(&p99_series);

            // Colored legend with the latest value of each line. The dashes
            // are color swatches; the numbers are the current readouts.
            let legend = Line::from(vec![
                Span::styled(format!("-- avg {} ", fmt_ms(current_avg)), Style::default().fg(color)),
                Span::styled(format!("-- p90 {} ", fmt_ms(last_val(&p90_series))), Style::default().fg(Color::Yellow)),
                Span::styled(format!("-- p95 {} ", fmt_ms(last_val(&p95_series))), Style::default().fg(WARN)),
                Span::styled(format!("-- p99 {}", fmt_ms(last_val(&p99_series))), Style::default().fg(Color::Red)),
            ]);
            f.render_widget(Paragraph::new(legend), parts[0]);

            if avg_data.is_empty() {
                return;
            }

            let max_x = (avg_data.len() as f64 - 1.0).max(1.0);
            let max_y = [&avg_data, &p90_data, &p95_data, &p99_data]
                .iter()
                .flat_map(|d| d.iter().map(|(_, y)| *y))
                .fold(0.0_f64, f64::max)
                .max(0.001);

            let datasets = vec![
                Dataset::default()
                    .marker(Marker::Braille)
                    .graph_type(GraphType::Line)
                    .style(Style::default().fg(color))
                    .data(&avg_data),
                Dataset::default()
                    .marker(Marker::Braille)
                    .graph_type(GraphType::Line)
                    .style(Style::default().fg(Color::Yellow))
                    .data(&p90_data),
                Dataset::default()
                    .marker(Marker::Braille)
                    .graph_type(GraphType::Line)
                    .style(Style::default().fg(WARN))
                    .data(&p95_data),
                Dataset::default()
                    .marker(Marker::Braille)
                    .graph_type(GraphType::Line)
                    .style(Style::default().fg(Color::Red))
                    .data(&p99_data),
            ];

            let chart = Chart::new(datasets)
                .style(Style::default().bg(BG))
                .x_axis(Axis::default().bounds([0.0, max_x]))
                .y_axis(Axis::default().bounds([0.0, max_y * 1.1]));

            f.render_widget(chart, parts[1]);
        }
        other => {
            let series = match other {
                PercentileMode::Avg => base_series.to_vec(),
                PercentileMode::P90 => percentile_series(base_series, 0.90),
                PercentileMode::P95 => percentile_series(base_series, 0.95),
                PercentileMode::P99 => percentile_series(base_series, 0.99),
                _ => unreachable!(),
            };
            // Avg mode tracks the live per-op average; the percentile modes
            // read the latest point of their rolling-window series so the
            // displayed number matches the selected line (not the avg).
            let current = match other {
                PercentileMode::Avg => current_avg,
                _ => last_val(&series),
            };
            draw_line_card(
                f,
                area,
                &format!("{} {}", title, other.label()),
                &series,
                &fmt_ms(current),
                color,
            );
        }
    }
}

/// Latest finite, positive sample in a series — the "current" value shown
/// in the latency legend. Returns None when the series has no real data yet
/// (so the legend renders "-" rather than a stale or zero reading).
fn last_val(series: &[f64]) -> Option<f64> {
    series.iter().rev().copied().find(|v| v.is_finite() && *v > 0.0)
}

fn to_chart_data(series: &[f64]) -> Vec<(f64, f64)> {
    series
        .iter()
        .enumerate()
        .map(|(i, v)| (i as f64, if v.is_finite() { *v } else { 0.0 }))
        .collect()
}

fn percentile_series(series: &[f64], p: f64) -> Vec<f64> {
    let mut out = Vec::with_capacity(series.len());
    for i in 0..series.len() {
        let mut window = series[..=i]
            .iter()
            .copied()
            .filter(|v| v.is_finite() && *v > 0.0)
            .collect::<Vec<_>>();
        if window.is_empty() {
            out.push(0.0);
            continue;
        }
        window.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let rank = ((window.len() as f64 - 1.0) * p).round() as usize;
        out.push(window[rank.min(window.len() - 1)]);
    }
    out
}
