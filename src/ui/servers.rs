use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::App;
use crate::ui::{draw_line_card, panel, ACCENT_A, ACCENT_B};
use crate::util::format::{fmt_ms, fmt_rate};

pub fn draw(f: &mut Frame<'_>, area: ratatui::layout::Rect, app: &App) {
    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(10)])
        .split(area);

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 4); 4])
        .split(parts[0]);

    // Draw top cards for selected server's history
    let (read_series, write_series, ops_series, rtt_series) =
        if let Some(h) = app.selected_server_history() {
            (
                h.read_bps.iter().copied().collect::<Vec<_>>(),
                h.write_bps.iter().copied().collect::<Vec<_>>(),
                h.ops.iter().copied().collect::<Vec<_>>(),
                h.rtt_ms.iter().copied().collect::<Vec<_>>(),
            )
        } else {
            (Vec::new(), Vec::new(), Vec::new(), Vec::new())
        };

    let srv = app.selected_server();
    let read_val = srv.map(|s| fmt_rate(s.read_bps, app.units)).unwrap_or_else(|| "-".into());
    let write_val = srv.map(|s| fmt_rate(s.write_bps, app.units)).unwrap_or_else(|| "-".into());
    let ops_val = srv.map(|s| format!("{:.1}", s.ops_per_sec)).unwrap_or_else(|| "-".into());
    let rtt_val = srv.map(|s| fmt_ms(s.avg_rtt_ms)).unwrap_or_else(|| "-".into());

    draw_line_card(f, top[0], "Read Throughput", &read_series, &read_val, ACCENT_A);
    draw_line_card(f, top[1], "Write Throughput", &write_series, &write_val, ACCENT_B);
    draw_line_card(f, top[2], "Ops/s", &ops_series, &ops_val, ACCENT_A);
    draw_line_card(f, top[3], "Avg RTT", &rtt_series, &format!("{rtt_val} ms"), ACCENT_B);

    // Bottom: table (left) + detail (right)
    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(parts[1]);

    let servers = app.aggregate_servers();

    let header = Row::new(vec!["Host", "Read", "Write", "Ops/s", "RTT", "EXE", "nconn"])
        .style(Style::default().fg(ACCENT_A).add_modifier(Modifier::BOLD));

    let rows = servers
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let style = if i == app.server_selected {
                Style::default().fg(Color::Black).bg(ACCENT_B)
            } else {
                Style::default().fg(Color::White)
            };
            Row::new(vec![
                Cell::from(s.hostname.clone()),
                Cell::from(fmt_rate(s.read_bps, app.units)),
                Cell::from(fmt_rate(s.write_bps, app.units)),
                Cell::from(format!("{:.1}", s.ops_per_sec)),
                Cell::from(fmt_ms(s.avg_rtt_ms)),
                Cell::from(fmt_ms(s.avg_exe_ms)),
                Cell::from(s.nconnect.map(|n| n.to_string()).unwrap_or_else(|| "-".into())),
            ])
            .style(style)
        })
        .collect::<Vec<_>>();

    let widths = [
        Constraint::Length(24),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(6),
    ];

    let table = Table::new(rows, widths).header(header).block(panel("Servers"));
    f.render_widget(table, middle[0]);

    // Detail panel
    let details = if let Some(s) = srv {
        let mounts_str = if s.mounts.is_empty() {
            "-".to_string()
        } else {
            s.mounts.join(", ")
        };

        let rpc_lines: Vec<String> = s
            .per_op
            .iter()
            .take(8)
            .map(|op| {
                format!(
                    "  {:<10} {:>8.1} ops/s  {:>5.1}%  rtt:{} exe:{}",
                    op.op,
                    op.ops_per_sec,
                    op.share_pct,
                    fmt_ms(op.avg_rtt_ms),
                    fmt_ms(op.avg_exe_ms),
                )
            })
            .collect();

        format!(
            "host: {}\nmounts: {}\nnconnect: {}\n\nRPC mix (top 8):\n{}",
            s.hostname,
            mounts_str,
            s.nconnect.map(|n| n.to_string()).unwrap_or_else(|| "-".into()),
            rpc_lines.join("\n"),
        )
    } else {
        "no servers".to_string()
    };

    f.render_widget(Paragraph::new(details).block(panel("Detail")), middle[1]);
}
