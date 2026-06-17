use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::symbols::Marker;
use ratatui::widgets::{Axis, Block, Borders, Chart, Dataset, GraphType, Paragraph, Tabs};
use ratatui::Frame;

use crate::app::{App, Tab};

pub mod help;
pub mod hist;
pub mod latency;
pub mod raw;
pub mod rpc_mix;
pub mod servers;
pub mod transport;

pub const BG: Color = Color::Rgb(11, 14, 18);
pub const PANEL: Color = Color::Rgb(20, 27, 36);
pub const ACCENT_A: Color = Color::Rgb(72, 181, 255);
pub const ACCENT_B: Color = Color::Rgb(89, 224, 166);
pub const WARN: Color = Color::Rgb(255, 179, 71);

pub fn draw(f: &mut Frame<'_>, app: &App) {
    // Baseline bg fill. Without this, any cell that no widget below paints
    // (border gaps inside the Tabs block, trailing cells in the status row,
    // rounding leftovers from %-based layouts) keeps the terminal's default
    // bg instead of our scheme — and on tab switches that asymmetry reads as
    // a dirty redraw.
    f.render_widget(Block::default().style(Style::default().bg(BG)), f.area());

    let areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(1)])
        .split(f.area());

    let tab_titles = Tab::titles().iter().copied().collect::<Vec<&str>>();
    let tabs = Tabs::new(tab_titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" nfsview ")
                .style(Style::default().bg(PANEL)),
        )
        .select(app.tab.idx())
        .highlight_style(Style::default().fg(ACCENT_A).add_modifier(Modifier::BOLD))
        .style(Style::default().fg(Color::Gray).bg(PANEL));
    f.render_widget(tabs, areas[0]);

    match app.tab {
        Tab::Servers => servers::draw(f, areas[1], app),
        Tab::RpcMix => rpc_mix::draw(f, areas[1], app),
        Tab::Trends => latency::draw(f, areas[1], app),
        Tab::Hist => hist::draw(f, areas[1], app),
        Tab::Connections => transport::draw(f, areas[1], app),
        Tab::Raw => raw::draw(f, areas[1], app),
        Tab::Help => help::draw(f, areas[1], app),
    }

    let (status, status_style) = if let Some(ref err) = app.last_error {
        (
            format!("ERROR: {err}"),
            Style::default().fg(Color::White).bg(Color::Red),
        )
    } else {
        let mut s = format!(
            "backend:crossterm interval:{}ms paused:{} filter:{} sort:{} units:{} trend:{}",
            app.interval_ms(),
            if app.paused { "yes" } else { "no" },
            if app.filter.is_empty() { "-" } else { &app.filter },
            app.sort.as_str(),
            app.units.label(),
            app.percentile_mode.label(),
        );
        if let Some(snap) = app.snapshot.as_ref()
            && !snap.partial_errors.is_empty()
        {
            s.push_str(" warn:");
            s.push_str(&snap.partial_errors.join("; "));
        }
        (s, Style::default().fg(Color::Black).bg(WARN))
    };
    // Wrap in a Block carrying the same style so every cell in the status
    // row is filled — without this, cells past the end of the status text
    // keep terminal-default bg instead of WARN/Red, leaving a torn-looking
    // half-painted strip whenever the text length changes.
    let p = Paragraph::new(status)
        .style(status_style)
        .block(Block::default().style(status_style));
    f.render_widget(p, areas[2]);
}

pub fn panel(title: &str) -> Block<'_> {
    Block::default()
        .title(format!(" {} ", title))
        .borders(Borders::ALL)
        .style(Style::default().bg(PANEL))
}

/// Render a line chart card with a title, current value header, and braille line graph.
pub fn draw_line_card(f: &mut Frame<'_>, area: Rect, title: &str, series: &[f64], value: &str, color: Color) {
    let block = panel(title);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3)])
        .split(inner);

    let header = Paragraph::new(value.to_string()).style(Style::default().fg(Color::White));
    f.render_widget(header, parts[0]);

    let data: Vec<(f64, f64)> = series
        .iter()
        .enumerate()
        .map(|(i, v)| (i as f64, if v.is_finite() { *v } else { 0.0 }))
        .collect();

    if data.is_empty() {
        return;
    }

    let max_x = (data.len() as f64 - 1.0).max(1.0);
    let max_y = data.iter().map(|(_, y)| *y).fold(0.0_f64, f64::max).max(f64::MIN_POSITIVE);

    let datasets = vec![
        Dataset::default()
            .marker(Marker::Braille)
            .graph_type(GraphType::Line)
            .style(Style::default().fg(color))
            .data(&data),
    ];

    let chart = Chart::new(datasets)
        .style(Style::default().bg(BG))
        .x_axis(Axis::default().bounds([0.0, max_x]))
        .y_axis(Axis::default().bounds([0.0, max_y * 1.1]));

    f.render_widget(chart, parts[1]);
}
