//! Live TUI dashboard.
//!
//! Immediate-mode ratatui render loop driven by `tokio::select!` over three
//! sources: terminal key events, a redraw/spinner tick, and the stream of
//! probe results. The connectivity chain re-probes on a fixed cadence so the
//! topology, verdict, and telemetry update in real time.

use crate::diagnose::{Verdict, diagnose};
use crate::engine;
use crate::model::{Hop, HopId, Path, Status};
use color_eyre::Result;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use futures::StreamExt;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Gauge, Padding, Paragraph};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;

const SPINNER: [&str; 8] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧"];
const REPROBE_SECS: u64 = 4;
const HISTORY: usize = 40;

struct App {
    path: Path,
    verdict: Verdict,
    tick: usize,
    gw_hist: VecDeque<f64>,
    wan_hist: VecDeque<f64>,
    scanning: bool,
}

impl App {
    fn new() -> Self {
        let path = engine::skeleton();
        let verdict = diagnose(&path);
        App {
            path,
            verdict,
            tick: 0,
            gw_hist: VecDeque::with_capacity(HISTORY),
            wan_hist: VecDeque::with_capacity(HISTORY),
            scanning: true,
        }
    }

    fn apply(&mut self, hop: Hop) {
        match hop.id {
            HopId::Gateway => push(&mut self.gw_hist, hop.latency_ms),
            HopId::Wan => push(&mut self.wan_hist, hop.latency_ms),
            _ => {}
        }
        self.path.upsert(hop);
        if self.path.is_complete() {
            self.verdict = diagnose(&self.path);
            self.scanning = false;
        }
    }

    fn restart(&mut self) -> mpsc::UnboundedReceiver<Hop> {
        // Drop conditional hops (e.g. VPN) so a tunnel that disconnected between
        // sweeps doesn't linger as a Pending hop that never resolves — which
        // would leave `is_complete()` false forever and wedge the dashboard.
        // The next sweep re-adds it via `upsert` only if the tunnel is still up.
        self.path.hops.retain(|h| engine::CHAIN.contains(&h.id));
        // Keep telemetry history; reset statuses to pending for the new sweep.
        for hop in &mut self.path.hops {
            if hop.id != HopId::Host {
                hop.status = Status::Pending;
            }
        }
        self.scanning = true;
        engine::spawn()
    }
}

fn push(hist: &mut VecDeque<f64>, v: Option<f64>) {
    if let Some(v) = v {
        if hist.len() == HISTORY {
            hist.pop_front();
        }
        hist.push_back(v);
    }
}

/// Entry point for `wtfi -w`.
pub async fn run() -> Result<()> {
    if !std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        // No TTY (piped/CI): fall back to a single report instead of failing.
        let path = engine::run_once().await;
        let verdict = diagnose(&path);
        print!("{}", crate::render::report(&path, &verdict, true, false));
        return Ok(());
    }

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal).await;
    ratatui::restore();
    result
}

async fn event_loop(terminal: &mut ratatui::DefaultTerminal) -> Result<()> {
    let mut app = App::new();
    let mut events = EventStream::new();
    let mut ticker = interval(Duration::from_millis(120));
    let mut reprobe = interval(Duration::from_secs(REPROBE_SECS));
    let mut rx = app.restart();

    terminal.draw(|f| draw(f, &app))?;

    loop {
        tokio::select! {
            maybe_ev = events.next() => {
                if let Some(Ok(Event::Key(k))) = maybe_ev
                    && k.kind == KeyEventKind::Press
                {
                    match k.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('r') => rx = app.restart(),
                        _ => {}
                    }
                }
            }
            _ = ticker.tick() => {
                app.tick = app.tick.wrapping_add(1);
            }
            Some(hop) = rx.recv() => {
                app.apply(hop);
            }
            _ = reprobe.tick() => {
                if !app.scanning {
                    rx = app.restart();
                }
            }
        }
        terminal.draw(|f| draw(f, &app))?;
    }
    Ok(())
}

// ---- rendering ----

fn color(s: Status) -> Color {
    match s {
        Status::Ok => Color::Green,
        Status::Warn => Color::Yellow,
        Status::Fail => Color::Red,
        Status::Pending => Color::Cyan,
        Status::Skipped => Color::DarkGray,
    }
}

fn draw(f: &mut Frame, app: &App) {
    let rows = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(6), // topology
        Constraint::Length(5), // verdict
        Constraint::Min(6),    // detail + telemetry
        Constraint::Length(1), // footer
    ])
    .split(f.area());

    header(f, rows[0], app);
    topology(f, rows[1], app);
    verdict(f, rows[2], app);
    bottom(f, rows[3], app);
    footer(f, rows[4]);
}

fn header(f: &mut Frame, area: Rect, app: &App) {
    let spin = if app.scanning {
        format!(" {} scanning", SPINNER[app.tick % SPINNER.len()])
    } else {
        " ✓ live".into()
    };
    let line = Line::from(vec![
        Span::styled(
            " wtfi ",
            Style::new().bold().fg(Color::Black).bg(Color::Cyan),
        ),
        Span::styled(" what the f*ck internet", Style::new().dim()),
        Span::styled(spin, Style::new().fg(color(app.verdict.status))),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn topology(f: &mut Frame, area: Rect, app: &App) {
    let hops = &app.path.hops;
    // Alternate node / connector cells across the row.
    let mut constraints = Vec::new();
    for i in 0..hops.len() {
        if i > 0 {
            constraints.push(Constraint::Length(5));
        }
        constraints.push(Constraint::Fill(1));
    }
    let cells = Layout::horizontal(constraints).split(area);

    let mut broke = false;
    for (i, hop) in hops.iter().enumerate() {
        let cell = cells[i * 2];
        node_card(f, cell, hop, app);
        if i + 1 < hops.len() {
            let conn_cell = cells[i * 2 + 1];
            let next = &hops[i + 1];
            let is_break = !broke && next.status == Status::Fail;
            if is_break {
                broke = true;
            }
            connector(f, conn_cell, hop.status.max(next.status), is_break);
        }
    }
}

fn node_card(f: &mut Frame, area: Rect, hop: &Hop, app: &App) {
    let c = color(hop.status);
    let glyph = if hop.status == Status::Pending {
        SPINNER[app.tick % SPINNER.len()]
    } else {
        hop.status.glyph()
    };
    let title = Line::from(vec![
        Span::raw(" "),
        Span::styled(glyph, Style::new().fg(c)),
        Span::styled(format!(" {} ", hop.title), Style::new().fg(c).bold()),
    ]);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(c))
        .title(title);

    let sub = hop.subtitle.clone().unwrap_or_default();
    let stat = hop_stat_line(hop);
    let body = Text::from(vec![
        Line::from(Span::styled(sub, Style::new().dim())).centered(),
        Line::from(stat).centered(),
    ]);
    f.render_widget(Paragraph::new(body).block(block), area);
}

/// The one number that matters for this hop, for the card face.
fn hop_stat_line(hop: &Hop) -> Span<'static> {
    let c = color(hop.status);
    if let Some(ms) = hop.latency_ms {
        return Span::styled(format!("{ms:.0} ms"), Style::new().fg(c).bold());
    }
    let txt = match hop.status {
        Status::Pending => "…",
        Status::Skipped => "skipped",
        Status::Ok => "ok",
        Status::Warn => "warn",
        Status::Fail => "down",
    };
    Span::styled(txt.to_string(), Style::new().fg(c).bold())
}

fn connector(f: &mut Frame, area: Rect, sev: Status, is_break: bool) {
    let c = color(sev);
    let arrow = if is_break {
        "─╳─▶"
    } else {
        "───▶"
    };
    // Vertically center the arrow within the card height.
    let mut lines = vec![Line::default(); 2];
    lines.push(Line::from(Span::styled(arrow, Style::new().fg(c).bold())).centered());
    f.render_widget(Paragraph::new(Text::from(lines)), area);
}

fn verdict(f: &mut Frame, area: Rect, app: &App) {
    let v = &app.verdict;
    let c = color(v.status);
    let tag = match v.status {
        Status::Ok => " ALL GOOD ",
        Status::Warn => " DEGRADED ",
        Status::Pending => " SCANNING ",
        _ => " BROKEN ",
    };
    let mut lines = vec![Line::from(vec![
        Span::styled(tag, Style::new().bg(c).fg(Color::Black).bold()),
        Span::raw(" "),
        Span::styled(v.headline.clone(), Style::new().fg(c).bold()),
    ])];
    lines.push(Line::from(Span::styled(
        v.cause.clone(),
        Style::new().dim(),
    )));
    if let Some(fix) = &v.fix {
        lines.push(Line::from(vec![
            Span::styled("→ ", Style::new().fg(Color::Green).bold()),
            Span::raw(fix.clone()),
        ]));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::DarkGray))
        .padding(Padding::horizontal(1))
        .title(Span::styled(" verdict ", Style::new().dim()));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn bottom(f: &mut Frame, area: Rect, app: &App) {
    let cols =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).split(area);
    detail(f, cols[0], app);
    telemetry(f, cols[1], app);
}

fn detail(f: &mut Frame, area: Rect, app: &App) {
    let mut lines = Vec::new();
    for hop in &app.path.hops {
        if hop.id == HopId::Host {
            continue;
        }
        let c = color(hop.status);
        let mut spans = vec![
            Span::styled(format!("{} ", hop.status.glyph()), Style::new().fg(c)),
            Span::styled(format!("{:<9}", hop.title), Style::new().fg(c).bold()),
        ];
        if let Some(sum) = &hop.summary {
            spans.push(Span::styled(sum.clone(), Style::new().dim()));
        }
        lines.push(Line::from(spans));
    }
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::DarkGray))
        .padding(Padding::horizontal(1))
        .title(Span::styled(" path detail ", Style::new().dim()));
    f.render_widget(Paragraph::new(lines).block(block), area);
}

fn telemetry(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(Color::DarkGray))
        .padding(Padding::horizontal(1))
        .title(Span::styled(" telemetry ", Style::new().dim()));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let rows = Layout::vertical([
        Constraint::Length(2), // signal gauge
        Constraint::Length(2), // gateway latency
        Constraint::Length(2), // wan latency
    ])
    .split(inner);

    // Signal strength gauge from the link hop's RSSI metric.
    let rssi = app
        .path
        .get(HopId::Link)
        .and_then(|h| h.metrics.iter().find(|m| m.label == "RSSI"))
        .and_then(|m| m.value.split_whitespace().next())
        .and_then(|s| s.parse::<f64>().ok());
    let ratio = rssi
        .map(|r| ((r + 90.0) / 60.0).clamp(0.0, 1.0))
        .unwrap_or(0.0);
    let gcol = if ratio > 0.6 {
        Color::Green
    } else if ratio > 0.35 {
        Color::Yellow
    } else {
        Color::Red
    };
    let g = Gauge::default()
        .gauge_style(Style::new().fg(gcol))
        .ratio(ratio)
        .label(format!(
            "signal {}",
            rssi.map(|r| format!("{r:.0} dBm"))
                .unwrap_or_else(|| "—".into())
        ));
    f.render_widget(g, rows[0]);

    sparkline(f, rows[1], "gateway", &app.gw_hist, Color::Cyan);
    sparkline(f, rows[2], "wan", &app.wan_hist, Color::Magenta);
}

/// Dependency-free unicode sparkline so we fully control scaling.
fn sparkline(f: &mut Frame, area: Rect, label: &str, hist: &VecDeque<f64>, col: Color) {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let last = hist.back().copied();
    let (min, max) = hist
        .iter()
        .fold((f64::MAX, f64::MIN), |(lo, hi), &v| (lo.min(v), hi.max(v)));
    let width = area.width.saturating_sub(14) as usize;
    let take = hist.len().saturating_sub(width);
    let spark: String = hist
        .iter()
        .skip(take)
        .map(|&v| {
            let t = if max > min {
                (v - min) / (max - min)
            } else {
                0.5
            };
            BARS[((t * 7.0).round() as usize).min(7)]
        })
        .collect();
    let line = Line::from(vec![
        Span::styled(format!("{label:<8}"), Style::new().dim()),
        Span::styled(spark, Style::new().fg(col)),
        Span::styled(
            last.map(|v| format!(" {v:.0}ms")).unwrap_or_default(),
            Style::new().fg(col).add_modifier(Modifier::BOLD),
        ),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn footer(f: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(" q ", Style::new().bg(Color::DarkGray)),
        Span::styled(" quit   ", Style::new().dim()),
        Span::styled(" r ", Style::new().bg(Color::DarkGray)),
        Span::styled(" re-probe now   ", Style::new().dim()),
        Span::styled(format!(" auto every {REPROBE_SECS}s"), Style::new().dim()),
    ]);
    f.render_widget(Paragraph::new(line), area);
}
