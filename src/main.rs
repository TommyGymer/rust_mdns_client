use async_std::task;
use clap::Parser;
use color_eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use futures_util::{pin_mut, stream::StreamExt};
use mdns::{discover, Record, RecordKind};
use ratatui::{
    prelude::{Buffer, Constraint, Rect},
    style::Stylize,
    symbols::border,
    text::Line,
    widgets::{Block, Paragraph, Row, Table, Widget},
    DefaultTerminal, Frame,
};
use std::{
    fmt::{self, Display, Formatter},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Duration,
};

/// Simple TUI for discovering mDNS capable devices
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// The mDNS query, e.g., "_http._tcp.local"
    query: String,
}

#[derive(Debug, Ord, PartialOrd, PartialEq, Eq, Clone)]
enum RecordEntry {
    A(Ipv4Addr, String),
    AAAA(Ipv6Addr, String),
}

#[derive(Default, Debug, Clone)]
struct RecordEntries {
    entries: Vec<RecordEntry>,
}

impl RecordEntry {
    fn new(ip: IpAddr, name: String) -> Self {
        match ip {
            IpAddr::V4(addr) => RecordEntry::A(addr, name),
            IpAddr::V6(addr) => RecordEntry::AAAA(addr, name),
        }
    }

    fn get_name(self) -> String {
        match self {
            RecordEntry::A(_, name) => name,
            RecordEntry::AAAA(_, name) => name,
        }
    }

    fn is_ipv4(self) -> bool {
        match self {
            RecordEntry::A(_, _) => true,
            RecordEntry::AAAA(_, _) => false,
        }
    }

    fn is_ipv6(self) -> bool {
        match self {
            RecordEntry::A(_, _) => false,
            RecordEntry::AAAA(_, _) => true,
        }
    }

    fn get_addr(self) -> IpAddr {
        match self {
            RecordEntry::A(addr, _) => IpAddr::V4(addr),
            RecordEntry::AAAA(addr, _) => IpAddr::V6(addr),
        }
    }
}

impl Display for RecordEntry {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let (addr, name) = match self {
            RecordEntry::A(addr, name) => (format!("{}", addr), name),
            RecordEntry::AAAA(addr, name) => (format!("{}", addr), name),
        };
        write!(f, "{}: {}", name, addr)
    }
}

impl RecordEntries {
    fn find(self, name: String) -> (Option<IpAddr>, Option<IpAddr>) {
        let mut remaining = self.entries.clone();
        remaining.retain(|r| r.clone().get_name() == name);

        let mut ipv4 = remaining.clone();
        ipv4.retain(|r| r.clone().is_ipv4());

        let mut ipv6 = remaining.clone();
        ipv6.retain(|r| r.clone().is_ipv6());

        let v4 = match ipv4.pop() {
            Some(ip) => Some(ip.get_addr()),
            None => None,
        };

        let v6 = match ipv6.pop() {
            Some(ip) => Some(ip.get_addr()),
            None => None,
        };

        (v4, v6)
    }
}

impl Display for RecordEntries {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        for r in self.entries.clone() {
            write!(f, "{}\n", r)?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct App {
    exit: bool,
    records: Arc<Mutex<RecordEntries>>,
}

impl App {
    fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while !self.exit {
            terminal.draw(|frame| self.draw(frame))?;
            match event::poll(Duration::from_millis(8)) {
                Ok(true) => self.handle_events()?,
                _ => {}
            }
        }
        Ok(())
    }

    fn draw(&self, frame: &mut Frame) {
        frame.render_widget(self, frame.area());
    }

    fn handle_events(&mut self) -> Result<()> {
        match event::read()? {
            Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                self.handle_key_event(key_event)
            }
            _ => {}
        };
        Ok(())
    }

    fn handle_key_event(&mut self, key_event: KeyEvent) {
        match key_event.code {
            KeyCode::Char('q') => self.exit = true,
            _ => {}
        }
    }
}

impl Widget for &App {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let title = Line::from(" mDNS ".bold());
        let block = Block::bordered()
            .title(title.centered())
            .border_set(border::THICK);

        // TODO: add field to specify the mDNS query

        let records: RecordEntries = self.records.lock().unwrap().clone();
        let mut hosts: Vec<String> = records
            .entries
            .iter()
            .map(|r| r.clone().get_name())
            .collect();
        let mut seen: Vec<String> = Vec::new();

        hosts.retain(|h| {
            let r = !seen.contains(h);
            seen.push(h.clone());
            r
        });

        let rows: Vec<Row> = hosts
            .iter()
            .map(|h| {
                // TODO: this clone shouldn't be needed
                let (ipv4, ipv6) = records.clone().find(h.clone());
                let v4 = match ipv4 {
                    Some(ip) => format!("{:?}", ip),
                    None => String::from(""),
                };
                let v6 = match ipv6 {
                    Some(ip) => format!("{:?}", ip),
                    None => String::from(""),
                };
                Row::new(vec![String::from(h), v4, v6])
            })
            .collect();
        let widths = [
            Constraint::Percentage(40),
            Constraint::Percentage(30),
            Constraint::Percentage(30),
        ];
        Table::new(rows, widths)
            .header(
                Row::new(vec!["Host", "IPv4", "IPv6"])
                    .bold()
                    .bottom_margin(1),
            )
            .block(block)
            .render(area, buf);
    }
}

#[async_std::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let mut terminal = ratatui::init();

    let args = Args::parse();

    let stream = discover::all(args.query, Duration::from_secs(5))?.listen();

    let mut app = App::default();
    let records = Arc::clone(&app.records);

    let child = task::spawn(async move {
        pin_mut!(stream);
        while let Some(Ok(response)) = stream.next().await {
            let res: Vec<(IpAddr, String)> =
                response.records().filter_map(self::to_ip_addr).collect();

            for (addr, name) in res {
                records.lock().unwrap().entries.retain(|r| !match r {
                    RecordEntry::A(_, n) => addr.is_ipv4() && *n == name,
                    RecordEntry::AAAA(_, n) => addr.is_ipv6() && *n == name,
                });
                records
                    .lock()
                    .unwrap()
                    .entries
                    .push(RecordEntry::new(addr, name));
            }
            records.lock().unwrap().entries.sort();
        }
    });

    let result = app.run(&mut terminal);
    ratatui::restore();

    child.cancel().await;
    result
}

fn to_ip_addr(record: &Record) -> Option<(IpAddr, String)> {
    match record.kind {
        RecordKind::A(addr) => Some((addr.into(), record.name.clone())),
        RecordKind::AAAA(addr) => Some((addr.into(), record.name.clone())),
        _ => None,
    }
}
