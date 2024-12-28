use async_std::task::{self, JoinHandle};
use clap::Parser;
use color_eyre::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use futures_util::{pin_mut, stream::StreamExt};
use mdns::{discover, Record, RecordKind};
use ratatui::{
    prelude::{Buffer, Constraint, Layout, Rect},
    style::Stylize,
    symbols::border,
    text::Line,
    widgets::{Block, Paragraph, Row, Table, Widget},
    DefaultTerminal, Frame,
};
use std::{
    fmt::{self, Display, Formatter},
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Duration,
};

/// Simple TUI for discovering mDNS capable devices
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// The mDNS query, e.g., "_http._tcp.local"
    query: Option<String>,
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
    query: String,
    editing: bool,
    child: Option<JoinHandle<()>>,
}

impl App {
    async fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while !self.exit {
            terminal.draw(|frame| self.draw(frame))?;
            match event::poll(Duration::from_millis(8)) {
                Ok(true) => self.handle_events().await?,
                _ => {}
            }
        }
        if let Some(c) = mem::take(&mut self.child) {
            c.cancel().await;
        }
        Ok(())
    }

    async fn start_scanner(&mut self) {
        let query = self.query.clone();
        let records: Arc<Mutex<RecordEntries>> = Arc::clone(&self.records);

        if let Some(c) = mem::take(&mut self.child) {
            c.cancel().await;
        }

        self.child = Some(task::spawn(async move {
            let stream = discover::all(query, Duration::from_secs(5))
                .unwrap()
                .listen();
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
        }));
    }

    fn draw(&self, frame: &mut Frame) {
        frame.render_widget(self, frame.area());
    }

    async fn handle_events(&mut self) -> Result<()> {
        match event::read()? {
            Event::Key(key_event) if key_event.kind == KeyEventKind::Press => {
                self.handle_key_event(key_event).await
            }
            _ => {}
        };
        Ok(())
    }

    async fn handle_key_event(&mut self, key_event: KeyEvent) {
        match self.editing {
            false => match key_event.code {
                KeyCode::Char('q') => self.exit = true,
                KeyCode::Esc => self.exit = true,
                KeyCode::Char('/') => self.editing = true,
                _ => {}
            },
            true => match key_event.code {
                KeyCode::Char(c) => self.query.push(c),
                KeyCode::Esc => {
                    self.editing = false;
                    self.start_scanner().await;
                    self.records.lock().unwrap().entries.clear();
                }
                KeyCode::Backspace => {
                    self.query.pop().unwrap_or('a');
                    ()
                }
                KeyCode::Enter => {
                    self.editing = false;
                    self.start_scanner().await;
                    self.records.lock().unwrap().entries.clear();
                }
                _ => {}
            },
        }
    }
}

impl Widget for &App {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let search_block = Block::bordered()
            .title(Line::from(" mDNS Query ".bold()))
            .border_set(border::THICK);

        let table_block = Block::bordered()
            .title(Line::from(" Records ".bold()))
            .border_set(border::THICK);

        let [search_area, table_area] =
            Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).areas(area);

        Paragraph::new(match self.editing {
            false => self.query.clone(),
            true => format!("{}_", self.query.clone()),
        })
        .block(search_block)
        .render(search_area, buf);

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
                let (ipv4, ipv6) = records.clone().find(h.clone());
                let v4 = match ipv4 {
                    Some(ip) => format!("{:?}", ip),
                    None => String::from("Not found"),
                };
                let v6 = match ipv6 {
                    Some(ip) => format!("{:?}", ip),
                    None => String::from("Not found"),
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
            .block(table_block)
            .render(table_area, buf);
    }
}

#[async_std::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let mut terminal = ratatui::init();
    terminal.clear()?;

    let args = Args::parse();

    let mut app = App::default();
    match args.query {
        Some(q) => {
            app.query = q;
            app.start_scanner().await;
        }
        None => app.query = String::from(""),
    };
    app.editing = false;

    let result = app.run(&mut terminal).await;
    ratatui::restore();

    result
}

fn to_ip_addr(record: &Record) -> Option<(IpAddr, String)> {
    match record.kind {
        RecordKind::A(addr) => Some((addr.into(), record.name.clone())),
        RecordKind::AAAA(addr) => Some((addr.into(), record.name.clone())),
        _ => None,
    }
}
