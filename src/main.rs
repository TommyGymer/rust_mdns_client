use async_std::task;
use clap::Parser;
use color_eyre::Result;
use crossterm::event::{self, Event};
use futures_util::{pin_mut, stream::StreamExt};
use mdns::{discover, Record, RecordKind};
use ratatui::{DefaultTerminal, Frame};
use std::{
    net::IpAddr,
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

#[async_std::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init();

    let args = Args::parse();

    let stream = discover::all(args.query, Duration::from_secs(15))?.listen();

    let records: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let records_out = records.clone();

    let child = task::spawn(async move {
        pin_mut!(stream);
        while let Some(Ok(response)) = stream.next().await {
            let res: Vec<(IpAddr, String)> =
                response.records().filter_map(self::to_ip_addr).collect();

            for (addr, name) in res {
                // println!("found cast device {} at {}", name, addr);
                records
                    .lock()
                    .unwrap()
                    .push(format!("found cast device {} at {}", name, addr));
            }
        }
    });

    let result = run(terminal, records_out);
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

fn run(mut terminal: DefaultTerminal, records: Arc<Mutex<Vec<String>>>) -> Result<()> {
    loop {
        terminal.draw(render)?;
        if matches!(event::read()?, Event::Key(_)) {
            break Ok(());
        }
    }
}

fn render(frame: &mut Frame) {
    frame.render_widget("hello world", frame.area());
}
