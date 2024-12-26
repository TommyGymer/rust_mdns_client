use clap::Parser;
use color_eyre::Result;
use futures_util::{pin_mut, stream::StreamExt};
use mdns::{discover, Record, RecordKind};
use std::{net::IpAddr, time::Duration};

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

    let args = Args::parse();

    let stream = discover::all(args.query, Duration::from_secs(15))?.listen();
    pin_mut!(stream);

    while let Some(Ok(response)) = stream.next().await {
        let res: Vec<(IpAddr, String)> = response.records().filter_map(self::to_ip_addr).collect();

        for (addr, name) in res {
            println!("found cast device {} at {}", name, addr);
        }
    }

    Ok(())
}

fn to_ip_addr(record: &Record) -> Option<(IpAddr, String)> {
    match record.kind {
        RecordKind::A(addr) => Some((addr.into(), record.name.clone())),
        RecordKind::AAAA(addr) => Some((addr.into(), record.name.clone())),
        _ => None,
    }
}
