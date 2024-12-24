use color_eyre::Result;
use futures_util::{pin_mut, stream::StreamExt};
use mdns::{Record, RecordKind};
use std::{net::IpAddr, time::Duration};

#[async_std::main]
async fn main() -> Result<()> {
    let stream =
        mdns::discover::all("_formlabs_formule._tcp.local", Duration::from_secs(15))?.listen();
    pin_mut!(stream);

    while let Some(Ok(response)) = stream.next().await {
        // println!(
        //     "{:#?}",
        //     response
        //         .records()
        //         .map(|r| format!("{:#?}", r))
        //         .collect::<Vec<String>>()
        // );
        let res = response.records().filter_map(self::to_ip_addr).next();
        // let name: Vec<String> = response
        //     .records()
        //     .filter_map(|r| Some(r.name.clone()))
        //     .collect();

        if let Some((addr, name)) = res {
            println!("found cast device {} at {}", name, addr);
        } else {
            println!("cast device does not advertise address");
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
