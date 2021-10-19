#[macro_use]
extern crate tracing;

use anyhow::{anyhow, Result};
use pcap::{Capture, Device, Packet};
use pktparse::ethernet::parse_ethernet_frame;
use pktparse::icmp::{parse_icmp_header, IcmpCode};
use pktparse::ipv4::parse_ipv4_header;
use sha2::{Digest, Sha512};
use std::time::{Duration, Instant};
use structopt::StructOpt;

#[derive(StructOpt)]
#[structopt(rename_all = "snake_case")]
/// Network watchdog.
struct Config {
    /// Bind interface
    #[structopt(short, long, default_value = "lo")]
    bind_interface: String,
    /// Watchdog interval
    #[structopt(short = "i", long, parse(try_from_str = humantime::parse_duration), default_value = "1s")]
    watchdog_interval: Duration,
    /// Watchdog secret
    #[structopt(short = "s", long)]
    watchdog_secret: Option<String>,
}

/// Check if a packet is a valid watchdog kick.
fn valid_packet(conf: &Config, packet: &Packet) -> bool {
    if let Ok((payload, icmp)) = parse_ethernet_frame(&packet.data)
        .and_then(|(rem_data, _frame)| parse_ipv4_header(rem_data))
        .and_then(|(rem_data, _datagram)| parse_icmp_header(rem_data))
    {
        // Check the ICMP header
        if icmp.code != IcmpCode::Other(4864) {
            debug!("dropping packet with invalid code");
            return false;
        }

        // Check for the watchdog prefix
        if !payload[4..].starts_with(b"witness_me") {
            debug!("dropping packet with invalid prefix");
            return false;
        }

        // Check for the watchdog secret
        let mut hasher = Sha512::new();
        if let Some(ref secret) = conf.watchdog_secret {
            if &payload[14..(14 + secret.len())] != secret.as_bytes() {
                debug!("dropping packet with invalid secret");
                return false;
            }
            hasher.update(&payload[4..(14 + secret.len())]);
        } else {
            hasher.update(&payload[4..14]);
        }

        if payload.len() < 64 {
            debug!("dropping short packet");
            return false;
        }

        if hasher.finalize()[..] != payload[(payload.len() - 64)..] {
            debug!("dropping packet with invalid hash");
            return false;
        }

        return true;
    }

    false
}

/// Main.
fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let conf = Config::from_args();
    info!("initializing watchdog on {}", conf.bind_interface);
    let device = Device::list()?
        .into_iter()
        .find(|x| x.name == conf.bind_interface)
        .ok_or_else(|| anyhow!("unable to resolve interface"))?;
    let mut capture = Capture::from_device(device)?
        .promisc(true)
        .snaplen(65536)
        .timeout(100)
        .open()?
        .setnonblock()?;
    capture.filter("icmp", true)?;

    info!(
        "running watchdog with timeout set to {}ms",
        conf.watchdog_interval.as_millis(),
    );

    let mut epoch = Instant::now();
    loop {
        let now = Instant::now();
        if now.duration_since(epoch) > conf.watchdog_interval {
            error!("WATCHDOG EXPIRED!!!");
            break;
        }

        match capture.next() {
            Ok(packet) => {
                if valid_packet(&conf, &packet) {
                    info!("kicked, starting new epoch");
                    epoch = now;
                }
            }

            Err(pcap::Error::TimeoutExpired) => {}

            Err(e) => {
                error!("pcap error: {}", e);
                break;
            }
        }
    }

    Ok(())
}
