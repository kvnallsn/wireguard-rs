//! Demonstrates creating a tun device and connecting to a wireguard endpoint

use std::net::SocketAddr;
use tun_rs::TunConfig;
use wireguard_rs::device::WgDevice;

fn main() {
    let (tx, rx) = crossbeam_channel::unbounded();
    ctrlc::set_handler(move || tx.send(()).expect("failed to send ctrlc signal"))
        .expect("failed to set ctrlc handler");

    color_eyre::install().expect("failed to install color_eyre handler");

    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .with_thread_names(true)
        .init();

    let tun_cfg = TunConfig::default()
        .name("dune1")
        .ip([192, 168, 70, 100], 24);

    let wg = WgDevice::builder()
        .key("EAGwEkkiCJCtrtkLbvkWWUGBoAf3kdumEIQUI7RhtBM=")
        .tun_config(tun_cfg)
        .build()
        .expect("failed to build wireguard device");

    let endpoint: SocketAddr = "10.1.1.6:7777".parse().unwrap();

    // add a peer
    wg.peer("EpujOfemrARH/JE/T0b7Y8/tqvERVAVo7i4mVlWLPCE=")
        .expect("invalid peer key")
        .endpoint(endpoint)
        .keepalive(25)
        .allowed_ip(([192, 168, 70, 0].into(), 24))
        .add();

    // wait for ctrl-c
    rx.recv().expect("failed to receive ctrlc signal");
    println!("caught ctrlc, exiting");
}
