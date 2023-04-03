use core::panic;
use etherparse::PacketHeaders;
use libc::{self, c_void, read};
use pnet::{
    packet::{
        icmp::{echo_request, IcmpTypes},
        ip::IpNextHeaderProtocols,
    },
    transport::{transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4},
};
use std::{
    net::{IpAddr, Ipv4Addr},
    thread,
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

    let mut buffer = [0u8; 16];

    let mut icmp_req_packet = echo_request::MutableEchoRequestPacket::new(&mut buffer).unwrap();
    icmp_req_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_req_packet.set_sequence_number(0);
    let payload = [1, 2, 3, 4, 5, 6, 7, 8];
    icmp_req_packet.set_payload(&payload);
    icmp_req_packet.set_checksum(59371);

    let (mut tx, rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!(
            "An error occurred when creating the transport channel: {}",
            e
        ),
    };

    thread::scope(|s| {
        s.spawn(|| {
            match tx.send_to(
                icmp_req_packet,
                IpAddr::V4(Ipv4Addr::new(192, 168, 100, 14)),
            ) {
                Ok(n) => n,
                Err(e) => panic!("failed to send packet: {}", e),
            }
        });
    });

    let sd = rx.socket.fd;

    let mut res = [0u8; 200]; // the response packet
    let buf_point: *mut c_void = res.as_mut_ptr() as *mut c_void;

    unsafe { read(sd, buf_point, 200) };

    match PacketHeaders::from_ip_slice(&res) {
        Err(e) => println!("{:?}", e),
        Ok(val) => println!("{:?}", val.transport),
    }

    Ok(())
}
