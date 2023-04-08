use core::panic;
use etherparse::{Icmpv4Type, PacketHeaders, ReadError, TransportHeader};
use libc::{self, c_void, read};
use pnet::{
    packet::{
        icmp::{
            echo_request::{self, MutableEchoRequestPacket},
            IcmpTypes,
        },
        ip::IpNextHeaderProtocols,
    },
    transport::{
        transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4, TransportReceiver,
    },
};
use rayon::prelude::*;
use std::{
    io::Error,
    net::{IpAddr, Ipv4Addr},
    thread,
};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

    (1..=255).into_par_iter().for_each(|x| {
        let (mut tx, rx) = match transport_channel(4096, protocol) {
            Ok((tx, rx)) => (tx, rx),
            Err(e) => panic!(
                "An error occurred when creating the transport channel: {}",
                e
            ),
        };
        let mut buffer = [0u8; 16];
        let icmp_req_packet = create_packet(&mut buffer);
        let ip_address = IpAddr::V4(Ipv4Addr::new(192, 168, 100, x));
        thread::scope(|s| {
            s.spawn(|| {
                match tx.send_to(icmp_req_packet, ip_address) {
                    Ok(n) => n,
                    Err(e) => panic!("failed to send packet: {}", e),
                };
            });
        });

        match read_from_res(rx) {
            Ok(s) => println!("{}: {}", ip_address, s),
            Err(e) => println!("{}: {}", ip_address, e.to_string()),
        };
    });

    Ok(())
}

fn read_from_res(rx: TransportReceiver) -> Result<String, Error> {
    let sd = rx.socket.fd;

    let mut res = [0u8; 200]; // the response packet
    let buf_point: *mut c_void = res.as_mut_ptr() as *mut c_void;

    unsafe { read(sd, buf_point, 200) };

    let res_protocol: Result<Option<TransportHeader>, ReadError> =
        match PacketHeaders::from_ip_slice(&res) {
            Ok(v) => Ok(v.transport),
            Err(e) => Err(e),
        };

    if let Some(v) = res_protocol.unwrap().unwrap().icmpv4() {
        match v.icmp_type {
            Icmpv4Type::EchoReply(_) => Ok(String::from("Host available")),
            Icmpv4Type::DestinationUnreachable(_) => Ok(String::from("Destination unreachable")),
            _ => Ok(String::from("Unexpected")),
        }
    } else {
        return Ok(String::from("Unexpected"));
    }
}

fn create_packet(buffer: &mut [u8; 16]) -> MutableEchoRequestPacket {
    let mut icmp_req_packet = echo_request::MutableEchoRequestPacket::new(buffer).unwrap();
    icmp_req_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_req_packet.set_sequence_number(0);
    let payload = [1, 2, 3, 4, 5, 6, 7, 8];
    icmp_req_packet.set_payload(&payload);
    icmp_req_packet.set_checksum(59371);
    icmp_req_packet
}
