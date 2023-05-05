use core::{panic, time};
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
    transport::{transport_channel, TransportChannelType::Layer4, TransportProtocol::Ipv4},
};
use rayon;
use std::{
    fmt,
    io::{self, stdin, stdout, Write},
    net::Ipv4Addr,
    process::Command,
    sync::{Arc, Mutex},
};
use termion::{cursor::DetectCursorPos, raw::IntoRawMode};
use termion::{event::Key, input::TermRead};

enum IntruderError {
    UnableToRead,
    NotFound,
}

impl fmt::Display for IntruderError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IntruderError::UnableToRead => write!(f, "Unable to read packet"),
            IntruderError::NotFound => write!(f, "Icmp Echo Reply not found"),
        }
    }
}

#[derive(Debug)]
struct IcmpEchoReply {
    received: bool,
    src: Ipv4Addr,
    dst: Ipv4Addr,
}

#[tokio::main]
async fn main() {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

    let clients: Arc<std::sync::Mutex<Box<Vec<Ipv4Addr>>>> =
        Arc::new(Mutex::new(Box::new(Vec::new()))); // devices connected to the network

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(255)
        .build()
        .unwrap();

    let ten_mins = time::Duration::from_secs(600); // ten mins = 600 seconds

    // send icmp requests every ten minutes
    loop {
        for i in 1..255 {
            let clients = Arc::clone(&clients);
            pool.install(|| {
                let (mut tx, rx) = match transport_channel(4096, protocol) {
                    Ok((tx, rx)) => (tx, rx),
                    Err(e) => panic!(
                        "An error occurred when creating the transport channel: {}",
                        e
                    ),
                };
                let mut buffer = [0u8; 16];
                let icmp_req_packet = create_packet(&mut buffer);
                let ip_address = Ipv4Addr::new(192, 168, 100, i);
                match tx.send_to(icmp_req_packet, std::net::IpAddr::V4(ip_address)) {
                    Ok(n) => n,
                    Err(e) => panic!("failed to send packet: {}", e),
                };

                let sd = rx.socket.fd;

                let mut clients = clients.lock().unwrap();

                match read_from_res(sd, ip_address) {
                    Ok(s) => {
                        if s.received {
                            match clients.contains(&ip_address) {
                                true => (),
                                false => {
                                    let output = Command::new("sudo")
                                        .arg("-u")
                                        .arg("[NON-PRIVILEGED-USER]") // add non-privileged user
                                        .arg("cargo")
                                        .arg("run")
                                        .arg("--bin")
                                        .arg("alert")
                                        .output()
                                        .expect("alert.rs failed to run");
                                    io::stdout().write_all(&output.stdout).unwrap(); // intruder alert

                                    confirm_ip(s.src);
                                    clients.push(ip_address)
                                }
                            }
                        }
                        println!("{:?}", s);
                    }
                    Err(e) => println!("{}: {}", ip_address, e.to_string()),
                };
            });
        }

        println!("hosts detected: {:?}", clients.lock().unwrap()); // debug

        std::thread::sleep(ten_mins);
    }
}

fn read_from_res(sd: i32, ip_address: Ipv4Addr) -> Result<IcmpEchoReply, IntruderError> {
    let mut res = [0u8; 200]; // the response packet
    let buf_point: *mut c_void = res.as_mut_ptr() as *mut c_void;

    unsafe { read(sd, buf_point, 200) };

    let res_protocol: Result<Option<TransportHeader>, ReadError> =
        match PacketHeaders::from_ip_slice(&res) {
            Ok(v) => Ok(v.transport),
            Err(e) => Err(e),
        };

    let src_ip = match etherparse::Ipv4HeaderSlice::from_slice(&res) {
        Ok(iph) => Ok(iph.source_addr()),
        Err(e) => Err(e),
    };

    let dst_ip = match etherparse::Ipv4HeaderSlice::from_slice(&res) {
        Ok(iph) => Ok(iph.destination_addr()),
        Err(e) => Err(e),
    };

    let mut icmp_reply = IcmpEchoReply {
        received: false,
        src: src_ip.unwrap(),
        dst: dst_ip.unwrap(),
    };

    if icmp_reply.src == ip_address {
        if let Some(v) = res_protocol.unwrap().unwrap().icmpv4() {
            match v.icmp_type {
                Icmpv4Type::EchoReply(_) => {
                    icmp_reply.received = true;
                    Ok(icmp_reply)
                }
                _ => Ok(icmp_reply), // redundant
            }
        } else {
            return Err(IntruderError::UnableToRead);
        }
    } else {
        return Err(IntruderError::NotFound);
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

fn confirm_ip(ip_address: Ipv4Addr) {
    let stdin = stdin();
    let mut stdout = stdout().into_raw_mode().unwrap();

    write!(
        stdout,
        "Press 'c' to confirm the ip address {}{}",
        ip_address,
        termion::cursor::Hide
    )
    .unwrap();
    stdout.flush().unwrap();

    let y_coordinate = stdout.cursor_pos().unwrap().1;

    for c in stdin.keys() {
        write!(stdout, "\n {}", termion::cursor::Goto(1, y_coordinate + 1)).unwrap();

        match c.unwrap() {
            Key::Char('c') => break,
            _ => {}
        }
        stdout.flush().unwrap();
    }

    write!(stdout, "{}", termion::cursor::Show).unwrap();
}
