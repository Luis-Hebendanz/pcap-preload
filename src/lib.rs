use lazy_static::lazy_static;
use libc::{c_int, c_void, size_t, ssize_t};
use pcap_file::pcap::PcapPacket;
use pcap_file::pcap::PcapWriter;
use std::env;
use std::fs::File;
use std::mem;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Mutex;
use std::time::Instant;

struct Message {
    data: Vec<u8>,
    source_addr: Option<SocketAddrV4>,
    dest_addr: Option<SocketAddrV4>,
    ret: isize,
}

lazy_static! {
    static ref MESSAGES: Mutex<Vec<Message>> = Mutex::new(Vec::new());
    static ref PCAP_LOG_FILE: Option<Mutex<PcapWriter<File>>> = {
        if let Ok(strval) = env::var("PCAP_LOG_FILE") {
            if let Ok(file) = File::create(strval) {
                Some(Mutex::new(
                    PcapWriter::new(file).expect("Error writing file"),
                ))
            } else {
                None
            }
        } else {
            None
        }
    };
    static ref START: Instant = Instant::now();
    static ref REAL_RECV: extern "C" fn(socket: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t = unsafe {
        std::mem::transmute(libc::dlsym(
            libc::RTLD_NEXT,
            b"recv\0".as_ptr() as *const i8,
        ))
    };
    static ref REAL_SEND: extern "C" fn(socket: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t = unsafe {
        std::mem::transmute(libc::dlsym(
            libc::RTLD_NEXT,
            b"send\0".as_ptr() as *const i8,
        ))
    };
}



fn create_ethernet_frame(
    data: Vec<u8>,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
) -> Vec<u8> {
    let mut frame = Vec::new();
    // Ethernet header
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&[0x08, 0x00]); // EtherType (IPv4)
    // IP header
    frame.push(0x45); // version and header length
    frame.push(0); // type of service
    let total_length = (data.len() + 28) as u16;
    frame.extend_from_slice(&total_length.to_be_bytes()); // total length
    frame.extend_from_slice(&0u16.to_be_bytes()); // identification
    frame.extend_from_slice(&0u16.to_be_bytes()); // flags and fragment offset
    frame.push(64); // time to live
    frame.push(17); // protocol (UDP)
    frame.extend_from_slice(&0u16.to_be_bytes()); // checksum (will be calculated later)
    frame.extend_from_slice(&src_ip.octets());
    frame.extend_from_slice(&dst_ip.octets());
    // UDP header
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    let length = (data.len() + 8) as u16;
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // checksum
    // data
    frame.extend(data);
    // calculate IP checksum
    let checksum = ip_checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in header.chunks(2) {
        let word = u16::from_be_bytes([word[0], word[1]]);
        sum = sum.wrapping_add(word as u32);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn get_peer_addr(fd: i32) -> Option<SocketAddrV4> {
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len = std::mem::size_of_val(&addr) as u32;
    let result =
        unsafe { libc::getpeername(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len) };
    if result == 0 {
        let ip = Ipv4Addr::new(
            ((addr.sin_addr.s_addr & 0xFF) >> 0) as u8,
            ((addr.sin_addr.s_addr & 0xFF00) >> 8) as u8,
            ((addr.sin_addr.s_addr & 0xFF0000) >> 16) as u8,
            ((addr.sin_addr.s_addr & 0xFF000000) >> 24) as u8,
        );
        let port = u16::from_be(addr.sin_port);
        Some(SocketAddrV4::new(ip, port))
    } else {
        None
    }
}

fn get_sock_name(fd: i32) -> Option<SocketAddrV4> {
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len = std::mem::size_of_val(&addr) as u32;
    let result =
        unsafe { libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len) };
    if result == 0 {
        let ip = Ipv4Addr::new(
            ((addr.sin_addr.s_addr & 0xFF) >> 0) as u8,
            ((addr.sin_addr.s_addr & 0xFF00) >> 8) as u8,
            ((addr.sin_addr.s_addr & 0xFF0000) >> 16) as u8,
            ((addr.sin_addr.s_addr & 0xFF000000) >> 24) as u8,
        );
        let port = u16::from_be(addr.sin_port);
        Some(SocketAddrV4::new(ip, port))
    } else {
        None
    }
}

fn write_message(m: Message) {
    println!("Message len: {}", m.data.len());
    if let Some(Ok(mut file)) = PCAP_LOG_FILE.as_ref().and_then(|f| Some(f.lock())) {
        let udp = create_ethernet_frame(
            m.data,
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            *m.source_addr.unwrap().ip(),
            m.source_addr.unwrap().port(),
            *m.dest_addr.unwrap().ip(),
            m.dest_addr.unwrap().port(),
        );
        let p = PcapPacket {
            timestamp: START.elapsed(),
            orig_len: udp.len().try_into().unwrap(),
            data: udp.into(),
        };
        file.write_packet(&p).expect("Error writing packet");
    }
}

#[no_mangle]
pub unsafe extern "C" fn recv(fd: c_int, buf: *const c_void, n: size_t, flags: c_int) -> isize {
    let source_addr = get_peer_addr(fd);
    let dest_addr = get_sock_name(fd);
    println!("====recv({:?}, {:?})====", source_addr, dest_addr);
    let res = REAL_RECV(fd, buf, n, flags);

    if res <= 0 {
        return res;
    }

    let slice = std::slice::from_raw_parts(buf as *const u8, res as usize);

    let message = Message {
        data: slice.to_vec(),
        source_addr: source_addr,
        dest_addr: dest_addr,
        ret: res,
    };
    write_message(message);
    res
}

#[no_mangle]
pub unsafe extern "C" fn send(fd: c_int, buf: *const c_void, n: size_t, flags: c_int) -> isize {
    let source_addr = get_peer_addr(fd);
    let dest_addr = get_sock_name(fd);
    println!("====send({:?} -> {:?})====", source_addr, dest_addr);
    let res = REAL_SEND(fd, buf, n, flags);
    if res <= 0 {
        return res;
    }
    let slice = std::slice::from_raw_parts(buf as *const u8, n as usize);
    let message = Message {
        data: slice.to_vec(),
        source_addr: source_addr,
        dest_addr: dest_addr,
        ret: res,
    };
    write_message(message);
    res
}