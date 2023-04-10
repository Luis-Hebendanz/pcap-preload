#![allow(clippy::missing_safety_doc)]
use lazy_static::lazy_static;
use libc::socklen_t;
use libc::{c_int, c_void, size_t, ssize_t, sockaddr, msghdr};
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
    dest_addr: Option<SocketAddrV4>
}


lazy_static! {
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

    static ref REAL_RECVFROM: extern "C" fn(socket: c_int, buf: *const c_void, len: size_t, flags: c_int, src_addr: *mut sockaddr, src_len: *mut socklen_t) -> ssize_t = unsafe {
        std::mem::transmute(libc::dlsym(
            libc::RTLD_NEXT,
            b"recvfrom\0".as_ptr() as *const i8,
        ))
    };
    static ref REAL_RECVMSG: extern "C" fn(socket: c_int, msg: *mut msghdr, flags: c_int) -> ssize_t = unsafe {
        std::mem::transmute(libc::dlsym(
            libc::RTLD_NEXT,
            b"recvmsg\0".as_ptr() as *const i8,
        ))
    };

    static ref REAL_SEND: extern "C" fn(socket: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t = unsafe {
        std::mem::transmute(libc::dlsym(
            libc::RTLD_NEXT,
            b"send\0".as_ptr() as *const i8,
        ))
    };
    static ref REAL_SENDTO: extern "C" fn(socket: c_int, buf: *const c_void, len: size_t, flags: c_int, dest_addr: *const sockaddr, dest_len: socklen_t) -> ssize_t = unsafe {
        std::mem::transmute(libc::dlsym(
            libc::RTLD_NEXT,
            b"sendto\0".as_ptr() as *const i8,
        ))
    };

    static ref REAL_SENDMSG: extern "C" fn(socket: c_int, msg: *const msghdr, flags: c_int) -> ssize_t = unsafe {
        std::mem::transmute(libc::dlsym(
            libc::RTLD_NEXT,
            b"sendmsg\0".as_ptr() as *const i8,
        ))
    };
}



// This function creates an Ethernet frame with an IPv4 header and a UDP header. The IP and UDP headers are calculated automatically.
// The data parameter contains the data that should be sent in the Ethernet frame.
// The src_mac and dst_mac parameters are the MAC addresses of the source and destination of the Ethernet frame.
// The src_ip and dst_ip parameters are the IP addresses of the source and destination of the Ethernet frame.
// The src_port and dst_port parameters are the source and destination ports of the UDP header.
// The function returns the Ethernet frame.

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

// This function returns the address of the peer associated with a
// socket descriptor. The socket descriptor is the value returned by
// the socket function, and is used by other socket functions to
// identify a socket.
fn get_peer_addr(fd: i32) -> Option<SocketAddrV4> {
    // Create a socket address structure and zero it out.
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };

    // Get the size of the socket address structure.
    let mut len = std::mem::size_of_val(&addr) as u32;

    // Call getpeername to get the address of the peer.
    let result =
        unsafe { libc::getpeername(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len) };

    // If getpeername returns success, extract the IP address and port
    // from the socket address structure and return it.
    if result == 0 {
        // Extract the IP address from the socket address structure.
        let ip = Ipv4Addr::new(
            (addr.sin_addr.s_addr & 0xFF) as u8,
            ((addr.sin_addr.s_addr & 0xFF00) >> 8) as u8,
            ((addr.sin_addr.s_addr & 0xFF0000) >> 16) as u8,
            ((addr.sin_addr.s_addr & 0xFF000000) >> 24) as u8,
        );

        // Extract the port from the socket address structure.
        let port = u16::from_be(addr.sin_port);

        // Return the peer address.
        Some(SocketAddrV4::new(ip, port))
    } else {
        None
    }
}



// This function returns the local address and port of a socket.
//
// The socket is identified by the file descriptor.
//
// The function returns an Option containing the SocketAddrV4 if the call to
// getsockname was successful, or None if it was not.
fn get_sock_name(fd: i32) -> Option<SocketAddrV4> {
    let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
    let mut len = std::mem::size_of_val(&addr) as u32;
    let result =
        unsafe { libc::getsockname(fd, &mut addr as *mut _ as *mut libc::sockaddr, &mut len) };
    if result == 0 {
        let ip = Ipv4Addr::new(
            (addr.sin_addr.s_addr & 0xFF) as u8,
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
    if let Some(Ok(mut file)) = PCAP_LOG_FILE.as_ref().map(|f| f.lock()) {
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

//
// This function is called when a packet is received by the server.
// It takes the following arguments:
// fd: The file descriptor of the socket on which the packet was received.
// buf: A pointer to a buffer that contains the data of the packet.
// n: The size of the buffer.
// flags: Flags that were passed to the recv function.
//
// It returns the number of bytes received, or -1 if an error occurred.
//
// The function prints the source and destination addresses of the packet,
// and writes the packet to a file.
//
// The function is marked unsafe, because it accesses a raw pointer.
// This is safe because the pointer is only used to read data from the buffer,
// and the data is not modified.
//
// The function is marked extern "C", because it is called from C code.
//
// The function is marked #[no_mangle], because we want to call it directly,
// without going through the Rust name mangling mechanism.
//

#[no_mangle]
pub unsafe extern "C" fn recv(fd: c_int, buf: *const c_void, n: size_t, flags: c_int) -> isize {
    let source_addr = get_peer_addr(fd);
    let dest_addr = get_sock_name(fd);
    println!("====recv source: {:?}, destination: {:?})====", source_addr, dest_addr);
    let res = REAL_RECV(fd, buf, n, flags);

    if res <= 0 {
        return res;
    }

    let slice = std::slice::from_raw_parts(buf as *const u8, res as usize);

    let message = Message {
        data: slice.to_vec(),
        source_addr,
        dest_addr
    };
    write_message(message);
    res
}

// send() is a wrapper function that intercepts send() calls and sends them to the
// server.
// fd: the file descriptor of the socket
// buf: the buffer to write to
// n: the number of bytes to write
// flags: the flags to pass to send()
// returns: the number of bytes written, or a negative error code

#[no_mangle]
pub unsafe extern "C" fn send(fd: c_int, buf: *const c_void, n: size_t, flags: c_int) -> isize {
    let source_addr = get_peer_addr(fd);
    let dest_addr = get_sock_name(fd);
    println!("====send source: {:?}, destination: {:?} ====", source_addr, dest_addr);
    let mut total_res: usize = 0;

    while total_res < n {
        let res = REAL_SEND(fd, buf, n, flags);
        if res <= 0 {
            return res;
        }
        total_res += res as usize;
    }

    let slice = std::slice::from_raw_parts(buf as *const u8, n);
    let message = Message {
        data: slice.to_vec(),
        source_addr,
        dest_addr
    };
    write_message(message);
    total_res as isize
}

#[no_mangle]
pub unsafe extern "C" fn sendto(
    fd: c_int,
    buf: *const c_void,
    n: size_t,
    flags: c_int,
    addr: *const libc::sockaddr,
    addr_len: socklen_t,
) -> isize {
    let source_addr = get_peer_addr(fd);
    let dest_addr = get_sock_name(fd);
    println!("====sendto source: {:?}, destination: {:?} ====", source_addr, dest_addr);
    let mut total_res: usize = 0;

    while total_res < n {
        let res = REAL_SENDTO(fd, buf, n, flags, addr, addr_len);
        if res <= 0 {
            return res;
        }
        total_res += res as usize;
    }

    let slice = std::slice::from_raw_parts(buf as *const u8, n);
    let message = Message {
        data: slice.to_vec(),
        source_addr,
        dest_addr
    };
    write_message(message);
    total_res as isize
}

#[no_mangle]
pub unsafe extern "C" fn sendmsg(
    fd: c_int,
    msg: *const libc::msghdr,
    flags: c_int,
) -> isize {
    let source_addr = get_peer_addr(fd);
    let dest_addr = get_sock_name(fd);
    println!("====sendmsg source: {:?}, destination: {:?} ====", source_addr, dest_addr);
    let mut total_res: usize = 0;

    let msg = &*msg;
    let slice = std::slice::from_raw_parts(msg.msg_iov as *const libc::iovec, msg.msg_iovlen);
    let mut data = Vec::new();
    for iovec in slice {
        let slice = std::slice::from_raw_parts(iovec.iov_base as *const u8, iovec.iov_len);
        data.extend_from_slice(slice);
    }

    while total_res < data.len() {
        let res = REAL_SENDMSG(fd, msg, flags);
        if res <= 0 {
            return res;
        }
        total_res += res as usize;
    }

    let message = Message {
        data,
        source_addr,
        dest_addr
    };
    write_message(message);
    total_res as isize
}

#[no_mangle]
pub unsafe extern "C" fn recvfrom(
    fd: c_int,
    buf: *mut c_void,
    n: size_t,
    flags: c_int,
    addr: *mut libc::sockaddr,
    addr_len: *mut socklen_t,
) -> isize {
    let source_addr = get_peer_addr(fd);
    let dest_addr = get_sock_name(fd);
    println!("====recvfrom source: {:?}, destination: {:?} ====", source_addr, dest_addr);
    let res = REAL_RECVFROM(fd, buf, n, flags, addr, addr_len);

    if res <= 0 {
        return res;
    }

    let slice = std::slice::from_raw_parts(buf as *const u8, res as usize);

    let message = Message {
        data: slice.to_vec(),
        source_addr,
        dest_addr
    };
    write_message(message);
    res
}

#[no_mangle]
pub unsafe extern "C" fn recvmsg(
    fd: c_int,
    msg: *mut libc::msghdr,
    flags: c_int,
) -> isize {
    let source_addr = get_peer_addr(fd);
    let dest_addr = get_sock_name(fd);
    println!("====recvmsg source: {:?}, destination: {:?} ====", source_addr, dest_addr);
    let res = REAL_RECVMSG(fd, msg, flags);

    if res <= 0 {
        return res;
    }

    let msg = &*msg;
    let slice = std::slice::from_raw_parts(msg.msg_iov as *const libc::iovec, msg.msg_iovlen);
    let mut data = Vec::new();
    for iovec in slice {
        let slice = std::slice::from_raw_parts(iovec.iov_base as *const u8, iovec.iov_len);
        data.extend_from_slice(slice);
    }

    let message = Message {
        data,
        source_addr,
        dest_addr
    };
    write_message(message);
    res
}