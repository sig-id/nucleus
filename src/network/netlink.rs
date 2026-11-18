//! Native netlink operations replacing external `ip` command usage.
//!
//! Uses raw `NETLINK_ROUTE` sockets to configure links, addresses, and routes
//! without requiring iproute2 on the host.

use crate::error::{NucleusError, Result};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

// ── Netlink constants (stable kernel ABI) ────────────────────────────

// nlmsghdr special message types
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// nlmsghdr flags
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLM_F_ROOT: u16 = 0x100;
const NLM_F_MATCH: u16 = 0x200;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;
// Modifiers for NEW requests (same bit positions, different semantics)
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

// rtnetlink message types
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWROUTE: u16 = 24;

// IFLA_* (link attributes)
const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_FD: u16 = 28;

// IFLA_INFO_* (nested under IFLA_LINKINFO)
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;

// VETH_INFO_* (nested under IFLA_INFO_DATA for veth)
const VETH_INFO_PEER: u16 = 1;

// IFA_* (address attributes)
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

// RTA_* (route attributes)
const RTA_GATEWAY: u16 = 5;

// Route constants
const RTN_UNICAST: u8 = 1;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;

// Nested attribute flag
const NLA_F_NESTED: u16 = 0x8000;

// Interface flags
const IFF_UP: u32 = libc::IFF_UP as u32;

// Struct sizes
const NLMSGHDR_LEN: usize = 16;
const IFINFOMSG_LEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTMSG_LEN: usize = 12;
const NLA_HDR_LEN: usize = 4;

fn align4(len: usize) -> usize {
    (len + 3) & !3
}

// ── Netlink message builder ──────────────────────────────────────────

struct NlMsg {
    buf: Vec<u8>,
}

impl NlMsg {
    fn new(msg_type: u16, flags: u16) -> Self {
        let mut buf = vec![0u8; NLMSGHDR_LEN];
        // nlmsg_len: placeholder (fixed in as_bytes)
        // nlmsg_type
        buf[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        // nlmsg_flags
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        // nlmsg_seq: set by NlSocket
        // nlmsg_pid: 0 (kernel fills)
        Self { buf }
    }

    fn set_seq(&mut self, seq: u32) {
        self.buf[8..12].copy_from_slice(&seq.to_ne_bytes());
    }

    fn pad(&mut self) {
        self.buf.resize(align4(self.buf.len()), 0);
    }

    fn put_ifinfomsg(&mut self, family: u8, index: i32, flags: u32, change: u32) {
        let mut d = [0u8; IFINFOMSG_LEN];
        d[0] = family;
        d[4..8].copy_from_slice(&index.to_ne_bytes());
        d[8..12].copy_from_slice(&flags.to_ne_bytes());
        d[12..16].copy_from_slice(&change.to_ne_bytes());
        self.buf.extend_from_slice(&d);
    }

    fn put_ifaddrmsg(&mut self, family: u8, prefix: u8, index: u32) {
        let mut d = [0u8; IFADDRMSG_LEN];
        d[0] = family;
        d[1] = prefix;
        d[4..8].copy_from_slice(&index.to_ne_bytes());
        self.buf.extend_from_slice(&d);
    }

    fn put_rtmsg(
        &mut self,
        family: u8,
        dst_len: u8,
        table: u8,
        protocol: u8,
        scope: u8,
        rt_type: u8,
    ) {
        let mut d = [0u8; RTMSG_LEN];
        d[0] = family;
        d[1] = dst_len;
        d[4] = table;
        d[5] = protocol;
        d[6] = scope;
        d[7] = rt_type;
        self.buf.extend_from_slice(&d);
    }

    fn put_attr(&mut self, attr_type: u16, data: &[u8]) {
        let nla_len = (NLA_HDR_LEN + data.len()) as u16;
        self.buf.extend_from_slice(&nla_len.to_ne_bytes());
        self.buf.extend_from_slice(&attr_type.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.pad();
    }

    fn put_attr_str(&mut self, attr_type: u16, s: &str) {
        let mut data = s.as_bytes().to_vec();
        data.push(0); // NUL-terminate
        self.put_attr(attr_type, &data);
    }

    fn put_attr_u32(&mut self, attr_type: u16, val: u32) {
        self.put_attr(attr_type, &val.to_ne_bytes());
    }

    /// Begin a nested attribute. Returns the offset for `end_nested`.
    fn begin_nested(&mut self, attr_type: u16) -> usize {
        let offset = self.buf.len();
        self.buf.extend_from_slice(&0u16.to_ne_bytes()); // placeholder len
        self.buf
            .extend_from_slice(&(attr_type | NLA_F_NESTED).to_ne_bytes());
        offset
    }

    /// Fix up the length of a nested attribute started at `offset`.
    fn end_nested(&mut self, offset: usize) {
        let nla_len = (self.buf.len() - offset) as u16;
        self.buf[offset..offset + 2].copy_from_slice(&nla_len.to_ne_bytes());
    }

    /// Finalize the message buffer, writing the total length into nlmsghdr.
    fn as_bytes(&mut self) -> &[u8] {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        &self.buf
    }
}

// ── Netlink socket ───────────────────────────────────────────────────

struct NlSocket {
    fd: OwnedFd,
    seq: u32,
}

impl NlSocket {
    fn open() -> Result<Self> {
        // SAFETY: socket() returns a new fd or -1; we check and wrap in OwnedFd.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if raw < 0 {
            return Err(NucleusError::NetworkError(format!(
                "netlink socket: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: raw is a valid, newly-created fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: addr is a valid, zeroed sockaddr_nl with nl_family set.
        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            return Err(NucleusError::NetworkError(format!(
                "netlink bind: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self { fd, seq: 1 })
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        s
    }

    fn send_raw(&self, buf: &[u8]) -> Result<()> {
        // SAFETY: fd is a valid netlink socket, buf is a valid byte slice.
        let ret = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                libc::MSG_TRUNC,
            )
        };
        if ret < 0 {
            return Err(NucleusError::NetworkError(format!(
                "netlink send: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Send a request and wait for the kernel ACK.
    fn request(&mut self, msg: &mut NlMsg) -> Result<()> {
        let seq = self.next_seq();
        msg.set_seq(seq);
        self.send_raw(msg.as_bytes())?;
        self.recv_ack(seq)
    }

    /// Receive until we get an ACK (NLMSG_ERROR with code 0) or an error.
    fn recv_ack(&self, expected_seq: u32) -> Result<()> {
        let mut buf = [0u8; 4096];
        loop {
            let n = self.recv_into(&mut buf)?;
            let mut off = 0;
            while off + NLMSGHDR_LEN <= n {
                let (msg_len, msg_type, seq) = parse_nlmsghdr(&buf[off..]);
                if msg_len < NLMSGHDR_LEN || off + msg_len > n {
                    break;
                }
                if seq == expected_seq && msg_type == NLMSG_ERROR {
                    return check_nl_error(&buf[off..off + msg_len]);
                }
                off += align4(msg_len);
            }
        }
    }

    /// Send a dump request and collect all response payloads.
    fn dump(&mut self, msg: &mut NlMsg) -> Result<Vec<Vec<u8>>> {
        let seq = self.next_seq();
        msg.set_seq(seq);
        self.send_raw(msg.as_bytes())?;

        let mut result = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            let n = self.recv_into(&mut buf)?;
            let mut off = 0;
            while off + NLMSGHDR_LEN <= n {
                let (msg_len, msg_type, response_seq) = parse_nlmsghdr(&buf[off..]);
                let flags = u16::from_ne_bytes([buf[off + 6], buf[off + 7]]);
                if msg_len < NLMSGHDR_LEN
                    || off + msg_len > n
                    || response_seq != seq
                    || flags & NLM_F_DUMP_INTR != 0
                {
                    return Err(NucleusError::NetworkError(
                        "Incomplete netlink address dump".into(),
                    ));
                }
                match msg_type {
                    NLMSG_DONE => return Ok(result),
                    NLMSG_ERROR => {
                        check_nl_error(&buf[off..off + msg_len])?;
                    }
                    _ => {
                        result.push(buf[off..off + msg_len].to_vec());
                    }
                }
                off += align4(msg_len);
            }
        }
    }

    fn recv_into(&self, buf: &mut [u8]) -> Result<usize> {
        // SAFETY: fd is a valid netlink socket, buf is a valid mutable slice.
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_TRUNC,
            )
        };
        if n < 0 {
            return Err(NucleusError::NetworkError(format!(
                "netlink recv: {}",
                std::io::Error::last_os_error()
            )));
        }
        if n as usize > buf.len() {
            return Err(NucleusError::NetworkError(
                "Truncated netlink datagram".into(),
            ));
        }
        Ok(n as usize)
    }
}

/// Parse the first three fields of an nlmsghdr.
fn parse_nlmsghdr(buf: &[u8]) -> (usize, u16, u32) {
    let len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let msg_type = u16::from_ne_bytes([buf[4], buf[5]]);
    let seq = u32::from_ne_bytes([buf[8], buf[9], buf[10], buf[11]]);
    (len, msg_type, seq)
}

/// Check an NLMSG_ERROR payload: error code 0 is ACK (success).
fn check_nl_error(msg: &[u8]) -> Result<()> {
    if msg.len() < NLMSGHDR_LEN + 4 {
        return Err(NucleusError::NetworkError(
            "truncated netlink error".to_string(),
        ));
    }
    let errcode = i32::from_ne_bytes([
        msg[NLMSGHDR_LEN],
        msg[NLMSGHDR_LEN + 1],
        msg[NLMSGHDR_LEN + 2],
        msg[NLMSGHDR_LEN + 3],
    ]);
    if errcode == 0 {
        Ok(())
    } else {
        Err(NucleusError::NetworkError(format!(
            "{}",
            std::io::Error::from_raw_os_error(-errcode)
        )))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Resolve an interface name to its index.
fn ifindex(name: &str) -> Result<u32> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| NucleusError::NetworkError(format!("invalid interface name: {}", name)))?;
    // SAFETY: c_name is a valid NUL-terminated C string.
    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        return Err(NucleusError::NetworkError(format!(
            "interface '{}' not found",
            name
        )));
    }
    Ok(idx)
}

// ── Public API ───────────────────────────────────────────────────────

/// Check whether a network interface exists.
pub fn link_exists(name: &str) -> bool {
    let Ok(c_name) = std::ffi::CString::new(name) else {
        return false;
    };
    // SAFETY: c_name is a valid NUL-terminated C string.
    unsafe { libc::if_nametoindex(c_name.as_ptr()) != 0 }
}

/// Create a Linux bridge interface.
pub fn create_bridge(name: &str) -> Result<()> {
    let mut sock = NlSocket::open()?;
    let mut msg = NlMsg::new(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.put_ifinfomsg(0, 0, 0, 0);
    msg.put_attr_str(IFLA_IFNAME, name);
    let li = msg.begin_nested(IFLA_LINKINFO);
    msg.put_attr_str(IFLA_INFO_KIND, "bridge");
    msg.end_nested(li);
    sock.request(&mut msg)
        .map_err(|e| NucleusError::NetworkError(format!("create bridge '{}': {}", name, e)))
}

/// Create a veth pair.
pub fn create_veth(host_name: &str, peer_name: &str) -> Result<()> {
    let mut sock = NlSocket::open()?;
    let mut msg = NlMsg::new(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.put_ifinfomsg(0, 0, 0, 0);
    msg.put_attr_str(IFLA_IFNAME, host_name);

    let li = msg.begin_nested(IFLA_LINKINFO);
    msg.put_attr_str(IFLA_INFO_KIND, "veth");
    let data = msg.begin_nested(IFLA_INFO_DATA);
    let peer = msg.begin_nested(VETH_INFO_PEER);
    msg.put_ifinfomsg(0, 0, 0, 0); // peer ifinfomsg
    msg.put_attr_str(IFLA_IFNAME, peer_name);
    msg.end_nested(peer);
    msg.end_nested(data);
    msg.end_nested(li);

    sock.request(&mut msg).map_err(|e| {
        NucleusError::NetworkError(format!(
            "create veth pair ({}, {}): {}",
            host_name, peer_name, e
        ))
    })
}

pub fn rename_link(from: &str, to: &str) -> Result<()> {
    let mut sock = NlSocket::open()?;
    let mut msg = NlMsg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
    msg.put_ifinfomsg(0, ifindex(from)? as i32, 0, 0);
    msg.put_attr_str(IFLA_IFNAME, to);
    sock.request(&mut msg)
}

/// Attach a link to a bridge (set master).
pub fn set_link_master(link: &str, master: &str) -> Result<()> {
    let link_idx = ifindex(link)?;
    let master_idx = ifindex(master)?;
    let mut sock = NlSocket::open()?;
    let mut msg = NlMsg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
    msg.put_ifinfomsg(0, link_idx as i32, 0, 0);
    msg.put_attr_u32(IFLA_MASTER, master_idx);
    sock.request(&mut msg).map_err(|e| {
        NucleusError::NetworkError(format!("set master {} -> {}: {}", link, master, e))
    })
}

/// Bring a link up.
pub fn set_link_up(name: &str) -> Result<()> {
    let idx = ifindex(name)?;
    let mut sock = NlSocket::open()?;
    let mut msg = NlMsg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
    msg.put_ifinfomsg(0, idx as i32, IFF_UP, IFF_UP);
    sock.request(&mut msg)
        .map_err(|e| NucleusError::NetworkError(format!("set link up '{}': {}", name, e)))
}

/// Move a link into another network namespace (by pinned namespace fd).
pub fn set_link_netns(name: &str, ns: &std::fs::File) -> Result<()> {
    let idx = ifindex(name)?;
    let mut sock = NlSocket::open()?;
    let mut msg = NlMsg::new(RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK);
    msg.put_ifinfomsg(0, idx as i32, 0, 0);
    msg.put_attr_u32(IFLA_NET_NS_FD, std::os::fd::AsRawFd::as_raw_fd(ns) as u32);
    sock.request(&mut msg)
        .map_err(|e| NucleusError::NetworkError(format!("move link {name} into pinned netns: {e}")))
}

/// Add an IPv4 address to a link.
pub fn add_addr(link: &str, addr: Ipv4Addr, prefix: u8) -> Result<()> {
    let idx = ifindex(link)?;
    let mut sock = NlSocket::open()?;
    let mut msg = NlMsg::new(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.put_ifaddrmsg(libc::AF_INET as u8, prefix, idx);
    let octets = addr.octets();
    msg.put_attr(IFA_LOCAL, &octets);
    msg.put_attr(IFA_ADDRESS, &octets);
    sock.request(&mut msg).map_err(|e| {
        NucleusError::NetworkError(format!("add addr {}/{} to '{}': {}", addr, prefix, link, e))
    })
}

/// Add a default route via a gateway (dst 0.0.0.0/0).
pub fn add_default_route(gateway: Ipv4Addr) -> Result<()> {
    let mut sock = NlSocket::open()?;
    let mut msg = NlMsg::new(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
    );
    msg.put_rtmsg(
        libc::AF_INET as u8,
        0, // dst_len = 0 → default route
        RT_TABLE_MAIN,
        RTPROT_BOOT,
        RT_SCOPE_UNIVERSE,
        RTN_UNICAST,
    );
    msg.put_attr(RTA_GATEWAY, &gateway.octets());
    sock.request(&mut msg).map_err(|e| {
        NucleusError::NetworkError(format!("add default route via {}: {}", gateway, e))
    })
}

/// Delete a link by name. Returns `Ok(())` if the link does not exist.
pub fn del_link(name: &str) -> Result<()> {
    let idx = match ifindex(name) {
        Ok(i) => i,
        Err(_) => return Ok(()), // already gone
    };
    let mut sock = NlSocket::open()?;
    let mut msg = NlMsg::new(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK);
    msg.put_ifinfomsg(0, idx as i32, 0, 0);
    sock.request(&mut msg)
        .map_err(|e| NucleusError::NetworkError(format!("del link '{}': {}", name, e)))
}

/// Check whether an IPv4 address is assigned to any interface in this netns.
pub fn is_addr_in_use(ip: &Ipv4Addr) -> Result<bool> {
    has_address(ip, None)
}

pub fn has_address(ip: &Ipv4Addr, interface: Option<(&str, u8)>) -> Result<bool> {
    let expected = interface
        .map(|(name, prefix)| Ok::<_, NucleusError>((ifindex(name)?, prefix)))
        .transpose()?;
    let mut sock = NlSocket::open()?;
    let mut msg = NlMsg::new(RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP);
    msg.put_ifaddrmsg(libc::AF_INET as u8, 0, 0);
    let msgs = sock.dump(&mut msg)?;

    let target = ip.octets();
    for m in &msgs {
        if m.len() < NLMSGHDR_LEN + IFADDRMSG_LEN {
            continue;
        }
        if let Some((idx, prefix)) = expected {
            let hdr = &m[NLMSGHDR_LEN..];
            if hdr[1] != prefix || u32::from_ne_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) != idx {
                continue;
            }
        }
        let mut off = NLMSGHDR_LEN + IFADDRMSG_LEN;
        while off + NLA_HDR_LEN <= m.len() {
            let nla_len = u16::from_ne_bytes([m[off], m[off + 1]]) as usize;
            let nla_type = u16::from_ne_bytes([m[off + 2], m[off + 3]]);
            if nla_len < NLA_HDR_LEN || off + nla_len > m.len() {
                break;
            }
            if nla_type == IFA_LOCAL
                && nla_len >= NLA_HDR_LEN + 4
                && m[off + NLA_HDR_LEN..off + NLA_HDR_LEN + 4] == target
            {
                return Ok(true);
            }
            off += align4(nla_len);
        }
    }
    Ok(false)
}
