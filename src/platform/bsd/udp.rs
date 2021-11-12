//! BSD UDP Implementation

use super::super::{udp::*, Endpoint};
use nix::{
    errno::Errno,
    sys::socket::{
        bind, cmsghdr, getsockname, msghdr, setsockopt, sockaddr_in, sockaddr_in6, socket,
        sockopt::{Ipv4RecvDstAddr, ReuseAddr, Ipv6V6Only, Ipv6RecvPacketInfo},
        AddressFamily, InetAddr, SockAddr, SockFlag, SockProtocol, SockType,
    },
    unistd::close,
};
use std::{
    mem,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6, IpAddr},
    os::unix::io::RawFd,
    ptr,
    sync::Arc,
};

/// Wrapper around a `RawFd` that closes the `RawFd` when dropped
#[derive(Clone, Debug)]
pub struct Fd(RawFd);

#[derive(Clone, Debug)]
pub struct BsdUdp {
    /// Ipv4 UDP socket
    socket4: Arc<Fd>,

    /// Ipv6 UDP socket
    socket6: Arc<Fd>,

    /// Bound Port
    port: u16
}

#[derive(Clone, Debug)]
pub enum BsdUdpReader {
    V4(BsdUdp),
    V6(BsdUdp),
}

impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 != -1 {
            log::debug!("bsd udp, release fd (fd = {})", self.0);
            if let Err(e) = close(self.0) {
                log::warn!("bsd udp, failed to close fd (fd = {}): {}", self.0, e);
            }
        }
    }
}

#[repr(C, align(1))]
struct ControlHeaderV4 {
    hdr: cmsghdr,
    ip: libc::in_addr,
}

#[repr(C, align(1))]
struct ControlHeaderV6 {
    hdr: cmsghdr,
    ip: libc::in6_addr,
}

pub enum BsdEndpoint {
    V4 {
        dst: sockaddr_in,
        src: libc::in_addr,
    },
    V6 {
        dst: sockaddr_in6,
        src: libc::in6_addr,
    },
}

impl UDP for BsdUdp {
    type Error = Errno;
    type Endpoint = BsdEndpoint;
    type Writer = Self;
    type Reader = BsdUdpReader;
}

impl Endpoint for BsdEndpoint {
    fn from_address(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => Self::V4 {
                dst: sockaddr_in {
                    sin_len: 0,
                    sin_family: libc::AF_INET as u8,
                    sin_port: addr.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(*addr.ip()).to_be(),
                    },
                    sin_zero: [0i8; 8],
                },
                src: libc::in_addr { s_addr: 0 },
            },
            SocketAddr::V6(addr) => Self::V6 {
                dst: sockaddr_in6 {
                    sin6_len: 0,
                    sin6_family: libc::AF_INET6 as u8,
                    sin6_port: addr.port().to_be(),
                    sin6_flowinfo: addr.flowinfo(),
                    sin6_addr: libc::in6_addr {
                        s6_addr: addr.ip().octets(),
                    },
                    sin6_scope_id: addr.scope_id(),
                },
                src: libc::in6_addr { s6_addr: [0u8; 16] },
            },
        }
    }

    fn into_address(&self) -> SocketAddr {
        match self {
            Self::V4 { ref dst, .. } => SocketAddr::V4(SocketAddrV4::new(
                u32::from_be(dst.sin_addr.s_addr).into(),
                u16::from_be(dst.sin_port),
            )),
            Self::V6 { ref dst, .. } => SocketAddr::V6(SocketAddrV6::new(
                u128::from_ne_bytes(dst.sin6_addr.s6_addr).into(),
                u16::from_be(dst.sin6_port),
                dst.sin6_flowinfo,
                dst.sin6_scope_id,
            )),
        }
    }

    fn clear_src(&mut self) {
        match self {
            Self::V4 { ref mut src, .. } => src.s_addr = 0,
            Self::V6 { ref mut src, .. } => src.s6_addr = [0u8; 16],
        }
    }
}

impl BsdUdp {
    fn create(addr: SocketAddr) -> Result<(u16, Arc<Fd>), Errno> {
        log::trace!("attempting to bind udp [port {}]", addr.port());

        let fd = match &addr {
            SocketAddr::V4(_) => {
                let fd = socket(
                    AddressFamily::Inet,
                    SockType::Datagram,
                    SockFlag::empty(),
                    SockProtocol::Udp,
                )?;

                // Set Socket Options
                // * allow binding an ip addr even if it's already in use
                // * append ipv4 destination information to calls via sendmsg/recvmsg
                setsockopt(fd, ReuseAddr, &true)?;
                setsockopt(fd, Ipv4RecvDstAddr, &true)?;

                fd
            }
            SocketAddr::V6(_) => {
                let fd = socket(
                    AddressFamily::Inet6,
                    SockType::Datagram,
                    SockFlag::empty(),
                    SockProtocol::Udp,
                )?;

                // Set Socket Options
                // * allow binding an ip addr even if it's already in use
                // * append ipv4 destination information to calls via sendmsg/recvmsg
                setsockopt(fd, ReuseAddr, &true)?;
                setsockopt(fd, Ipv6RecvPacketInfo, &true)?;
                setsockopt(fd, Ipv6V6Only, &true)?;

                fd
            }
        };

        log::trace!("udp bind socket created [fd = {}]", fd);

        // bind the port
        let sockaddr = SockAddr::Inet(InetAddr::from_std(&addr));
        bind(fd, &sockaddr)?;

        log::trace!("bound udp socket [port {}, fd = {}]", addr.port(), fd);

        // verify assigned port is the same
        let port = match getsockname(fd)? {
            SockAddr::Inet(inet) => match inet {
                InetAddr::V4(addr) => u16::from_be(addr.sin_port),
                InetAddr::V6(addr) => u16::from_be(addr.sin6_port),
            },
            SockAddr::Unix(_) => unreachable!("somehow got unix socket from inet fd"),
            SockAddr::Link(_) => unreachable!("somehow got hardware address from inet fd"),
            _ => unreachable!("unknown other socket variant"),
        };

        log::trace!("udp confirmed socket [port = {}, fd = {}]", port, fd);

        Ok((port, Arc::new(Fd(fd))))
    }

    fn read4(&self, buf: &mut [u8]) -> Result<(usize, BsdEndpoint), Errno> {
        log::trace!(
            "received IPv4 packet (block) [fd = {}, max_len = {}]",
            self.socket4.0,
            buf.len()
        );
        debug_assert!(!buf.is_empty(), "reading into empty buffer (will fail)");

        let mut iovs: [libc::iovec; 1] = [libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        }];
        let mut src = mem::MaybeUninit::<sockaddr_in>::zeroed();
        let mut ctrl = mem::MaybeUninit::<ControlHeaderV4>::zeroed();
        let mut hdr = msghdr {
            msg_name: src.as_mut_ptr() as *mut libc::c_void,
            msg_namelen: mem::size_of_val(&src) as u32,
            msg_iov: iovs.as_mut_ptr(),
            msg_iovlen: iovs.len() as i32,
            msg_control: ctrl.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: mem::size_of_val(&ctrl) as u32,
            msg_flags: 0,
        };

        /*
        debug_assert!(
            hdr.msg_controllen >= mem::size_of::<libc::cmsghdr>() + mem::size_of::<libc::in_addr>()
        );
        */

        // SAFETY: ensure msghdr struct is properly constructed and fd is a valid file descriptor
        let len = Errno::result(unsafe { libc::recvmsg(self.socket4.0, &mut hdr as *mut libc::msghdr, 0) })?;

        // SAFETY: the recvmsg call succeeded, we can assume both src and ctrl
        // have been properly initialized;
        let src = unsafe { src.assume_init() };
        let ctrl = unsafe { ctrl.assume_init() };

        log::debug!("[udp rd] src ip: {:?}", ctrl.ip);
        log::debug!("[udp rd] dst ip: {:?}", src);

        Ok((
            len.try_into().expect("failed to convert i32 to usize"),
            BsdEndpoint::V4 {
                dst: src,     // future destination is the current source address
                src: ctrl.ip, // ip of interface this packet came in on
            },
        ))
    }
}

impl Reader<BsdEndpoint> for BsdUdpReader {
    type Error = Errno;

    fn read(&self, buf: &mut [u8]) -> Result<(usize, BsdEndpoint), Self::Error> {
        match self {
            Self::V4(sock) => sock.read4(buf),
            Self::V6(_) => todo!(),
        }
    }
}

impl Writer<BsdEndpoint> for BsdUdp {
    type Error = Errno;

    fn write(&self, buf: &[u8], dst: &mut BsdEndpoint) -> Result<(), Self::Error> {
        match dst {
            BsdEndpoint::V4 {
                ref mut dst,
                ref mut src,
            } => {
                log::trace!(
                    "sending IPv4 packet (block) [fd = {}, len = {}]",
                    self.socket4.0,
                    buf.len()
                );

                log::debug!("[udp wr] src ip: {:?}", src);
                log::debug!("[udp wr] dst ip: {:?}", dst);

                let mut iovs = [libc::iovec {
                    iov_base: buf.as_ptr() as *mut libc::c_void,
                    iov_len: buf.len(),
                }];

                // SAFETY: verify call to CMSG_LEN is good
                let cmsg_len = unsafe { libc::CMSG_LEN(mem::size_of::<libc::in_addr>() as u32) };
                let mut control = ControlHeaderV4 {
                    hdr: cmsghdr {
                        cmsg_len,
                        cmsg_level: libc::IPPROTO_IP,
                        cmsg_type: libc::IP_RECVDSTADDR,
                    },
                    ip: *src,
                };

                // TODO verify control hdr len is aligned to a long

                let mut hdr = msghdr {
                    msg_name: (dst as *mut sockaddr_in) as *mut libc::c_void,
                    msg_namelen: mem::size_of_val(dst) as u32,
                    msg_iov: iovs.as_mut_ptr(),
                    msg_iovlen: iovs.len() as i32,
                    msg_control: (&mut control as *mut ControlHeaderV4) as *mut libc::c_void,
                    msg_controllen: mem::size_of_val(&control) as u32,
                    msg_flags: 0,
                };

                // SAFETY: Fd is valid (>1) and hdr is properly constructed
                let ret = unsafe { libc::sendmsg(self.socket4.0, &hdr, 0) };
                match Errno::result(ret) {
                    Ok(_) => Ok(()),
                    Err(Errno::EINVAL) => {
                        log::debug!("[udp wr] clear source and retry");
                        hdr.msg_control = ptr::null_mut();
                        hdr.msg_controllen = 0;
                        src.s_addr = 0;

                        // SAFETY: same as previous call, now with null control
                        Errno::result(unsafe { libc::sendmsg(self.socket4.0, &hdr, 0) })?;
                        Ok(())
                    }
                    Err(e) => {
                        log::warn!("failed to send ipv4 packet");
                        Err(e)
                    }
                }
            }
            BsdEndpoint::V6 {
                ref mut dst,
                ref mut src,
            } => {
                todo!("ipv6 not supported yet");
            }
        }
    }
}

impl Owner for BsdUdp {
    type Error = Errno;

    fn get_port(&self) -> u16 {
        self.port
    }

    fn set_fwmark(&mut self, value: Option<u32>) -> Result<(), Self::Error> {
        // not supported on BSD
        Err(Errno::EDOOFUS)
    }
}

impl PlatformUDP for BsdUdp {
    type Owner = Self;

    fn bind(mut port: u16) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Owner), Self::Error> {
        let (port4, udp4) = Self::create((IpAddr::from([0u8; 4]), port).into())?;
        let (port6, udp6) = Self::create((IpAddr::from([0u8; 16]), port).into())?;
        if port4 != port6 {
            // ports need to be the same?
            // TODO see if ports can be different
            //return Err(Errno::EADDRINUSE);
            log::warn!("bound different ports [v4: {}, v6: {}]", port4, port6);
        }
        port = port4;

        let owner = BsdUdp {
            socket4: udp4,
            socket6: udp6,
            port: port4
        };

        let mut readers: Vec<Self::Reader> = Vec::with_capacity(2);
        readers.push(BsdUdpReader::V4(owner.clone()));
        //readers.push(BsdUdpReader::V6(owner.clone()));

        Ok((readers, owner.clone(), owner))
    }
}
