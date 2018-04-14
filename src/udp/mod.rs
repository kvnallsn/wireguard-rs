#![allow(unused)]

use std::{fmt, io, mem};
use std::net::{self, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;

use futures::{Async, Future, Poll};
use libc;
use mio;
use nix::{self, errno::Errno};
use nix::sys::{uio::IoVec, socket::{CmsgSpace, ControlMessage, UnknownCmsg, MsgFlags, SockAddr, recvmsg}};
use socket2::{Socket, Domain, Type, Protocol};

use tokio_core::reactor::{Handle, PollEvented};

/// An I/O object representing a UDP socket.
pub struct UdpSocket {
    io: PollEvented<mio::net::UdpSocket>,
    handle: Handle,
}

/// IPV6_RECVPKTINFO is missing from the libc crate. Value taken from https://git.io/vxNel.
pub const IPV6_RECVPKTINFO : i32 = 61;
pub const IP_PKTINFO       : i32 = 26;
pub const IP_RECVDSTADDR   : i32 = 7;

#[repr(C)]
struct in6_pktinfo {
    ipi6_addr    : libc::in6_addr,
    ipi6_ifindex : libc::c_uint
}

#[repr(C)]
struct in_pktinfo {
    ipi_ifindex  : libc::c_uint,
    ipi_spec_dst : libc::in_addr,
    ipi_addr     : libc::in_addr,
}

mod frame;
pub use self::frame::{UdpChannel, UdpFramed, VecUdpCodec, PeerServerMessage};

impl UdpSocket {
    /// Create a new UDP socket bound to the specified address.
    ///
    /// This function will create a new UDP socket and attempt to bind it to the
    /// `addr` provided. If the result is `Ok`, the socket has successfully bound.
    pub fn bind(addr: SocketAddr, handle: Handle) -> io::Result<UdpSocket> {
        let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;

        let off: libc::c_int = 0;
        let on: libc::c_int = 1;
//        unsafe {
//            let ret = libc::setsockopt(socket.as_raw_fd(),
//                                       libc::IPPROTO_IP,
//                                       3,
//                                       &off as *const _ as *const libc::c_void,
//                                       mem::size_of_val(&off) as libc::socklen_t);
//            if ret != 0 {
//                let err: Result<(), _> = Err(io::Error::last_os_error());
//                err.expect("setsockopt failed");
//            }
//            debug!("set IP_PKTINFO");
//        }

        unsafe {
            let ret = libc::setsockopt(socket.as_raw_fd(),
                                       libc::IPPROTO_IPV6,
                                       IPV6_RECVPKTINFO,
                                       &on as *const _ as *const libc::c_void,
                                       mem::size_of_val(&on) as libc::socklen_t);
            if ret != 0 {
                let err: Result<(), _> = Err(io::Error::last_os_error());
                err.expect("setsockopt failed");
            }

            debug!("set IPV6_PKTINFO");
        }

        socket.set_only_v6(false)?;
        socket.set_nonblocking(true)?;
        socket.set_reuse_port(true)?;
        socket.set_reuse_address(true)?;

        socket.bind(&addr.into())?;
        Self::from_socket(socket.into_udp_socket(), handle)
    }

    fn new(socket: mio::net::UdpSocket, handle: Handle) -> io::Result<UdpSocket> {
        let io = PollEvented::new(socket, &handle)?;
        Ok(UdpSocket { io, handle })
    }

    /// Creates a new `UdpSocket` from the previously bound socket provided.
    ///
    /// The socket given will be registered with the event loop that `handle` is
    /// associated with. This function requires that `socket` has previously
    /// been bound to an address to work correctly.
    ///
    /// This can be used in conjunction with net2's `UdpBuilder` interface to
    /// configure a socket before it's handed off, such as setting options like
    /// `reuse_address` or binding to multiple addresses.
    pub fn from_socket(socket: net::UdpSocket, handle: Handle) -> io::Result<UdpSocket> {
        let udp = mio::net::UdpSocket::from_socket(socket)?;
        UdpSocket::new(udp, handle)
    }

    /// Provides a `Stream` and `Sink` interface for reading and writing to this
    /// `UdpSocket` object, using the provided `UdpCodec` to read and write the
    /// raw data.
    ///
    /// Raw UDP sockets work with datagrams, but higher-level code usually
    /// wants to batch these into meaningful chunks, called "frames". This
    /// method layers framing on top of this socket by using the `UdpCodec`
    /// trait to handle encoding and decoding of messages frames. Note that
    /// the incoming and outgoing frame types may be distinct.
    ///
    /// This function returns a *single* object that is both `Stream` and
    /// `Sink`; grouping this into a single object is often useful for layering
    /// things which require both read and write access to the underlying
    /// object.
    ///
    /// If you want to work more directly with the streams and sink, consider
    /// calling `split` on the `UdpFramed` returned by this method, which will
    /// break them into separate objects, allowing them to interact more
    /// easily.
    pub fn framed(self) -> UdpFramed {
        frame::new(self)
    }

    /// Returns the local address that this stream is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.get_ref().local_addr()
    }

    /// Sends data on the socket to the address previously bound via connect().
    /// On success, returns the number of bytes written.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        if let Async::NotReady = self.io.poll_write() {
            return Err(io::ErrorKind::WouldBlock.into())
        }
        match self.io.get_ref().send(buf) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.io.need_write();
                }
                Err(e)
            }
        }
    }

    /// Receives data from the socket previously bound with connect().
    /// On success, returns the number of bytes read.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if let Async::NotReady = self.io.poll_read() {
            return Err(io::ErrorKind::WouldBlock.into())
        }
        let mut cmsgs = CmsgSpace::<in6_pktinfo>::new();
        let res = recvmsg(self.io.get_ref().as_raw_fd(),
                          &[IoVec::from_mut_slice(buf)],
                          Some(&mut cmsgs),
                          MsgFlags::empty());

        match res {
            Ok(msg) => {
                debug!("address: {:?}", msg.address);
                Ok(msg.bytes)
            },
            Err(nix::Error::Sys(Errno::EAGAIN)) => {
                debug!("EAGAIN");
                self.io.need_read();
                Err(io::ErrorKind::WouldBlock.into())
            },
            Err(nix::Error::Sys(errno)) => {
                Err(io::Error::last_os_error())
            },
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }

    /// Test whether this socket is ready to be read or not.
    ///
    /// If the socket is *not* readable then the current task is scheduled to
    /// get a notification when the socket does become readable. That is, this
    /// is only suitable for calling in a `Future::poll` method and will
    /// automatically handle ensuring a retry once the socket is readable again.
    pub fn poll_read(&self) -> Async<()> {
        self.io.poll_read()
    }

    /// Test whether this socket is ready to be written to or not.
    ///
    /// If the socket is *not* writable then the current task is scheduled to
    /// get a notification when the socket does become writable. That is, this
    /// is only suitable for calling in a `Future::poll` method and will
    /// automatically handle ensuring a retry once the socket is writable again.
    pub fn poll_write(&self) -> Async<()> {
        self.io.poll_write()
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    ///
    /// Address type can be any implementer of `ToSocketAddrs` trait. See its
    /// documentation for concrete examples.
    pub fn send_to(&self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        if let Async::NotReady = self.io.poll_write() {
            return Err(io::ErrorKind::WouldBlock.into())
        }
        match self.io.get_ref().send_to(buf, target) {
            Ok(n) => Ok(n),
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.io.need_write();
                }
                Err(e)
            }
        }
    }

    /// Receives data from the socket. On success, returns the number of bytes
    /// read and the address from whence the data came.
    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if let Async::NotReady = self.io.poll_read() {
            return Err(io::ErrorKind::WouldBlock.into())
        }
        if let Async::NotReady = self.io.poll_read() {
            return Err(io::ErrorKind::WouldBlock.into())
        }
        let mut cmsgs = CmsgSpace::<[u8; 1024]>::new();
        let res = recvmsg(self.io.get_ref().as_raw_fd(),
                          &[IoVec::from_mut_slice(buf)],
                          Some(&mut cmsgs),
                          MsgFlags::empty());

        match res {
            Ok(msg) => {
                for cmsg in msg.cmsgs() {
                    match cmsg {
                        ControlMessage::Unknown(_) => {
                            debug!("unknown cmsg");
                        }
                        _ => debug!("known cmsg")
                    }
                }
                if let Some(SockAddr::Inet(addr)) = msg.address {
                    Ok((msg.bytes, addr.to_std()))
                } else {
                    Err(io::Error::new(io::ErrorKind::Other, "invalid source address"))
                }
            },
            Err(nix::Error::Sys(Errno::EAGAIN)) => {
                self.io.need_read();
                Err(io::ErrorKind::WouldBlock.into())
            },
            Err(nix::Error::Sys(errno)) => {
                Err(io::Error::last_os_error())
            },
            Err(e) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}

impl fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.io.get_ref().fmt(f)
    }
}

#[cfg(all(unix, not(target_os = "fuchsia")))]
mod sys {
    use std::os::unix::prelude::*;
    use super::UdpSocket;

    impl AsRawFd for UdpSocket {
        fn as_raw_fd(&self) -> RawFd {
            self.io.get_ref().as_raw_fd()
        }
    }
}

#[cfg(windows)]
mod sys {
    // TODO: let's land these upstream with mio and then we can add them here.
    //
    // use std::os::windows::prelude::*;
    // use super::UdpSocket;
    //
    // impl AsRawHandle for UdpSocket {
    //     fn as_raw_handle(&self) -> RawHandle {
    //         self.io.get_ref().as_raw_handle()
    //     }
    // }
}