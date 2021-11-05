//! Platform-Agnostic tunnel

use super::super::tun::*;
use std::{error::Error, fmt, io, sync::Arc};
use tun_rs::{OsTun, Tun as _};

pub struct UnixTun(Arc<OsTun>);

#[derive(Debug)]
pub enum UnixTunError {
    Tun(tun_rs::TunError),
    IO(io::Error),
    Closed,
}

impl Tun for OsTun {
    type Writer = UnixTun;
    type Reader = UnixTun;
    type Error = UnixTunError;
}
impl fmt::Display for UnixTunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnixTunError::Tun(e) => write!(f, "Tunnel error: {}", e),
            UnixTunError::IO(e) => write!(f, "Tunnel i/o error: {}", e),
            UnixTunError::Closed => write!(f, "Tunnel device closed"),
        }
    }
}

impl Error for UnixTunError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        unimplemented!()
    }

    fn description(&self) -> &str {
        unimplemented!()
    }
}

impl Reader for UnixTun {
    type Error = UnixTunError;

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        self.0
            .read_packet(&mut buf[offset..])
            .map_err(|e| UnixTunError::Tun(e))?;
        Ok(0)
        /*
        use libc::{iovec, msghdr, recvmsg};
        use std::ptr::null_mut;
        let mut _hdr = [0u8; 4];
        let mut iov = [
            // mac has a 4-byte etherent header that we'll need to read first
            #[cfg(target_os = "macos")]
            iovec {
                iov_base: _hdr.as_mut_ptr() as _,
                iov_len: _hdr.len(),
            },
            // all OSes use this buffer
            iovec {
                iov_base: buf[offset..].as_mut_ptr() as _,
                iov_len: buf.len() - offset,
            },
        ];

        let mut msg_hdr = msghdr {
            msg_name: null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov[0],
            msg_iovlen: iov.len() as _,
            msg_control: null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        match unsafe { recvmsg(self.fd, &mut msg_hdr, 0) } {
            -1 => Err(UnixTunError::Closed),
            0..=4 => Ok(0),
            n => Ok((n - 4) as usize),
        }
        */
    }
}

impl Writer for UnixTun {
    type Error = UnixTunError;

    fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        self.0
            .write_packet(src, 0x02)
            .map_err(|e| UnixTunError::IO(e))?;
        Ok(())
        /*
        use libc::{iovec, msghdr, sendmsg};
        use std::ptr::null_mut;
        let _hdr = [0u8, 0u8, 0u8, 2u8];

        let mut iov = [
            // mac requires the 4 byte ethernet header to be written as well
            #[cfg(target_os = "macos")]
            iovec {
                iov_base: _hdr.as_ptr() as _,
                iov_len: _hdr.len(),
            },
            // all OSes use this buffer
            iovec {
                iov_base: src.as_ptr() as _,
                iov_len: src.len(),
            },
        ];

        let msg_hdr = msghdr {
            msg_name: null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov[0],
            msg_iovlen: iov.len() as _,
            msg_control: null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        match unsafe { sendmsg(self.fd, &msg_hdr, 0) } {
            -1 => Err(UnixTunError::Closed),
            _ => Ok(()),
        }
        */
    }
}
