//! Platform-Agnostic tunnel

use super::super::tun::*;
use std::{
    error::Error,
    fmt,
    net::Ipv4Addr,
    os::unix::io::{AsRawFd, RawFd},
};
use tun::platform::Device;

pub struct UnixTun {
    device: Device,
}

#[derive(Debug, Default)]
pub struct UnixTunBuilder {
    ip: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    mtu: Option<i32>,
}

pub struct UnixTunReader {
    fd: RawFd,
}

pub struct UnixTunWriter {
    fd: RawFd,
}

#[derive(Debug)]
pub enum UnixTunError {
    Tun(tun::Error),
    Closed,
}

impl fmt::Display for UnixTunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnixTunError::Tun(e) => write!(f, "Tunnel error: {}", e),
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

impl Reader for UnixTunReader {
    type Error = UnixTunError;

    fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
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
    }
}

impl Writer for UnixTunWriter {
    type Error = UnixTunError;

    fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
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
    }
}

impl Tun for UnixTun {
    type Writer = UnixTunWriter;
    type Reader = UnixTunReader;
    type Error = UnixTunError;
}

impl UnixTun {
    /// Creates a new unix tunnel device
    pub fn builder() -> UnixTunBuilder {
        UnixTunBuilder::default()
    }

    pub fn readers(&self) -> Vec<UnixTunReader> {
        vec![UnixTunReader {
            fd: self.device.as_raw_fd(),
        }]
    }

    pub fn writer(&self) -> UnixTunWriter {
        UnixTunWriter {
            fd: self.device.as_raw_fd(),
        }
    }
}

impl UnixTunBuilder {
    /// Sets the IP address of this TUN device
    ///
    /// # Arguments
    /// * `ip` - IP address to assign to this TUN device
    pub fn ip(&mut self, ip: Ipv4Addr) -> &mut Self {
        self.ip = Some(ip);
        self
    }

    /// Sets the netmask of this TUN device
    ///
    /// # Arguments
    /// * `netmask` - Subnet mask of Ipv4 address
    pub fn netmask(&mut self, netmask: Ipv4Addr) -> &mut Self {
        self.netmask = Some(netmask);
        self
    }

    /// Sets the Maximum Transfer Unit (MTU)
    ///
    /// # Arguments
    /// * `mtu` - Maxmium amount of data to send in one packet
    pub fn mtu(&mut self, mtu: i32) -> &mut Self {
        self.mtu = Some(mtu);
        self
    }

    /// Creates the TUN device with the supplied paramters
    ///
    /// # Arguments
    /// * `name` - Name to assign to this TUN device
    ///
    /// # Errors
    /// * `UnixTunError::Tun` - TUN device fails to create
    pub fn build(&mut self, name: &str) -> Result<UnixTun, UnixTunError> {
        let mut config = tun::Configuration::default();

        let mut cfg = config
            .name(name)
            .layer(tun::Layer::L3)
            .mtu(self.mtu.unwrap_or(1430));

        if let Some(ip) = self.ip {
            cfg = cfg.address(ip);
        }

        if let Some(netmask) = self.netmask {
            cfg = cfg.netmask(netmask);
        }

        cfg.up();

        #[cfg(target_os = "linux")]
        config.platform(|config| {
            config.packet_information(false);
        });

        log::info!("creating tunnel device");
        let device = tun::create(&config).map_err(|e| UnixTunError::Tun(e))?;

        log::info!("created tunnel device");

        Ok(UnixTun { device })
    }
}
