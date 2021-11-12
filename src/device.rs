//! Wrapper around a TUN device backed by a wireguard implementation

use crate::{
    configuration::{ConfigError, Configuration, WireGuardConfig},
    platform::UDP,
    wireguard::WireGuard,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tun_rs::{OsTun, TunConfig};
use x25519_dalek::{PublicKey, StaticSecret};

type TunDevice = Arc<OsTun>;

pub struct WgDevice {
    #[allow(dead_code)]
    tun: TunDevice,

    #[allow(dead_code)]
    wg: WireGuard<TunDevice, UDP>,

    cfg: WireGuardConfig<TunDevice, UDP>,
}

pub struct WgDeviceBuilder {
    key: Result<StaticSecret, WgBuildError>,
    tun: TunConfig,
}

pub struct WgPeerBuilder {
    /// WireGuard config to use for this device
    cfg: WireGuardConfig<TunDevice, UDP>,

    /// Public key of peer
    key: PublicKey,

    endpoint: Option<SocketAddr>,
    keepalive: Option<u64>,
    allowed_ips: Vec<(IpAddr, u8)>,
}

#[derive(Debug)]
pub enum WgBuildError {
    InvalidKey(base64::DecodeError),
    InvalidKeyLength,
    KeyNotSet,
    Tun(tun_rs::TunError),
    Wg(ConfigError),
}

impl WgDevice {
    pub fn builder() -> WgDeviceBuilder {
        WgDeviceBuilder::new()
    }

    pub fn peer(&self, key: impl AsRef<[u8]>) -> Result<WgPeerBuilder, WgBuildError> {
        let key = base64::decode_config(key, base64::STANDARD)
            .map_err(WgBuildError::InvalidKey)
            .and_then(|key| {
                let key: Result<[u8; 32], WgBuildError> =
                    key.try_into().map_err(|_| WgBuildError::InvalidKeyLength);
                key
            })
            .map(|key| PublicKey::from(key))?;

        Ok(WgPeerBuilder {
            cfg: self.cfg.clone(),
            key,
            endpoint: None,
            keepalive: None,
            allowed_ips: Vec::new(),
        })
    }
}

impl WgDeviceBuilder {
    fn new() -> Self {
        Self {
            key: Err(WgBuildError::KeyNotSet),
            tun: TunConfig::default(),
        }
    }

    /// Sets the private key for this device
    ///
    /// # Arguments
    /// * `key` - base64 encoded private key
    pub fn key(mut self, key: impl AsRef<[u8]>) -> Self {
        self.key = base64::decode_config(key, base64::STANDARD)
            .map_err(WgBuildError::InvalidKey)
            .and_then(|key| {
                let key: Result<[u8; 32], WgBuildError> =
                    key.try_into().map_err(|_| WgBuildError::InvalidKeyLength);
                key
            })
            .map(|key| StaticSecret::from(key));
        self
    }

    /// Sets the TUN device configuration for this WireGuard device
    ///
    /// TUN config includes:
    /// * TUN device name (on Linux only)
    /// * IP and Subnet mask
    ///
    /// # Arguments
    /// * `cfg` - TUN device configuration
    pub fn tun_config(mut self, cfg: TunConfig) -> Self {
        self.tun = cfg;
        self
    }

    pub fn build(self) -> Result<WgDevice, WgBuildError> {
        // unpack parsed private key (do this first to make sure the key is valid before
        // continuing)
        let key = self.key?;

        let tun = Arc::new(OsTun::create(self.tun).map_err(WgBuildError::Tun)?);

        let wg: WireGuard<TunDevice, UDP> = WireGuard::new(tun.clone());
        wg.add_tun_reader(tun.clone());

        let cfg = WireGuardConfig::new(wg.clone());
        cfg.set_private_key(Some(key));
        cfg.up(1380).map_err(WgBuildError::Wg)?;

        Ok(WgDevice { tun, wg, cfg })
    }
}

impl WgPeerBuilder {
    /// Sets the endpoint associated with this WireGuard device
    ///
    /// # Arguments
    /// * `addr` - Ip and port of remote peer
    pub fn endpoint(mut self, addr: impl Into<SocketAddr>) -> Self {
        self.endpoint = Some(addr.into());
        self
    }

    /// Sets the persistent keepalive interval
    ///
    /// Keepalive is useful for traversing NATs and firewalls
    ///
    /// # Argument
    /// * `keepalive` - Interval (in seconds) to send keepalive packets
    pub fn keepalive(mut self, keepalive: u64) -> Self {
        self.keepalive = Some(keepalive);
        self
    }

    /// Adds all IPs in the list to traverse this WireGuard connection
    ///
    /// # Arguments
    /// * `ips` - IP/CIDRs allowed to cross this bridge
    pub fn allowed_ips(mut self, ips: Vec<(IpAddr, u8)>) -> Self {
        let mut ips = ips;
        self.allowed_ips.append(&mut ips);
        self
    }

    /// Allows a single ip over the WireGuard Connection
    ///
    /// # Arguments
    /// * `ip` - IP/CIDR to allow
    pub fn allowed_ip(mut self, ip: (IpAddr, u8)) -> Self {
        self.allowed_ips.push(ip);
        self
    }

    /// Adds this peer to the device
    pub fn add(self) {
        self.cfg.add_peer(&self.key);

        if let Some(endpoint) = self.endpoint {
            self.cfg.set_endpoint(&self.key, endpoint);
        }

        if let Some(keepalive) = self.keepalive {
            self.cfg
                .set_persistent_keepalive_interval(&self.key, keepalive);
        }

        for (ip, mask) in self.allowed_ips {
            self.cfg.add_allowed_ip(&self.key, ip, mask as u32);
        }
    }

    /// Removes this peer from the device
    pub fn remove(self) {
        self.cfg.remove_peer(&self.key);
    }
}
