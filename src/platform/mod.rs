pub mod tun;
pub mod uapi;
pub mod udp;

mod endpoint;
pub use endpoint::Endpoint;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::UDP;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::UDP;

#[cfg(target_family = "unix")]
mod unix;
#[cfg(target_family = "unix")]
pub use self::unix::UAPI;

#[cfg(test)]
pub mod dummy;
