// TCP connections to network (Wi-Fi) devices.
//
// A bare `TcpStream::connect` has no bound on how long it waits for an asleep
// phone, leaves Nagle on for lockdown's small request/response frames, and
// leaves a connection that died mid-transfer to the kernel's retransmission
// limit (~15 minutes by default). Every connection to a network device goes
// through `connect` here instead.

use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
    time::Duration,
};

use log::debug;
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;

/// How long to wait for the device to accept a connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle time before the first keepalive probe, the gap between probes, and how
/// many may go unanswered: an idle connection to a vanished device closes
/// after about 35 seconds.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(15);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
const KEEPALIVE_RETRIES: u32 = 4;

/// How long sent data may stay unacknowledged before the connection is
/// dropped. Keepalive only covers idle connections; this covers a transfer
/// that stalls with data in flight.
#[cfg(any(target_os = "linux", target_os = "android"))]
const USER_TIMEOUT: Duration = Duration::from_secs(45);

/// Buffer size for each direction of a relayed connection. tokio's default
/// (8 KiB) means a syscall pair per 8 KiB on multi-hundred-MB uploads.
pub const RELAY_BUFFER: usize = 256 * 1024;

/// Connect to a device over the network, with the options above set.
pub async fn connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| {
            Error::new(
                ErrorKind::TimedOut,
                format!("no answer from {addr} within {CONNECT_TIMEOUT:?}"),
            )
        })??;
    tune(&stream);
    Ok(stream)
}

/// Set the socket options. A failure leaves the connection usable, only
/// without that option, so it's logged rather than returned.
fn tune(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!("Unable to set TCP_NODELAY: {e:?}");
    }
    let sock = SockRef::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
    let keepalive = keepalive.with_retries(KEEPALIVE_RETRIES);
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        debug!("Unable to set TCP keepalive: {e:?}");
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    if let Err(e) = sock.set_tcp_user_timeout(Some(USER_TIMEOUT)) {
        debug!("Unable to set TCP_USER_TIMEOUT: {e:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_sets_the_options() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = connect(addr).await.unwrap();
        assert!(stream.nodelay().unwrap());
        let sock = SockRef::from(&stream);
        assert!(sock.keepalive().unwrap());
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        {
            assert_eq!(sock.tcp_keepalive_time().unwrap(), KEEPALIVE_IDLE);
            assert_eq!(sock.tcp_keepalive_interval().unwrap(), KEEPALIVE_INTERVAL);
            assert_eq!(sock.tcp_keepalive_retries().unwrap(), KEEPALIVE_RETRIES);
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert_eq!(sock.tcp_user_timeout().unwrap(), Some(USER_TIMEOUT));
    }

    #[tokio::test]
    async fn connect_gives_up_on_an_unanswering_address() {
        // TEST-NET-1 (RFC 5737): nothing answers, so the SYN goes unanswered
        // (or the route is refused at once, which is also an error).
        let addr: SocketAddr = "192.0.2.1:62078".parse().unwrap();
        let started = std::time::Instant::now();
        assert!(connect(addr).await.is_err());
        assert!(started.elapsed() < CONNECT_TIMEOUT + Duration::from_secs(2));
    }
}
