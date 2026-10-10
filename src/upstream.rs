// Jackson Coxson
//
// Forwarding to an upstream usbmuxd when running in shim mode. The shim adds
// network devices of its own but defers USB devices and most request/response
// traffic to the real muxer pointed at by `--upstream-usbmuxd`.

use idevice::{
    ReadWrite,
    usbmuxd::{RawPacket, UsbmuxdAddr, server::UsbmuxdServerResponse},
};
use log::warn;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// Open a fresh connection to the upstream muxer.
pub async fn connect(addr: &UsbmuxdAddr) -> Result<Box<dyn ReadWrite>, String> {
    addr.to_socket()
        .await
        .map_err(|e| format!("connect to upstream usbmuxd: {e:?}"))
}

/// Read one usbmuxd frame (16-byte header + body) as raw bytes.
pub async fn read_frame<R: AsyncRead + Unpin + ?Sized>(sock: &mut R) -> std::io::Result<Vec<u8>> {
    let mut header = [0u8; 16];
    sock.read_exact(&mut header).await?;
    let size = u32::from_le_bytes(header[..4].try_into().expect("16-byte header")) as usize;
    if size < 16 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "upstream frame smaller than its header",
        ));
    }
    let mut buf = vec![0u8; size];
    buf[..16].copy_from_slice(&header);
    sock.read_exact(&mut buf[16..]).await?;
    Ok(buf)
}

/// Forward a single request to upstream and return its single response frame.
///
/// The frame is returned rather than written to the client so the caller can
/// fall back to handling the request locally if upstream is unreachable. Used
/// for the request/response messages the shim doesn't special-case (ReadBUID,
/// ReadPairRecord, SavePairRecord, and any unknown type).
pub async fn forward_to_upstream(addr: &UsbmuxdAddr, request: &[u8]) -> Result<Vec<u8>, String> {
    let mut up = connect(addr).await?;
    up.write_all(request)
        .await
        .map_err(|e| format!("write to upstream: {e:?}"))?;
    read_frame(&mut *up)
        .await
        .map_err(|e| format!("read from upstream: {e:?}"))
}

/// Forward the client's verbatim `ListDevices` request to upstream, then return
/// a response whose `DeviceList` is the upstream list with `network_devices`
/// appended. Preserves every property upstream reports for its USB devices.
pub async fn list_devices_merged(
    addr: &UsbmuxdAddr,
    request: &[u8],
    network_devices: Vec<plist::Value>,
    tag: u32,
) -> Result<Vec<u8>, String> {
    let mut up = connect(addr).await?;
    up.write_all(request)
        .await
        .map_err(|e| format!("write ListDevices to upstream: {e:?}"))?;
    let frame = read_frame(&mut *up)
        .await
        .map_err(|e| format!("read ListDevices from upstream: {e:?}"))?;

    let parsed = RawPacket::try_from(frame.as_slice())
        .map_err(|_| "could not parse upstream ListDevices response".to_string())?;
    let mut list = match parsed.plist.get("DeviceList") {
        Some(plist::Value::Array(a)) => a.clone(),
        _ => {
            warn!("upstream ListDevices response had no DeviceList array");
            Vec::new()
        }
    };
    list.retain(|entry| entry.as_dictionary().is_none_or(is_usb_entry));
    list.extend(network_devices);

    Ok(UsbmuxdServerResponse::DeviceList(list)
        .into_packet(tag)
        .into())
}

/// Whether an upstream device entry (a `DeviceList` item, or an `Attached`
/// frame) is a USB device. Only those are passed on: the shim serves network
/// devices itself, and upstream's own network entries are unreachable from
/// here and can be unreadable too. Windows' Apple Mobile Device Service lists
/// a phone on Wi-Fi with a Windows `sockaddr` (AF_INET6 is 23 there, an IPv6
/// link-local address), and libimobiledevice on Linux fails the whole device
/// list on it. An entry without a ConnectionType is kept.
pub fn is_usb_entry(entry: &plist::Dictionary) -> bool {
    entry
        .get("Properties")
        .and_then(|p| p.as_dictionary())
        .and_then(|p| p.get("ConnectionType"))
        .and_then(|c| c.as_string())
        .is_none_or(|c| c == "USB")
}

/// Drops upstream `Listen` frames for non-USB devices (see `is_usb_entry`),
/// and the `Detached` frames that follow them.
#[derive(Default)]
pub struct ListenFilter {
    hidden: std::collections::HashSet<u64>,
}

impl ListenFilter {
    /// Whether to relay this frame to the client. Frames that can't be parsed
    /// are relayed as they are.
    pub fn keep(&mut self, frame: &[u8]) -> bool {
        let Ok(packet) = RawPacket::try_from(frame) else {
            return true;
        };
        let id = packet
            .plist
            .get("DeviceID")
            .and_then(|i| i.as_unsigned_integer());
        match packet.plist.get("MessageType").and_then(|m| m.as_string()) {
            Some("Attached") if !is_usb_entry(&packet.plist) => {
                if let Some(id) = id {
                    self.hidden.insert(id);
                }
                false
            }
            Some("Detached") => id.is_none_or(|id| !self.hidden.remove(&id)),
            _ => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(id: u64, connection: &str) -> plist::Dictionary {
        let mut properties = plist::Dictionary::new();
        properties.insert("ConnectionType".into(), connection.into());
        properties.insert("DeviceID".into(), id.into());
        let mut entry = plist::Dictionary::new();
        entry.insert("DeviceID".into(), id.into());
        entry.insert("MessageType".into(), "Attached".into());
        entry.insert("Properties".into(), properties.into());
        entry
    }

    fn frame(dict: plist::Dictionary) -> Vec<u8> {
        RawPacket::new(dict, 1, 8, 0).into()
    }

    fn detached(id: u64) -> Vec<u8> {
        let mut dict = plist::Dictionary::new();
        dict.insert("DeviceID".into(), id.into());
        dict.insert("MessageType".into(), "Detached".into());
        frame(dict)
    }

    #[test]
    fn only_usb_entries_are_usb() {
        assert!(is_usb_entry(&device(1, "USB")));
        assert!(!is_usb_entry(&device(2, "Network")));
        assert!(is_usb_entry(&plist::Dictionary::new()));
    }

    #[test]
    fn listen_filter_drops_network_devices_and_their_detach() {
        let mut filter = ListenFilter::default();
        assert!(filter.keep(&frame(device(9, "USB"))));
        assert!(!filter.keep(&frame(device(11, "Network"))));
        assert!(!filter.keep(&detached(11)));
        assert!(filter.keep(&detached(9)));
        // A later detach for the same id isn't hidden twice.
        assert!(filter.keep(&detached(11)));
        assert!(filter.keep(b"not a frame"));
    }
}
