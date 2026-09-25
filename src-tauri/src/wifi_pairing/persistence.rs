//! Standard usbmuxd SavePairRecord with DeviceID, as used by libimobiledevice's
//! userpref_save_pair_record / libusbmuxd_save_pair_record_with_device_id.
//! The selected handle is rechecked on this socket before the only write.
use idevice::{
    ReadWrite,
    usbmuxd::{RawPacket, UsbmuxdAddr},
};
use plist::{Dictionary, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{DeviceInfo, RepairStatus, Step, valid_usb_target};

const MAX_RESPONSE: usize = 1024 * 1024;

pub(super) async fn save(device: &DeviceInfo, record: &[u8]) -> Step<()> {
    let address = UsbmuxdAddr::from_env_var().map_err(|_| RepairStatus::Failed)?;
    let mut socket = address
        .to_socket()
        .await
        .map_err(|_| RepairStatus::Failed)?;
    save_on_socket(socket.as_mut(), device, record).await
}

async fn save_on_socket(
    socket: &mut dyn ReadWrite,
    device: &DeviceInfo,
    record: &[u8],
) -> Step<()> {
    if !valid_usb_target(device) || device.id == 0 || record.is_empty() {
        return Err(RepairStatus::WrongDevice);
    }
    let inventory = exchange(socket, 1, message("ListDevices")).await?;
    require_inventory(&inventory, device)?;
    let mut request = message("SavePairRecord");
    request.insert("PairRecordID".into(), device.udid.clone().into());
    request.insert("DeviceID".into(), device.id.into());
    request.insert("PairRecordData".into(), Value::Data(record.to_vec()));
    let response = exchange(socket, 2, request).await?;
    if response.get("MessageType").and_then(Value::as_string) != Some("Result")
        || response.get("Number").and_then(Value::as_unsigned_integer) != Some(0)
    {
        return Err(RepairStatus::Failed);
    }
    Ok(())
}

fn message(kind: &str) -> Dictionary {
    let mut request = Dictionary::new();
    request.insert("MessageType".into(), kind.into());
    request.insert("ProgName".into(), "iloader".into());
    request.insert("ClientVersionString".into(), "iloader-usb-repair".into());
    request.insert("kLibUSBMuxVersion".into(), 3u32.into());
    request
}

fn require_inventory(inventory: &Dictionary, device: &DeviceInfo) -> Step<()> {
    let entries = inventory
        .get("DeviceList")
        .and_then(Value::as_array)
        .ok_or(RepairStatus::Failed)?;
    let mut matching_handle = 0;
    for entry in entries {
        let entry = entry.as_dictionary().ok_or(RepairStatus::Failed)?;
        let id = entry
            .get("DeviceID")
            .and_then(Value::as_unsigned_integer)
            .ok_or(RepairStatus::Failed)?;
        if id != u64::from(device.id) {
            continue;
        }
        matching_handle += 1;
        let props = entry
            .get("Properties")
            .and_then(Value::as_dictionary)
            .ok_or(RepairStatus::Failed)?;
        if props.get("SerialNumber").and_then(Value::as_string) != Some(device.udid.as_str())
            || props.get("ConnectionType").and_then(Value::as_string) != Some("USB")
        {
            return Err(RepairStatus::WrongDevice);
        }
    }
    if matching_handle != 1 {
        return Err(RepairStatus::DeviceGone);
    }
    Ok(())
}

async fn exchange(socket: &mut dyn ReadWrite, tag: u32, request: Dictionary) -> Step<Dictionary> {
    let packet: Vec<u8> = RawPacket::new(request, 1, 8, tag).into();
    socket
        .write_all(&packet)
        .await
        .map_err(|_| RepairStatus::Failed)?;
    read_response(socket, tag).await
}

async fn read_response(socket: &mut dyn ReadWrite, tag: u32) -> Step<Dictionary> {
    let mut header = [0; 16];
    socket
        .read_exact(&mut header)
        .await
        .map_err(|_| RepairStatus::Failed)?;
    let field = |offset| u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap());
    let length = field(0) as usize;
    if !(16..=MAX_RESPONSE).contains(&length) || field(4) != 1 || field(8) != 8 || field(12) != tag
    {
        return Err(RepairStatus::Failed);
    }
    let mut body = vec![0; length - 16];
    socket
        .read_exact(&mut body)
        .await
        .map_err(|_| RepairStatus::Failed)?;
    plist::from_bytes(&body).map_err(|_| RepairStatus::Failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> DeviceInfo {
        DeviceInfo {
            id: 42,
            udid: "synthetic-phone".into(),
            name: "Phone".into(),
            connection_type: "USB".into(),
            network_address: None,
            version: "26".into(),
        }
    }
    fn inventory(serial: &str, transport: &str, id: u32) -> Dictionary {
        plist_macro::plist!({"DeviceList": [{"DeviceID":id, "Properties": {
            "SerialNumber":serial, "ConnectionType":transport
        }}]})
        .into_dictionary()
        .unwrap()
    }
    async fn reply(socket: &mut dyn ReadWrite, tag: u32, value: Dictionary) {
        let bytes: Vec<u8> = RawPacket::new(value, 1, 8, tag).into();
        socket.write_all(&bytes).await.unwrap();
    }

    #[tokio::test]
    async fn real_wire_saves_exact_record_with_current_usb_handle_once() {
        let (mut client, mut server) = tokio::io::duplex(8192);
        let caller =
            async move { save_on_socket(&mut client, &device(), b"synthetic record").await };
        let daemon = async move {
            let list = read_response(&mut server, 1).await.unwrap();
            assert_eq!(list["MessageType"].as_string(), Some("ListDevices"));
            reply(&mut server, 1, inventory("synthetic-phone", "USB", 42)).await;
            let save = read_response(&mut server, 2).await.unwrap();
            assert_eq!(save["MessageType"].as_string(), Some("SavePairRecord"));
            assert_eq!(save["DeviceID"].as_unsigned_integer(), Some(42));
            assert_eq!(save["PairRecordID"].as_string(), Some("synthetic-phone"));
            assert_eq!(
                save["PairRecordData"].as_data(),
                Some(b"synthetic record".as_slice())
            );
            reply(
                &mut server,
                2,
                plist_macro::plist!({"MessageType":"Result", "Number":0})
                    .into_dictionary()
                    .unwrap(),
            )
            .await;
            // The caller closes; no retry, Unpair, or extra save message.
            assert!(server.read_u8().await.is_err());
        };
        let (result, ()) = tokio::join!(caller, daemon);
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn stale_wrong_network_or_duplicate_inventory_never_sends_save() {
        let mut duplicate = inventory("synthetic-phone", "USB", 42);
        let array = duplicate
            .get_mut("DeviceList")
            .unwrap()
            .as_array_mut()
            .unwrap();
        array.push(array[0].clone());
        for inventory in [
            inventory("synthetic-phone", "USB", 43),
            inventory("wrong", "USB", 42),
            inventory("synthetic-phone", "Network", 42),
            duplicate,
            Dictionary::new(),
        ] {
            let (mut client, mut server) = tokio::io::duplex(8192);
            let caller =
                async move { save_on_socket(&mut client, &device(), b"synthetic record").await };
            let daemon = async move {
                read_response(&mut server, 1).await.unwrap();
                reply(&mut server, 1, inventory).await;
                assert!(server.read_u8().await.is_err());
            };
            let (result, ()) = tokio::join!(caller, daemon);
            assert!(result.is_err());
        }
    }

    #[tokio::test]
    async fn daemon_error_or_wrong_result_type_never_reports_saved() {
        for value in [
            plist_macro::plist!({"MessageType":"Result", "Number":5}),
            plist_macro::plist!({"MessageType":"Other", "Number":0}),
            plist_macro::plist!({}),
        ] {
            let (mut client, mut server) = tokio::io::duplex(8192);
            let caller =
                async move { save_on_socket(&mut client, &device(), b"synthetic record").await };
            let daemon = async move {
                read_response(&mut server, 1).await.unwrap();
                reply(&mut server, 1, inventory("synthetic-phone", "USB", 42)).await;
                read_response(&mut server, 2).await.unwrap();
                reply(&mut server, 2, value.into_dictionary().unwrap()).await;
                assert!(server.read_u8().await.is_err());
            };
            let (result, ()) = tokio::join!(caller, daemon);
            assert_eq!(result, Err(RepairStatus::Failed));
        }
    }

    #[tokio::test]
    async fn response_header_is_bounded_and_matched_before_body_read() {
        for fields in [
            [15u32, 1, 8, 1],
            [MAX_RESPONSE as u32 + 1, 1, 8, 1],
            [16, 0, 8, 1],
            [16, 1, 0, 1],
            [16, 1, 8, 2],
        ] {
            let (mut client, mut server) = tokio::io::duplex(64);
            for field in fields {
                server.write_all(&field.to_le_bytes()).await.unwrap();
            }
            // Server deliberately stays open without a body. Invalid headers
            // must fail immediately rather than block or allocate their size.
            assert_eq!(
                tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    read_response(&mut client, 1)
                )
                .await
                .unwrap(),
                Err(RepairStatus::Failed)
            );
        }
    }
}
