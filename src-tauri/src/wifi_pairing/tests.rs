use super::*;

struct Fake {
    calls: Vec<&'static str>,
    pair: Step<()>,
    persist: Step<()>,
    verify: Step<()>,
    cancel_during_pair: Option<CancellationToken>,
    never_reply: bool,
}

impl Default for Fake {
    fn default() -> Self {
        Self {
            calls: vec![],
            pair: Ok(()),
            persist: Ok(()),
            verify: Ok(()),
            cancel_during_pair: None,
            never_reply: false,
        }
    }
}

impl RepairBackend for Fake {
    type Record = ();
    async fn prepare(&mut self) -> Step<()> {
        self.calls.push("prepare");
        Ok(())
    }
    async fn pair_once(&mut self) -> Step<()> {
        self.calls.push("pair");
        if self.never_reply {
            std::future::pending::<()>().await;
        }
        if let Some(token) = &self.cancel_during_pair {
            token.cancel();
        }
        self.pair
    }
    async fn persist(&mut self, _: &()) -> Step<()> {
        self.calls.push("persist");
        self.persist
    }
    async fn verify(&mut self, _: &()) -> Step<()> {
        self.calls.push("verify");
        self.verify
    }
}

#[tokio::test]
async fn lost_reply_is_bounded_uncertain_and_never_replayed() {
    let mut fake = Fake {
        never_reply: true,
        ..Default::default()
    };
    let result = run_with_pair_timeout(
        &mut fake,
        &CancellationToken::new(),
        Duration::from_millis(1),
    )
    .await;
    assert_eq!(result.status, RepairStatus::Uncertain);
    assert_eq!(fake.calls, ["prepare", "pair"]);
    assert!(!result.record_saved);
}

#[test]
fn phone_responses_are_typed_and_never_disclose_raw_errors() {
    assert_eq!(
        pair_error(IdeviceError::PasswordProtected),
        RepairStatus::Locked
    );
    assert_eq!(
        pair_error(IdeviceError::PairingDialogResponsePending),
        RepairStatus::Pending
    );
    assert_eq!(
        pair_error(IdeviceError::UserDeniedPairing),
        RepairStatus::Denied
    );
    assert_eq!(
        pair_error(IdeviceError::UnexpectedResponse(
            "sensitive sentinel".into()
        )),
        RepairStatus::Uncertain
    );
}

#[tokio::test]
async fn pending_locked_denied_and_uncertain_never_save_or_retry() {
    for status in [
        RepairStatus::Pending,
        RepairStatus::Locked,
        RepairStatus::Denied,
        RepairStatus::Uncertain,
    ] {
        let mut fake = Fake {
            pair: Err(status),
            ..Default::default()
        };
        let result = run(&mut fake, &CancellationToken::new()).await;
        assert_eq!(result.status, status);
        assert_eq!(fake.calls, ["prepare", "pair"]);
        assert!(!result.pair_accepted && !result.record_saved && !result.wifi_services_verified);
    }
}

#[tokio::test]
async fn cancelled_before_start_has_no_side_effects() {
    let token = CancellationToken::new();
    token.cancel();
    let mut fake = Fake::default();
    assert_eq!(run(&mut fake, &token).await.status, RepairStatus::Cancelled);
    assert!(fake.calls.is_empty());
}

#[tokio::test]
async fn cancellation_during_pair_cannot_discard_accepted_trust() {
    let token = CancellationToken::new();
    let mut fake = Fake {
        cancel_during_pair: Some(token.clone()),
        ..Default::default()
    };
    let result = run(&mut fake, &token).await;
    assert_eq!(result.status, RepairStatus::Completed);
    assert!(result.pair_accepted && result.record_saved);
    assert!(!result.wifi_services_verified);
    assert_eq!(fake.calls, ["prepare", "pair", "persist", "verify"]);
}

#[tokio::test]
async fn save_and_verification_failures_are_partial_never_success_or_retry() {
    let mut fake = Fake {
        persist: Err(RepairStatus::Failed),
        ..Default::default()
    };
    let result = run(&mut fake, &CancellationToken::new()).await;
    assert_eq!(result.status, RepairStatus::Partial);
    assert!(result.pair_accepted && !result.record_saved);
    assert_eq!(fake.calls, ["prepare", "pair", "persist"]);
    let mut fake = Fake {
        verify: Err(RepairStatus::DeviceGone),
        ..Default::default()
    };
    let result = run(&mut fake, &CancellationToken::new()).await;
    assert_eq!(result.status, RepairStatus::Partial);
    assert!(result.pair_accepted && result.record_saved);
    assert_eq!(result.stage, "verifyUsb");
}

#[test]
fn export_replaces_host_keys_and_escrow_preserving_remote_pairing() {
    let old = plist_macro::plist!({"HostID":"old", "EscrowBag":vec![1u8], "identifier":"remote", "privateKey":vec![9u8]});
    let new = plist_macro::plist!({"HostID":"new"});
    let encode = |value: plist::Value| {
        let mut bytes = vec![];
        value.to_writer_xml(&mut bytes).unwrap();
        bytes
    };
    let bytes = refresh_export(&encode(old), &encode(new)).unwrap();
    let value = plist::Value::from_reader(std::io::Cursor::new(bytes)).unwrap();
    let dictionary = value.as_dictionary().unwrap();
    assert_eq!(dictionary["HostID"].as_string(), Some("new"));
    assert_eq!(dictionary["identifier"].as_string(), Some("remote"));
    assert_eq!(dictionary["privateKey"].as_data(), Some([9u8].as_slice()));
    assert!(!dictionary.contains_key("EscrowBag"));
    assert!(refresh_export(b"invalid", &encode(plist_macro::plist!({}))).is_err());
}

#[test]
fn exact_selected_usb_only() {
    let device = DeviceInfo {
        id: 1,
        udid: "synthetic".into(),
        connection_type: "USB".into(),
        network_address: None,
        name: "Phone".into(),
        version: "26".into(),
    };
    assert!(usb_matches(
        &device,
        device.id,
        &device.udid,
        &Connection::Usb
    ));
    let mut other = device.clone();
    other.id = 2;
    assert!(!usb_matches(
        &device,
        other.id,
        &other.udid,
        &Connection::Usb
    ));
    other = device.clone();
    other.udid = "other".into();
    assert!(!usb_matches(
        &device,
        other.id,
        &other.udid,
        &Connection::Usb
    ));
    other = device.clone();
    other.connection_type = "Network".into();
    assert!(!valid_usb_target(&other));
    other = device.clone();
    other.network_address = Some("127.0.0.1".into());
    assert!(!valid_usb_target(&other));
}
