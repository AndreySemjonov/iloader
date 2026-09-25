use super::*;
use crate::renewal::Phase;
use std::{fs, io::Write};

#[test]
fn portal_rate_limit_survives_certificate_context_without_any_http_request() {
    let response = tauri::http::Response::builder()
        .status(429)
        .body(String::new())
        .unwrap();
    let error = reqwest::Response::from(response)
        .error_for_status()
        .unwrap_err();
    let report: Report = rootcause::report!(error)
        .context(CertificateReuseError::LookupFailed)
        .into();
    assert_eq!(classify(&report, Failure::Signing), Failure::RateLimited);
}

#[test]
fn prepared_archive_owns_unique_copy_and_cleans_failed_signing_workspace() {
    let root = std::env::temp_dir().join(format!("iloader-live-fixture-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let source = root.join("original.ipa");
    let mut zip = zip::ZipWriter::new(fs::File::create(&source).unwrap());
    zip.start_file(
        "Payload/Test.app/Info.plist",
        zip::write::SimpleFileOptions::default(),
    )
    .unwrap();
    write!(zip,"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>test.app</string></dict></plist>").unwrap();
    zip.finish().unwrap();
    let retained = root.join("retained");
    let identity = archive::retain(&source, &retained).unwrap();
    let first = Prepared::create(&identity, &retained).unwrap();
    let second = Prepared::create(&identity, &retained).unwrap();
    assert_ne!(first.ipa, second.ipa);
    assert_eq!(archive::inspect(&first.ipa).unwrap(), identity);
    fs::create_dir(&first.extracted).unwrap();
    fs::write(first.extracted.join("partial"), b"partial signing").unwrap();
    let (directory, extracted) = (first.directory.clone(), first.extracted.clone());
    drop(first);
    assert!(!directory.exists() && !extracted.exists());
    assert!(second.ipa.exists() && source.exists());
    drop(second);
    let retained_path = identity.path(&retained).unwrap();
    fs::write(&retained_path, b"changed").unwrap();
    assert!(matches!(
        Prepared::create(&identity, &retained),
        Err(Failure::ArchiveChanged)
    ));
    fs::remove_file(retained_path).unwrap();
    assert!(matches!(
        Prepared::create(&identity, &retained),
        Err(Failure::ArchiveMissing)
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn account_and_team_cannot_drift_between_enrollment_and_signing() {
    assert_eq!(
        require_session_identity("A@example.invalid", "TEAM", "a@example.invalid", "TEAM"),
        Ok(())
    );
    for (account, team) in [
        ("other@example.invalid", "TEAM"),
        ("a@example.invalid", "OTHER"),
        ("", "TEAM"),
    ] {
        assert_eq!(
            require_session_identity(account, team, "a@example.invalid", "TEAM"),
            Err(Failure::AccountMismatch)
        );
    }
}

#[test]
fn typed_dependency_failures_require_action() {
    assert_eq!(
        classify(
            &rootcause::report!(CertificateReuseError::MissingKey).into(),
            Failure::Signing
        ),
        Failure::CertificateActionRequired
    );
}

#[test]
fn original_archive_and_watch_enrollment_must_agree_before_transport_selection() {
    let root =
        std::env::temp_dir().join(format!("iloader-transport-archive-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for has_watch in [false, true] {
        let path = root.join(if has_watch { "watch.ipa" } else { "phone.ipa" });
        let mut zip = zip::ZipWriter::new(fs::File::create(&path).unwrap());
        let mut paths = vec![("Payload/Test.app/Info.plist", "test.app")];
        if has_watch {
            paths.push((
                "Payload/Test.app/Watch/Test.app/Info.plist",
                "test.app.watch",
            ));
        }
        for (name, id) in paths {
            zip.start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            write!(zip, "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{id}</string></dict></plist>").unwrap();
        }
        zip.finish().unwrap();
        let archive = archive::inspect(&path).unwrap();
        assert_eq!(archive.has_watch, has_watch);
        let mut job = Enrollment {
            product: Default::default(),
            pilot_enabled: false,
            attempt: None,
            failure_evidence: None,
            version: 1,
            archive,
            account: "test@example.invalid".into(),
            team_id: "TEAM".into(),
            phone_id: "phone".into(),
            watch_id: has_watch.then(|| "watch".into()),
            enabled: false,
            launch_confirmed: false,
            iphone: super::super::DeviceEvidence::unknown(),
            watch: has_watch.then(super::super::DeviceEvidence::unknown),
            phase: Phase::Idle,
            next_attempt: 0,
            retry_count: 0,
            last_checked: None,
            last_failure: None,
        };
        assert_eq!(require_archive_enrollment(&job), Ok(()));
        job.watch_id = (!has_watch).then(|| "watch".into());
        assert_eq!(require_archive_enrollment(&job), Err(Failure::WrongDevice));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn signed_profile_must_cover_exact_bundle_team_device_and_future_expiry() {
    let mut entitlements = plist::Dictionary::new();
    entitlements.insert(
        "application-identifier".into(),
        "PREFIX.test.app.TEAM".into(),
    );
    entitlements.insert("com.apple.developer.team-identifier".into(), "TEAM".into());
    let mut profile = plist::Dictionary::new();
    profile.insert("Entitlements".into(), entitlements.into());
    profile.insert(
        "TeamIdentifier".into(),
        vec![plist::Value::from("TEAM")].into(),
    );
    profile.insert(
        "ApplicationIdentifierPrefix".into(),
        vec![plist::Value::from("PREFIX")].into(),
    );
    profile.insert(
        "ProvisionedDevices".into(),
        vec![plist::Value::from("phone")].into(),
    );
    profile.insert(
        "ExpirationDate".into(),
        plist::Value::Date((UNIX_EPOCH + Duration::from_secs(200)).into()),
    );
    assert_eq!(
        validate_profile(&profile, "test.app.TEAM", "TEAM", "phone", 100),
        Ok(())
    );
    for (bundle, team, device, now) in [
        ("test.app.OTHER", "TEAM", "phone", 100),
        ("test.app.TEAM", "OTHER", "phone", 100),
        ("test.app.TEAM", "TEAM", "watch", 100),
        ("test.app.TEAM", "TEAM", "phone", 200),
    ] {
        assert_eq!(
            validate_profile(&profile, bundle, team, device, now),
            Err(Failure::Signing)
        );
    }
    profile.remove("ExpirationDate");
    assert_eq!(
        validate_profile(&profile, "test.app.TEAM", "TEAM", "phone", 100),
        Err(Failure::Signing)
    );
}

fn phone_job() -> Enrollment {
    Enrollment {
        product: Default::default(),
        pilot_enabled: false,
        attempt: None,
        failure_evidence: None,
        version: 1,
        archive: archive::ArchiveIdentity {
            sha256: "a".repeat(64),
            bundles: vec![("Payload/Test.app/Info.plist".into(), "test.app".into())],
            has_watch: false,
        },
        account: "a@example.invalid".into(),
        team_id: "TEAM".into(),
        phone_id: "phone".into(),
        watch_id: None,
        enabled: false,
        launch_confirmed: true,
        iphone: super::super::DeviceEvidence::unknown(),
        watch: None,
        phase: Phase::Idle,
        next_attempt: 0,
        retry_count: 0,
        last_checked: None,
        last_failure: None,
    }
}
#[tokio::test]
async fn native_adapter_rejects_watch_before_archive_or_network_access() {
    let directory =
        std::env::temp_dir().join(format!("iloader-native-guard-{}", std::process::id()));
    assert!(!directory.exists());
    let mut backend = LiveBackend::new(directory.clone(), "https://example.invalid").unwrap();
    let mut job = phone_job();
    job.archive.has_watch = true;
    assert_eq!(backend.prepare(&job).await, Err(Failure::WatchNotSupported));
    assert!(backend.prepared.is_none() && backend.job.is_none());
    assert_eq!(
        backend.connect_device("phone", Some("watch")).await,
        Err(Failure::WatchNotSupported)
    );
    assert!(backend.connection.is_none() && backend.session.is_none());
    assert!(!directory.exists());
}

#[test]
fn actual_cold_provider_endpoints_match_interactive_for_origin_and_path_prefix() {
    use isideload::anisette::remote_v3::{Endpoint, endpoint_url};
    for (base, headers, provisioning) in [
        (
            "https://example.invalid",
            "https://example.invalid/v3/get_headers",
            "wss://example.invalid/v3/provisioning_session",
        ),
        (
            "https://example.invalid/",
            "https://example.invalid/v3/get_headers",
            "wss://example.invalid/v3/provisioning_session",
        ),
        (
            "https://example.invalid/prefix/",
            "https://example.invalid/prefix/v3/get_headers",
            "wss://example.invalid/prefix/v3/provisioning_session",
        ),
    ] {
        let cold = LiveBackend::new(PathBuf::new(), base).unwrap();
        for configured in [base, cold.anisette_url.as_str()] {
            assert_eq!(
                endpoint_url(configured, Endpoint::Headers)
                    .unwrap()
                    .as_str(),
                headers
            );
            assert_eq!(
                endpoint_url(configured, Endpoint::Provisioning)
                    .unwrap()
                    .as_str(),
                provisioning
            );
        }
    }
}

#[test]
fn cold_anisette_validation_rejects_query_fragment_credentials_and_plain_http() {
    for url in [
        "https://example.invalid/?query=1",
        "https://example.invalid/#fragment",
        "https://user:pass@example.invalid",
        "http://example.invalid",
    ] {
        assert!(LiveBackend::new(PathBuf::new(), url).is_err());
    }
}

#[test]
fn shared_phone_identity_error_keeps_strict_failure_classification() {
    let error =
        idevice::IdeviceError::Socket(std::io::Error::other(crate::phone_transport::WrongPhone));
    assert_eq!(
        classify(
            &rootcause::report!(isideload::SideloadError::IdeviceError(error)).into(),
            Failure::Installation,
        ),
        Failure::WrongDevice,
    );
}
