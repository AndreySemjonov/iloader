use apple_codesign::ProvisioningProfile;
use hex::ToHex;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_RSA_SHA256};
use rootcause::{option_ext::OptionExt, prelude::*};
use rsa::{
    RsaPrivateKey,
    pkcs1::EncodeRsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};

use sha1::Sha1;
use sha2::{Digest, Sha256};
use tracing::{error, info};
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

use crate::{
    SideloadError,
    dev::{
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
        device_type::{DeveloperDeviceType, dev_url},
        teams::DeveloperTeam,
    },
    sideload::builder::{CertificatePolicy, MaxCertsBehavior},
    util::{plist::PlistDataExtract, storage::SideloadingStorage},
};

pub const APPLE_ROOT: &[u8] = include_bytes!("../assets/apple_root.cer");
pub const APPLE_WWDR_G3_CERTIFICATE_DER: &[u8] = include_bytes!("../assets/AppleWWDRCAG3.cer");

pub struct CertificateIdentity {
    pub machine_id: String,
    pub machine_name: String,
    pub private_key: RsaPrivateKey,
    pub certificate: Certificate,
}

#[derive(Debug, thiserror::Error)]
pub enum CertificateReuseError {
    #[error("Saved signing key is missing; configure signing in the foreground")]
    MissingKey,
    #[error("Saved signing key could not be read; check secure storage in the foreground")]
    KeyUnavailable,
    #[error("Certificate lookup failed; check the account in the foreground")]
    LookupFailed,
    #[error("No matching signing certificate; configure signing in the foreground")]
    NoMatch,
    #[error("Signing certificate is expired or not yet valid; renew it in the foreground")]
    InvalidValidity,
    #[error(
        "Signing certificate is revoked or its active status is unconfirmed; check it in the foreground"
    )]
    Inactive,
}

impl CertificateIdentity {
    // This implementation was mostly borrowed from Impactor (https://github.com/khcrysalis/Impactor/blob/main/crates/plume_core/src/utils/certificate.rs)
    /// Exports the certificate and private key as a PKCS#12 archive
    /// If you plan to import into SideStore/AltStore, use the machine id as the password
    pub async fn as_p12(&self, password: &str) -> Result<Vec<u8>, Report> {
        let cert_der = self.certificate.to_der()?;
        let cert_der_len = cert_der.len();
        let key_der = self.private_key.to_pkcs8_der()?.as_bytes().to_vec();
        let key_der_len = key_der.len();

        let cert = p12_keystore::Certificate::from_der(&cert_der)
            .map_err(|e| report!("Failed to parse certificate: {:?}", e))?;
        let cert_subject = cert.subject().to_string();
        let cert_issuer = cert.issuer().to_string();

        let local_key_id = {
            let mut hasher = Sha1::new();
            hasher.update(&key_der);
            let hash = hasher.finalize();
            hash[..8].to_vec()
        };

        let key_chain = p12_keystore::PrivateKeyChain::new(
            local_key_id,
            p12_keystore::PrivateKey::from_der(&key_der)?,
            vec![cert],
        );

        let mut keystore = p12_keystore::KeyStore::new();
        keystore.add_entry(
            "isideload",
            p12_keystore::KeyStoreEntry::PrivateKeyChain(key_chain),
        );

        let writer = keystore.writer(password);
        match writer.write() {
            Ok(p12) => Ok(p12),
            Err(e) => {
                let subject_codepoints = cert_subject
                    .chars()
                    .map(|c| format!("U+{:04X}", c as u32))
                    .collect::<Vec<_>>()
                    .join(" ");
                let has_non_bmp_subject_chars = cert_subject.chars().any(|c| (c as u32) > 0xFFFF);

                error!(
                    cert_subject = %cert_subject,
                    cert_issuer = %cert_issuer,
                    cert_subject_codepoints = %subject_codepoints,
                    has_non_bmp_subject_chars,
                    cert_der_len,
                    key_der_len,
                    password_char_len = password.chars().count(),
                    "Failed to write PKCS#12 archive"
                );

                let err = format!("Failed to write PKCS#12 archive: {:?}", e);
                Err(e).context(err)?
            }
        }
    }

    pub fn get_serial_number(&self) -> String {
        let serial: String = self
            .certificate
            .tbs_certificate
            .serial_number
            .as_bytes()
            .encode_hex::<String>();
        serial.trim_start_matches('0').to_string().to_uppercase()
    }

    pub async fn retrieve(
        machine_name: &str,
        apple_email: &str,
        developer_session: &mut DeveloperSession,
        team: &DeveloperTeam,
        storage: &dyn SideloadingStorage,
        max_certs_behavior: &MaxCertsBehavior,
    ) -> Result<Self, Report> {
        Self::retrieve_with_policy(
            machine_name,
            apple_email,
            developer_session,
            team,
            storage,
            max_certs_behavior,
            CertificatePolicy::AllowCreation,
        )
        .await
    }

    pub async fn retrieve_with_policy(
        machine_name: &str,
        apple_email: &str,
        developer_session: &mut DeveloperSession,
        team: &DeveloperTeam,
        storage: &dyn SideloadingStorage,
        max_certs_behavior: &MaxCertsBehavior,
        policy: CertificatePolicy,
    ) -> Result<Self, Report> {
        let pr = Self::retrieve_private_key(apple_email, storage, policy).await?;

        let found = Self::find_matching(&pr, machine_name, developer_session, team, policy).await;
        let found = if policy == CertificatePolicy::ReuseExistingOnly {
            // A lookup error must never fall through to certificate creation.
            Ok(found.context(CertificateReuseError::LookupFailed)?)
        } else {
            found
        };
        if let Ok(Some((cert, x509_cert))) = found {
            if policy == CertificatePolicy::ReuseExistingOnly {
                Self::validate_reuse(&cert, &x509_cert)?;
            }
            info!("Found matching certificate");
            return Ok(Self {
                machine_id: cert.machine_id.clone().unwrap_or_default(),
                machine_name: cert.machine_name.clone().unwrap_or_default(),
                certificate: x509_cert,
                private_key: pr,
            });
        }

        if policy == CertificatePolicy::ReuseExistingOnly {
            return Err(CertificateReuseError::NoMatch.into());
        }

        if let Err(e) = found {
            error!("Failed to check for matching certificate: {:?}", e);
        }
        info!("Requesting new certificate");
        let (cert, x509_cert) = Self::request_certificate(
            &pr,
            machine_name.to_string(),
            developer_session,
            team,
            max_certs_behavior,
        )
        .await?;

        info!("Successfully obtained certificate");

        Ok(Self {
            machine_id: cert.machine_id.clone().unwrap_or_default(),
            machine_name: cert.machine_name.clone().unwrap_or_default(),
            certificate: x509_cert,
            private_key: pr,
        })
    }

    fn validate_reuse(cert: &DevelopmentCertificate, parsed: &Certificate) -> Result<(), Report> {
        let now = std::time::SystemTime::now();
        let unix = now
            .duration_since(std::time::UNIX_EPOCH)
            .context(CertificateReuseError::InvalidValidity)?;
        let validity = &parsed.tbs_certificate.validity;
        if unix < validity.not_before.to_unix_duration()
            || unix >= validity.not_after.to_unix_duration()
            || cert
                .expiration_date
                .is_some_and(|date| std::time::SystemTime::from(date) <= now)
        {
            return Err(CertificateReuseError::InvalidValidity.into());
        }
        // Deliberately fail closed for absent/unrecognized portal status. Real
        // response compatibility is a separate acceptance check, not inferred
        // from possession of a previously issued certificate.
        if !cert.status.as_deref().is_some_and(|status| {
            status.eq_ignore_ascii_case("issued") || status.eq_ignore_ascii_case("active")
        }) || cert.status_code.is_some_and(|code| code != 0)
        {
            return Err(CertificateReuseError::Inactive.into());
        }
        Ok(())
    }

    pub fn profile_to_certificate_chain(
        &self,
        profile: &ProvisioningProfile,
    ) -> Result<Vec<Certificate>, Report> {
        let mut certificate_chain_der = Vec::with_capacity(profile.certificate_chain_der().len());

        certificate_chain_der.extend(profile.certificate_chain_der().iter().cloned());

        let mut certificate_candidates = Vec::new();

        for certificate_der in certificate_chain_der {
            let certificate = Certificate::from_der(certificate_der.as_ref())
                .context(format!("failed to decode chain certificate"))?;
            if !certificate_candidates.contains(&certificate) {
                certificate_candidates.push(certificate);
            }
        }

        for (name, certificate_der) in [
            ("Apple WWDR G3", APPLE_WWDR_G3_CERTIFICATE_DER),
            ("Apple Root CA", APPLE_ROOT),
        ] {
            let certificate = Certificate::from_der(certificate_der)
                .context(format!("failed to decode bundled {name} certificate"))?;
            if !certificate_candidates.contains(&certificate) {
                certificate_candidates.push(certificate);
            }
        }

        let certificate_chain = self.certificate_chain_for_signer(&certificate_candidates)?;
        Ok(certificate_chain)
    }

    fn certificate_chain_for_signer(
        &self,
        certificate_candidates: &[Certificate],
    ) -> Result<Vec<Certificate>, Report> {
        if self.certificate.tbs_certificate.subject == self.certificate.tbs_certificate.issuer {
            return Ok(Vec::new());
        }

        let mut issuer = self.certificate.tbs_certificate.issuer.clone();
        let mut certificate_chain = Vec::new();

        loop {
            let certificate = certificate_candidates
                .iter()
                .find(|candidate| candidate.tbs_certificate.subject == issuer)
                .ok_or_else(|| {
                    report!(
                        "missing issuer certificate {issuer} for the code-signing certificate chain"
                    )
                })?
                .clone();

            if certificate_chain.contains(&certificate) {
                bail!("certificate chain contains a cycle");
            }

            let is_root = certificate.tbs_certificate.subject == certificate.tbs_certificate.issuer;
            issuer = certificate.tbs_certificate.issuer.clone();
            certificate_chain.push(certificate);

            if is_root {
                return Ok(certificate_chain);
            }
        }
    }

    async fn retrieve_private_key(
        apple_email: &str,
        storage: &dyn SideloadingStorage,
        policy: CertificatePolicy,
    ) -> Result<RsaPrivateKey, Report> {
        let key_name = private_key_storage_key(apple_email);

        let private_key = storage
            .retrieve_data(&key_name)
            .context(CertificateReuseError::KeyUnavailable)?;
        // File storage "deletes" by leaving an empty value; treat it as absent.
        if let Some(priv_key) = private_key.filter(|key| !key.is_empty()) {
            info!("Using existing private key from storage");
            return Ok(RsaPrivateKey::from_pkcs8_der(&priv_key)
                .context(CertificateReuseError::KeyUnavailable)?);
        }

        if policy == CertificatePolicy::ReuseExistingOnly {
            return Err(CertificateReuseError::MissingKey.into());
        }

        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;
        storage.store_data(&key_name, private_key.to_pkcs8_der()?.as_bytes())?;

        Ok(private_key)
    }

    async fn find_matching(
        private_key: &RsaPrivateKey,
        machine_name: &str,
        developer_session: &mut DeveloperSession,
        team: &DeveloperTeam,
        policy: CertificatePolicy,
    ) -> Result<Option<(DevelopmentCertificate, Certificate)>, Report> {
        let public_key_der = private_key
            .to_public_key()
            .to_pkcs1_der()?
            .as_bytes()
            .to_vec();
        let certs = if policy == CertificatePolicy::ReuseExistingOnly {
            // The general API tolerates a portal error when result data is
            // present. Background reuse requires an unambiguous successful
            // lookup, even if a failed response includes cached certificates.
            let response = developer_session
                .send_dev_request_no_response(
                    &dev_url("listAllDevelopmentCerts", DeveloperDeviceType::Ios),
                    Some(plist_macro::plist!(dict { "teamId": &team.team_id })),
                )
                .await?;
            if response
                .get("resultCode")
                .and_then(plist::Value::as_signed_integer)
                != Some(0)
            {
                return Err(CertificateReuseError::LookupFailed.into());
            }
            response.get_struct::<Vec<DevelopmentCertificate>>("certificates")?
        } else {
            developer_session.list_ios_certs(team).await?
        };
        for cert in certs.iter().filter(|c| {
            c.cert_content.is_some()
                && c.certificate_platform
                    .as_deref()
                    .is_none_or(|p| p.eq_ignore_ascii_case("ios"))
                && c.machine_name.as_deref().unwrap_or("") == machine_name
                && c.machine_id.is_some()
        }) {
            let x509_cert =
                Certificate::from_der(cert.cert_content.as_ref().ok_or_report()?.as_ref())?;

            let apple_public_key_der = x509_cert
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .ok_or_report()?
                .to_vec();

            if public_key_der == apple_public_key_der {
                return Ok(Some((cert.clone(), x509_cert)));
            }
        }

        Ok(None)
    }

    async fn request_certificate(
        private_key: &RsaPrivateKey,
        machine_name: String,
        developer_session: &mut DeveloperSession,
        team: &DeveloperTeam,
        max_certs_behavior: &MaxCertsBehavior,
    ) -> Result<(DevelopmentCertificate, Certificate), Report> {
        let csr = Self::build_csr(private_key).context("Failed to generate CSR")?;

        let mut i = 0;
        let mut existing_certs: Option<Vec<DevelopmentCertificate>> = None;

        while i < 4 {
            i += 1;

            let result = developer_session
                .submit_development_csr(team, csr.clone(), machine_name.clone(), None)
                .await;

            match result {
                Ok(request) => {
                    let apple_certs = developer_session.list_ios_certs(team).await?;

                    let apple_cert = apple_certs
                        .iter()
                        .find(|c| c.certificate_id == Some(request.cert_request_id.clone()))
                        .ok_or_else(|| {
                            report!("Failed to find certificate after submitting CSR")
                        })?;

                    let x509_cert = Certificate::from_der(
                        apple_cert
                            .cert_content
                            .as_ref()
                            .ok_or_else(|| report!("Certificate content missing"))?
                            .as_ref(),
                    )?;

                    return Ok((apple_cert.clone(), x509_cert));
                }
                Err(e) => {
                    let error = e
                        .iter_reports()
                        .find_map(|node| node.downcast_current_context::<SideloadError>());
                    if let Some(SideloadError::DeveloperError(code, _)) = error {
                        if *code == 7460 {
                            if existing_certs.is_none() {
                                existing_certs = Some(
                                    developer_session
                                        .list_ios_certs(team)
                                        .await?
                                        .iter()
                                        .filter(|c| c.serial_number.is_some())
                                        .cloned()
                                        .collect(),
                                );
                            }
                            Self::revoke_others(
                                developer_session,
                                team,
                                max_certs_behavior,
                                SideloadError::DeveloperError(
                                    *code,
                                    "Maximum number of certificates reached".to_string(),
                                ),
                                existing_certs.as_mut().ok_or_report()?,
                            )
                            .await?;
                        } else {
                            return Err(e);
                        }
                    }
                }
            };
        }

        Err(report!("Reached max attempts to request certificate"))
    }

    fn build_csr(private_key: &RsaPrivateKey) -> Result<String, Report> {
        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();

        dn.push(DnType::CountryName, "US");
        dn.push(DnType::StateOrProvinceName, "STATE");
        dn.push(DnType::LocalityName, "LOCAL");
        dn.push(DnType::OrganizationName, "ORGNIZATION");
        dn.push(DnType::CommonName, "CN");
        params.distinguished_name = dn;

        let subject_key = KeyPair::from_pkcs8_pem_and_sign_algo(
            &private_key.to_pkcs8_pem(LineEnding::LF)?,
            &PKCS_RSA_SHA256,
        )?;

        Ok(params.serialize_request(&subject_key)?.pem()?)
    }

    async fn revoke_others(
        developer_session: &mut DeveloperSession,
        team: &DeveloperTeam,
        max_certs_behavior: &MaxCertsBehavior,
        error: SideloadError,
        existing_certs: &mut Vec<DevelopmentCertificate>,
    ) -> Result<(), Report> {
        match max_certs_behavior {
            MaxCertsBehavior::Revoke => {
                if let Some(cert) = existing_certs.pop() {
                    info!(
                        "Revoking certificate with name: {:?} ({:?})",
                        cert.name, cert.machine_name
                    );
                    developer_session
                        .revoke_development_cert(team, &cert.serial_number.ok_or_report()?, None)
                        .await?;
                    Ok(())
                } else {
                    error!("No more certificates to revoke but still hitting max certs error");
                    Err(error.into())
                }
            }
            MaxCertsBehavior::Error => Err(error.into()),
            MaxCertsBehavior::Prompt(prompt_fn) => {
                let certs_to_revoke = prompt_fn(existing_certs);
                if certs_to_revoke.is_none() {
                    error!("User did not select any certificates to revoke");
                    return Err(error.into());
                }
                for serial in certs_to_revoke.ok_or_report()? {
                    info!("Revoking certificate with serial number: {}", serial);
                    developer_session
                        .revoke_development_cert(team, &serial, None)
                        .await?;
                    existing_certs.retain(|c| c.serial_number != Some(serial.clone()));
                }
                Ok(())
            }
        }
    }
}

/// Storage key of the signing private key for an Apple ID. Callers pass the
/// email in the same (lowercase) form used to build the sideloader.
pub fn private_key_storage_key(apple_email: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(apple_email.as_bytes());
    format!("{}/key", hex::encode(hasher.finalize()))
}
