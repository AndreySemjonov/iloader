# isideload source

This directory contains a modified copy of the MIT-licensed
[isideload](https://github.com/nab138/isideload) crate by nab138, which iloader
uses for Apple ID sign-in, signing and installation. It is built from here as a
path dependency, so no other checkout is needed.

Base: `nab138/isideload` at `f6a4d5dba717d72fc2af63eaba26b27ba44116be`
(the revision the original iloader used before it moved to isideload 0.4).
Later upstream fixes ported here: app ID name normalization, retry on HTTP 429
from Apple's sign-in servers, `Connection: close` for sign-in requests, larger
AFC upload chunks and less frequent upload progress logging.

Changes made in this fork:

- Apple Watch companion signing and installation over RSD (`sideload/watch_install.rs`,
  `sideload/bundle.rs`, `sideload/install.rs`, `sideload/sideloader.rs`,
  `sideload/sign.rs`, `sideload/application.rs`). Watch companion support
  includes contributions by Data_C0re_ (Rzbck).
- Watch device registration (`dev/device_type.rs`, `dev/devices.rs`, `dev/app_ids.rs`).
- Certificate and signing identity policies (`sideload/cert_identity.rs`,
  `sideload/builder.rs`, `sideload/certificate_policy_tests.rs`).
- Non-interactive sign-in with saved credentials for automatic renewal
  (`auth/apple_account/noninteractive.rs`, `auth/apple_account.rs`,
  `auth/grandslam.rs`).
- Anisette endpoint normalization (`anisette/mod.rs`, `anisette/remote_v3`).

The crate source, its tests, manifest, upstream README and LICENSE are kept;
repository workflows and examples are not included. Keep LICENSE and this
attribution when updating the copy.
