# Automatic renewal

This fork can install and renew multiple **iPhone-only apps** over Wi-Fi. Each
saved app keeps its own original IPA, phone, signing account and renewal result.
Manual installation of apps that include an Apple Watch companion is separate;
automatic Watch renewal is not supported.

## Set up an app

1. Connect the phone by USB, select it and accept any Trust prompt on the phone.
   Choose **Set up Wi-Fi** once. This turns on the phone's Wi-Fi connections
   setting and creates a pairing used for Wi-Fi installs (to undo it later,
   reset Location & Privacy on the phone). If an existing pairing needs repair,
   use **Repair Wi-Fi pairing** with USB connected. Then disconnect USB, refresh
   devices and select the phone's Wi-Fi entry.
2. Sign in with saved credentials enabled.
3. Under **Your apps**, choose **Install & auto-renew** and select the original
   IPA. Repeat for additional apps. Open each installed app to check it works.

The original archive is retained locally for future signing. Selecting an IPA
does not turn this computer into a network server. Renewal still contacts the
configured signing/authentication services and the selected device.

Use an app's **...** menu to renew now, pause, resume, replace its saved IPA,
review details or remove its setup. Removing a setup does not uninstall the app
or delete your original IPA. Global pause stops new renewals for all saved apps;
work already in progress may finish.

## When it runs

Keep iLoader running and the PC awake. Enabled apps are normally checked daily
and renewed when their signed profile has 72 hours or less remaining, well before
the 7-day expiry of a free Apple account. A sleeping
PC cannot perform a renewal. The next eligible check is considered when the host
runs again; there is no guarantee that a locked or unreachable phone can install.

If discovery finds the phone offline or locked before authentication begins,
iLoader schedules another check after 15 minutes, then 30 minutes, 1 hour,
2 hours, 4 hours and at most 6 hours between subsequent checks. Pause remains
effective, and the waiting state survives a normal restart. Keep the phone on
the local network and unlock it when practical.

Failures after discovery need attention rather than unlimited retries. Account
verification, rate limiting, certificate or trust problems stop unattended work.
An interrupted or submitted installation is not automatically replayed. Review
the app's details and the actual installed app before using recovery controls.

## Tray and Windows startup

Under **Renewal settings and troubleshooting**, choose whether closing the
window keeps iLoader in the tray. Without that preference, closing exits after
active work settles. Minimizing uses the taskbar. The tray offers Open, Pause /
Resume and Quit; Quit waits for active work.

**Start iLoader in the tray when I sign in to Windows** is a separate opt-in.
It registers this copy of iLoader, so use a stable location for the executable.
Startup does not override paused apps or global pause.

## Diagnostics and limitations

Wi-Fi troubleshooting checks phone services without installing an app. Successful
service checks alone do not prove signing, installation or Watch readiness.
Installer success and profile expiry are recorded from the installation result
and signed artifact, not from a later readback of the installed profile. Open
the app to verify launch and retained data.

Saved renewal reuses existing account credentials, certificates and device trust.
Complete interactive account or trust setup in the foreground when required.
Only one iLoader process can own the renewal host. A second copy may display the
saved state but cannot run that host concurrently.

Result reports keep known error categories only, not raw error text. Logs are
kept in iLoader's app data folder; check them before sharing. Removing an Apple
ID also deletes its saved password and signing key; remove the account's renewal
apps first. This fork has no automatic updater: download new versions from its
GitHub releases.

The Windows startup entry is removed when you turn the option off. Turn it off
before deleting iLoader, or remove the `iLoaderRenewal` value under
`HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` manually.
