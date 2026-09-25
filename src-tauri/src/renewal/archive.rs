use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use super::Failure;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveIdentity {
    pub sha256: String,
    pub bundles: Vec<(String, String)>,
    pub has_watch: bool,
}

/// Display metadata is intentionally outside ArchiveIdentity equality, so older
/// serialized identities still verify against precisely the same retained bytes.
pub(crate) fn display_name(path: &Path) -> Option<String> {
    let mut archive = ZipArchive::new(File::open(path).ok()?).ok()?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).ok()?;
        let parts: Vec<_> = entry.name().split('/').collect();
        if parts.len() != 3
            || parts[0] != "Payload"
            || !parts[1].ends_with(".app")
            || parts[2] != "Info.plist"
        {
            continue;
        }
        if entry.size() > 4 * 1024 * 1024 {
            return None;
        }
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        let info = plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()?;
        let dict = info.as_dictionary()?;
        return ["CFBundleDisplayName", "CFBundleName"]
            .into_iter()
            .find_map(|key| {
                dict.get(key)
                    .and_then(plist::Value::as_string)
                    .map(str::trim)
                    .filter(|name| {
                        !name.is_empty()
                            && name.chars().count() <= 128
                            && !name.chars().any(char::is_control)
                    })
                    .map(str::to_owned)
            });
    }
    None
}

impl ArchiveIdentity {
    pub fn path(&self, directory: &Path) -> Result<PathBuf, Failure> {
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Failure::ArchiveChanged);
        }
        Ok(directory.join(format!("{}.ipa", self.sha256)))
    }

    pub fn verify(&self, directory: &Path) -> Result<PathBuf, Failure> {
        let path = self.path(directory)?;
        if inspect(&path)? != *self {
            return Err(Failure::ArchiveChanged);
        }
        Ok(path)
    }
}

/// Retain an explicit user-selected original. Caller holds the install lease.
/// A staged copy is inspected; source changes cannot create a mismatched identity.
pub fn retain(source: &Path, directory: &Path) -> Result<ArchiveIdentity, Failure> {
    fs::create_dir_all(directory).map_err(|_| Failure::ArchiveMissing)?;
    let staging = directory.join("archive.pending");
    let result = (|| {
        let mut input = File::open(source).map_err(|_| Failure::ArchiveMissing)?;
        let mut output = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&staging)
            .map_err(|_| Failure::ArchiveMissing)?;
        std::io::copy(&mut input, &mut output).map_err(|_| Failure::ArchiveMissing)?;
        output.flush().map_err(|_| Failure::ArchiveMissing)?;
        output.sync_all().map_err(|_| Failure::ArchiveMissing)?;
        drop(output);
        let identity = inspect(&staging)?;
        let target = identity.path(directory)?;
        if target.exists() {
            identity.verify(directory)?;
        } else {
            fs::rename(&staging, target).map_err(|_| Failure::ArchiveMissing)?;
        }
        Ok(identity)
    })();
    let _ = fs::remove_file(&staging);
    result
}

pub(crate) fn inspect(path: &Path) -> Result<ArchiveIdentity, Failure> {
    let mut file = File::open(path).map_err(|_| Failure::ArchiveMissing)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| Failure::ArchiveMissing)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    file.rewind().map_err(|_| Failure::ArchiveMissing)?;
    let mut archive = ZipArchive::new(file).map_err(|_| Failure::ArchiveChanged)?;
    let mut bundles = Vec::new();
    let mut main_count = 0;
    let mut has_watch = false;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| Failure::ArchiveChanged)?;
        let name = entry.name().to_string();
        // Inspect identities without extracting any archive entries.
        let parts: Vec<_> = name.split('/').collect();
        if parts.first() != Some(&"Payload") || parts.last() != Some(&"Info.plist") {
            continue;
        }
        if parts.len() < 3 {
            continue;
        }
        let container = parts[parts.len() - 2];
        if !container.ends_with(".app") && !container.ends_with(".appex") {
            continue;
        }
        if parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == ".." || part.contains('\\'))
        {
            return Err(Failure::ArchiveChanged);
        }
        if entry.size() > 4 * 1024 * 1024 {
            return Err(Failure::ArchiveChanged);
        }
        let mut bytes = Vec::new();
        entry
            .by_ref()
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::ArchiveChanged)?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(Failure::ArchiveChanged);
        }
        let info = plist::Value::from_reader(std::io::Cursor::new(bytes))
            .map_err(|_| Failure::ArchiveChanged)?;
        let id = info
            .as_dictionary()
            .and_then(|d| d.get("CFBundleIdentifier"))
            .and_then(plist::Value::as_string)
            .filter(|id| !id.is_empty())
            .ok_or(Failure::ArchiveChanged)?
            .to_owned();
        if parts.len() == 3 && container.ends_with(".app") {
            main_count += 1;
        }
        has_watch |= parts.contains(&"Watch");
        bundles.push((name, id));
    }
    if main_count != 1 {
        return Err(Failure::ArchiveChanged);
    }
    bundles.sort();
    if bundles.windows(2).any(|items| items[0].0 == items[1].0) {
        return Err(Failure::ArchiveChanged);
    }
    Ok(ArchiveIdentity {
        sha256,
        bundles,
        has_watch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zip::{ZipWriter, write::SimpleFileOptions};

    #[test]
    fn retained_original_survives_source_move_and_detects_changed_or_missing_copy() {
        let root =
            std::env::temp_dir().join(format!("iloader-archive-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("test.ipa");
        let mut zip = ZipWriter::new(File::create(&source).unwrap());
        for (path, id) in [
            ("Payload/Test.app/Info.plist", "test.app"),
            (
                "Payload/Test.app/Watch/Test.app/Info.plist",
                "test.app.watch",
            ),
        ] {
            zip.start_file(path, SimpleFileOptions::default()).unwrap();
            write!(zip, "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{id}</string></dict></plist>").unwrap();
        }
        zip.finish().unwrap();
        let retained = root.join("retained");
        let identity = retain(&source, &retained).unwrap();
        assert!(identity.has_watch);
        assert_eq!(identity.bundles.len(), 2);
        fs::remove_file(source).unwrap();
        let target = identity.verify(&retained).unwrap();
        fs::write(&target, b"changed IPA").unwrap();
        assert_eq!(identity.verify(&retained), Err(Failure::ArchiveChanged));
        fs::remove_file(target).unwrap();
        assert_eq!(identity.verify(&retained), Err(Failure::ArchiveMissing));
        fs::remove_dir(&retained).unwrap();
        fs::remove_dir(&root).unwrap();
    }
}
