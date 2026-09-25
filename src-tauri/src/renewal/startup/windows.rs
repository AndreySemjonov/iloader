//! The only real registry boundary. Never invoked by offline tests.
use super::{Registry, Value};
use winreg::{
    RegKey,
    enums::{HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ},
};
const KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const NAME: &str = "iLoaderRenewal";
pub(crate) struct NativeRegistry;
fn read_key(key: &RegKey) -> Result<Option<Value>, String> {
    let raw = match key.get_raw_value(NAME) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Unable to read Windows startup registration".into()),
    };
    Ok(Some(decode(raw)))
}
fn decode(raw: winreg::RegValue) -> Value {
    // Exact REG_SZ bytes only. Do not normalize malformed/expandable values into ownership.
    if raw.vtype != REG_SZ || raw.bytes.len() % 2 != 0 {
        return Value::Other;
    }
    let units = raw
        .bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
        return Value::Other;
    }
    match String::from_utf16(&units[..units.len() - 1]) {
        Ok(command) => Value::Command(command),
        Err(_) => Value::Other,
    }
}
impl Registry for NativeRegistry {
    fn read(&mut self) -> Result<Option<Value>, String> {
        match RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(KEY, KEY_QUERY_VALUE) {
            Ok(key) => read_key(&key),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("Unable to read Windows startup registration".into()),
        }
    }
    fn replace(&mut self, expected: Option<&Value>, next: Option<&str>) -> Result<(), String> {
        if self.read()?.as_ref() != expected {
            return Err(
                "Windows startup changed during this action; nothing was overwritten.".into(),
            );
        }
        let key = match RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(KEY, KEY_QUERY_VALUE | KEY_SET_VALUE)
        {
            Ok(key) => key,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && next.is_some() => {
                RegKey::predef(HKEY_CURRENT_USER)
                    .create_subkey_with_flags(KEY, KEY_QUERY_VALUE | KEY_SET_VALUE)
                    .map_err(|_| "Unable to create the Windows startup entry")?
                    .0
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && next.is_none() => return Ok(()),
            Err(_) => {
                return Err(
                    "Unable to change Windows startup. Check your Windows account permissions."
                        .into(),
                );
            }
        };
        // Recheck the same opened key immediately before changing the exact owned value.
        if read_key(&key)?.as_ref() != expected {
            return Err(
                "Windows startup changed during this action; nothing was overwritten.".into(),
            );
        }
        match next {
            Some(command) => key
                .set_value(NAME, &command)
                .map_err(|_| "Unable to register Windows startup")?,
            None => key
                .delete_value(NAME)
                .map_err(|_| "Unable to remove Windows startup registration")?,
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winreg::{enums::REG_EXPAND_SZ, types::ToRegValue};
    #[test]
    fn only_exact_well_formed_sz_can_match_owned_registration() {
        let command = r#""C:\Test & Tools\iloader.exe" --renewal-startup"#;
        assert_eq!(decode(command.to_reg_value()), Value::Command(command.into()));
        assert_eq!(
            decode(winreg::RegValue {
                vtype: REG_EXPAND_SZ,
                ..command.to_reg_value()
            }),
            Value::Other
        );
        for bytes in [
            vec![],
            vec![0],
            vec![65, 0],
            vec![0, 216, 0, 0],
            vec![65, 0, 0, 0, 66, 0, 0, 0],
        ] {
            assert_eq!(
                decode(winreg::RegValue {
                    bytes,
                    vtype: REG_SZ
                }),
                Value::Other
            );
        }
    }
}
