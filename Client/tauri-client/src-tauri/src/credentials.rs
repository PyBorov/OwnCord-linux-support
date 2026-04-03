use serde::Serialize;

/// Data returned from `load_credential`.
#[derive(Serialize, Clone)]
pub struct CredentialData {
    pub username: String,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl std::fmt::Debug for CredentialData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialData")
        .field("username", &self.username)
        .field("token", &"[REDACTED]")
        .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
        .finish()
    }
}

// ===========================================================================
// Windows — Windows Credential Manager (DPAPI)
// ===========================================================================

#[cfg(windows)]
mod platform {
    use super::CredentialData;
    use std::ptr;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::ERROR_NOT_FOUND;
    use windows::Win32::Security::Credentials::{
        CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_FLAGS,
        CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    fn target_name(host: &str) -> Vec<u16> {
        let name = format!("OwnCord/{host}");
        name.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn save(
        host: &str,
        username: &str,
        token: &str,
        password: Option<&str>,
    ) -> Result<(), String> {
        let target = target_name(host);
        let wide_user = to_wide(username);

        let mut payload = serde_json::json!({
            "username": username,
            "token": token,
        });
        if let Some(pw) = password {
            payload["password"] = serde_json::Value::String(pw.to_string());
        }
        let blob = payload.to_string().into_bytes();

        let mut cred = CREDENTIALW {
            Flags: CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target.as_ptr() as *mut u16),
            Comment: PWSTR::null(),
            LastWritten: Default::default(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_ptr() as *mut u8,
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: ptr::null_mut(),
            TargetAlias: PWSTR::null(),
            UserName: PWSTR(wide_user.as_ptr() as *mut u16),
        };

        unsafe {
            CredWriteW(&mut cred, 0).map_err(|e| format!("CredWriteW failed: {e}"))?;
        }
        Ok(())
    }

    pub fn load(host: &str) -> Result<Option<CredentialData>, String> {
        let target = target_name(host);
        let mut pcred: *mut CREDENTIALW = ptr::null_mut();

        let read_result =
        unsafe { CredReadW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0, &mut pcred) };

        match read_result {
            Ok(()) => {}
            Err(e) => {
                if e.code() == ERROR_NOT_FOUND.to_hresult() {
                    return Ok(None);
                }
                return Err(format!("CredReadW failed: {e}"));
            }
        }

        let blob = unsafe {
            let cred = &*pcred;
            let bytes = std::slice::from_raw_parts(
                cred.CredentialBlob,
                cred.CredentialBlobSize as usize,
            )
            .to_vec();
            CredFree(pcred as *const std::ffi::c_void);
            bytes
        };

        parse_blob(blob)
    }

    pub fn delete(host: &str) -> Result<(), String> {
        let target = target_name(host);
        let result = unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, 0) };

        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                if e.code() == ERROR_NOT_FOUND.to_hresult() {
                    return Ok(());
                }
                Err(format!("CredDeleteW failed: {e}"))
            }
        }
    }

    fn parse_blob(blob: Vec<u8>) -> Result<Option<CredentialData>, String> {
        let json_str = String::from_utf8(blob)
        .map_err(|e| format!("credential blob is not valid UTF-8: {e}"))?;
        let parsed: serde_json::Value =
        serde_json::from_str(&json_str).map_err(|e| format!("credential blob is not valid JSON: {e}"))?;

        let username = parsed
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or("credential blob missing 'username' field")?
        .to_string();
        let token = parsed
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or("credential blob missing 'token' field")?
        .to_string();
        let password = parsed
        .get("password")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

        Ok(Some(CredentialData { username, token, password }))
    }

    // Юнит-тесты для Windows-специфичных хелперов
    #[cfg(test)]
    pub mod tests {
        use super::*;

        #[test]
        fn target_name_encodes_host_as_utf16() {
            let result = target_name("localhost:8443");
            let expected: Vec<u16> = "OwnCord/localhost:8443"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
            assert_eq!(result, expected);
        }

        #[test]
        fn target_name_empty_host() {
            let result = target_name("");
            let expected: Vec<u16> = "OwnCord/"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
            assert_eq!(result, expected);
        }

        #[test]
        fn to_wide_ascii() {
            let result = to_wide("hello");
            let expected: Vec<u16> = "hello"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
            assert_eq!(result, expected);
            assert_eq!(*result.last().unwrap(), 0u16);
        }

        #[test]
        fn to_wide_empty_string() {
            let result = to_wide("");
            assert_eq!(result, vec![0u16]);
        }

        #[test]
        fn to_wide_unicode() {
            let result = to_wide("日本語");
            assert_eq!(*result.last().unwrap(), 0u16);
            assert_eq!(result.len(), 4);
        }
    }
}

// ===========================================================================
// Linux / macOS — keyring (libsecret / KWallet / macOS Keychain)
// ===========================================================================

#[cfg(not(windows))]
mod platform {
    use super::CredentialData;
    use keyring::Entry;

    /// service = "owncord", account = host
    /// Значение: JSON {"username":"...","token":"...","password":"..."}
    fn entry(host: &str) -> Result<Entry, String> {
        Entry::new("owncord", host).map_err(|e| format!("keyring entry error: {e}"))
    }

    pub fn save(
        host: &str,
        username: &str,
        token: &str,
        password: Option<&str>,
    ) -> Result<(), String> {
        let mut payload = serde_json::json!({
            "username": username,
            "token": token,
        });
        if let Some(pw) = password {
            payload["password"] = serde_json::Value::String(pw.to_string());
        }

        entry(host)?
        .set_password(&payload.to_string())
        .map_err(|e| format!("keyring save failed: {e}"))
    }

    pub fn load(host: &str) -> Result<Option<CredentialData>, String> {
        let e = entry(host)?;
        let raw = match e.get_password() {
            Ok(s) => s,
            Err(keyring::Error::NoEntry) => return Ok(None),
            Err(e) => return Err(format!("keyring load failed: {e}")),
        };

        let parsed: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("credential is not valid JSON: {e}"))?;

        let username = parsed
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or("credential missing 'username'")?
        .to_string();
        let token = parsed
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or("credential missing 'token'")?
        .to_string();
        let password = parsed
        .get("password")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

        Ok(Some(CredentialData { username, token, password }))
    }

    pub fn delete(host: &str) -> Result<(), String> {
        match entry(host)?.delete_password() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // уже нет — не ошибка
            Err(e) => Err(format!("keyring delete failed: {e}")),
        }
    }
}

// ===========================================================================
// Tauri commands — одинаковый публичный интерфейс на всех платформах
// ===========================================================================

#[tauri::command]
pub fn save_credential(
    host: String,
    username: String,
    token: String,
    password: Option<String>,
) -> Result<(), String> {
    if host.is_empty() {
        return Err("host must not be empty".into());
    }
    if token.is_empty() {
        return Err("token must not be empty".into());
    }
    if username.is_empty() {
        return Err("username must not be empty".into());
    }
    platform::save(&host, &username, &token, password.as_deref())
}

#[tauri::command]
pub fn load_credential(host: String) -> Result<Option<CredentialData>, String> {
    if host.is_empty() {
        return Err("host must not be empty".into());
    }
    platform::load(&host)
}

#[tauri::command]
pub fn delete_credential(host: String) -> Result<(), String> {
    if host.is_empty() {
        return Err("host must not be empty".into());
    }
    platform::delete(&host)
}

// ===========================================================================
// Кроссплатформенные тесты (валидация входных данных)
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_rejects_empty_host() {
        assert!(save_credential("".into(), "user".into(), "tok".into(), None).is_err());
    }

    #[test]
    fn save_rejects_empty_token() {
        assert!(save_credential("host".into(), "user".into(), "".into(), None).is_err());
    }

    #[test]
    fn save_rejects_empty_username() {
        assert!(save_credential("host".into(), "".into(), "tok".into(), None).is_err());
    }

    #[test]
    fn delete_rejects_empty_host() {
        assert!(delete_credential("".into()).is_err());
    }

    #[test]
    fn load_rejects_empty_host() {
        assert!(load_credential("".into()).is_err());
    }
}
