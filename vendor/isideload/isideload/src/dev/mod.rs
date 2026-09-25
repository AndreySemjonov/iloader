pub mod app_groups;
pub mod app_ids;
pub mod certificates;
pub mod developer_session;
pub mod device_type;
pub mod devices;
pub mod teams;

// Some non-alphanumeric characters cause Developer error 35:
// An invalid value was provided for the parameter 'appIdName'.
pub fn normalize_app_names(name: &str) -> String {
    let normalized: String = name.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if normalized.is_empty() {
        "App".to_string()
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_app_names;

    #[test]
    fn app_names_keep_only_ascii_alphanumerics_and_are_never_empty() {
        assert_eq!(normalize_app_names("X6 Remote"), "X6Remote");
        assert_eq!(normalize_app_names("Café-App!"), "CafApp");
        assert_eq!(normalize_app_names("✨ ✨"), "App");
    }
}
