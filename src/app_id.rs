//! Classification of the application identifiers Explorer stores as registry value names.

use forensic_rs::{
    core::UserEnvVars,
    utils::win::csidl::{csidl_value, interpolate_csidl_path},
};

/// What an application identifier found in the registry refers to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AppId {
    /// Application User Model ID (packaged apps, or apps that set one explicitly).
    Aumid(String),
    /// Executable path, with any known-folder GUID resolved against the user's environment.
    Executable(String),
    /// Path starting with a known-folder GUID that could not be resolved for this user.
    UnresolvedCsidl(String),
    /// Process that used the taskbar without an AUMID (`*PID<hex>`).
    Process(u32),
    /// Starts with `*PID` but the rest is not a valid 32-bit hex number. Kept verbatim.
    MalformedPid(String),
}

impl AppId {
    /// Classifies a raw registry value name. `env_vars` resolves `{GUID}\...` paths; pass an
    /// empty map when the user's environment is unknown and such paths stay unresolved.
    pub fn classify(raw: &str, env_vars: &UserEnvVars) -> Self {
        if let Some(hex) = raw.strip_prefix("*PID") {
            return match u32::from_str_radix(hex, 16) {
                Ok(pid) if !hex.is_empty() && !hex.starts_with('+') => Self::Process(pid),
                _ => Self::MalformedPid(raw.to_string()),
            };
        }
        if !(raw.contains('\\') || raw.contains('/')) {
            return Self::Aumid(raw.to_string());
        }
        let mut path = raw.to_string();
        match interpolate_csidl_path(&mut path, env_vars) {
            Some(resolved) => Self::Executable(resolved),
            None => Self::UnresolvedCsidl(raw.to_string()),
        }
    }

    /// The environment variables a `{GUID}\...` path was resolved through, outermost first
    /// (`%LOCALAPPDATA%`, then `%USERPROFILE%` inside it), following the same leading-`%VAR%`
    /// expansion as [`interpolate_csidl_path`]. Empty for anything that isn't a known-folder path.
    pub fn csidl_vars(raw: &str, env_vars: &UserEnvVars) -> Vec<String> {
        let mut out = Vec::new();
        let Some(end) = raw.strip_prefix('{').and_then(|r| r.find('}')) else {
            return out;
        };
        let guid = raw[..end + 2].to_ascii_uppercase();
        let mut template: Option<&str> = csidl_value(&guid);
        while let Some(rest) = template.and_then(|t| t.strip_prefix('%')) {
            let Some(var) = rest.split('%').next().filter(|v| !v.is_empty()) else {
                break;
            };
            // A self-referencing variable must not loop.
            if out.iter().any(|seen| seen == var) {
                break;
            }
            out.push(var.to_string());
            template = env_vars.get(var).map(String::as_str);
        }
        out
    }

    /// Stable, machine-readable name of the variant, used as a record field.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Aumid(_) => "aumid",
            Self::Executable(_) => "executable",
            Self::UnresolvedCsidl(_) => "unresolved_csidl",
            Self::Process(_) => "process",
            Self::MalformedPid(_) => "malformed_pid",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POWERSHELL_CSIDL: &str =
        r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";
    const POWERSHELL: &str = r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe";

    fn env_vars() -> UserEnvVars {
        let mut env_vars = UserEnvVars::new();
        env_vars.insert("APPDATA".into(), r"C:\ProgramData".into());
        env_vars.insert("LOCALAPPDATA".into(), r"%USERPROFILE%\AppData\Local".into());
        env_vars.insert("ProgramFiles".into(), r"C:\Program Files".into());
        env_vars.insert("USERPROFILE".into(), r"C:\Users\tester".into());
        env_vars.insert("windir".into(), r"C:\Windows".into());
        env_vars
    }

    #[test]
    fn classifies_known_shapes() {
        let env = env_vars();
        assert_eq!(AppId::classify("*PID00000f9c", &env), AppId::Process(3996));
        assert_eq!(
            AppId::classify("com.squirrel.Discord.Discord", &env),
            AppId::Aumid("com.squirrel.Discord.Discord".into())
        );
        assert_eq!(
            AppId::classify(POWERSHELL_CSIDL, &env),
            AppId::Executable(POWERSHELL.into())
        );
        assert_eq!(
            AppId::classify(POWERSHELL, &env),
            AppId::Executable(POWERSHELL.into())
        );
    }

    #[test]
    fn unresolvable_csidl_keeps_raw_name() {
        assert_eq!(
            AppId::classify(POWERSHELL_CSIDL, &UserEnvVars::new()),
            AppId::UnresolvedCsidl(POWERSHELL_CSIDL.into())
        );
    }

    #[test]
    fn malformed_pids_do_not_panic() {
        let env = UserEnvVars::new();
        for raw in [
            "*PID",
            "*PID123456789",
            "*PIDzz",
            "*PIDé",
            "*PID+1",
            "*PID-1",
        ] {
            assert_eq!(
                AppId::classify(raw, &env),
                AppId::MalformedPid(raw.into()),
                "{raw}"
            );
        }
        assert_eq!(
            AppId::classify("*PIDffffffff", &env),
            AppId::Process(u32::MAX)
        );
    }

    #[test]
    fn csidl_vars_follow_nested_variables() {
        let mut env = UserEnvVars::new();
        env.insert("LOCALAPPDATA".into(), r"%USERPROFILE%\AppData\Local".into());
        env.insert("USERPROFILE".into(), r"C:\Users\bob".into());
        // Lowercase GUID: matched like `interpolate_csidl_path` does.
        let raw = r"{f1b32785-6fba-4fcf-9d55-7b8e7f157091}\Programs\x.exe";
        assert_eq!(
            AppId::csidl_vars(raw, &env),
            ["LOCALAPPDATA", "USERPROFILE"]
        );
        assert!(AppId::csidl_vars(r"C:\x.exe", &env).is_empty());
        assert!(AppId::csidl_vars("{not-closed", &env).is_empty());
    }
}
