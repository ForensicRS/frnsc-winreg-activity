//! Shared per-user plumbing: walking `HKU\<sid>` hives and optional subkey paths.

use std::collections::BTreeSet;

use forensic_rs::{
    core::UserEnvVars,
    prelude::*,
    traits::registry::extra::env_vars::{EnvVarsReport, get_env_vars_of_users_report},
};

pub(crate) type UserKey<'r> = RegKey<'r, dyn Registry + 'r>;

/// What [`for_each_user`] calls per user: the SID, the user's hive key and environment.
pub(crate) type UserVisitor<'f, 'r> =
    dyn for<'k, 'e> FnMut(&str, RegKey<'k, dyn Registry + 'r>, &UserEnv<'e>) + 'f;

/// One user's environment: the variables, and which of them were assumed (a Windows default)
/// rather than read from the registry.
pub(crate) struct UserEnv<'a> {
    pub vars: &'a UserEnvVars,
    pub assumed: BTreeSet<&'a str>,
}

impl<'a> UserEnv<'a> {
    fn of(report: &'a EnvVarsReport, sid: &str, no_vars: &'a UserEnvVars) -> Self {
        let mut assumed: BTreeSet<&str> = report
            .fallbacks
            .iter()
            .filter(|f| f.sid.as_deref().is_none_or(|s| s == sid))
            .map(|f| f.var.as_str())
            .collect();
        // `windir` is SystemRoot under another name.
        if assumed.contains("SystemRoot") {
            assumed.insert("windir");
        }
        Self {
            vars: report.vars.get(sid).unwrap_or(no_vars),
            assumed,
        }
    }
}

/// Calls `f` once per user hive under `HKU` (SIDs only, `_Classes` hives skipped), in SID
/// order, through [`RegistryExt::for_each_user_hive`]: a user that cannot be opened goes to
/// `on_error` and the others are still read. Failures while resolving the users' environment
/// go to `on_error` too.
pub(crate) fn for_each_user<'r>(
    reg: &'r (dyn Registry + 'r),
    on_error: &mut dyn FnMut(ForensicError),
    f: &mut UserVisitor<'_, 'r>,
) -> ForensicResult<()> {
    let mut report = get_env_vars_of_users_report(reg).unwrap_or_else(|e| {
        // Without ProfileList we can still read every hive; {GUID} paths just stay unresolved.
        on_error(e);
        EnvVarsReport::default()
    });
    for e in std::mem::take(&mut report.errors) {
        on_error(e);
    }
    let no_vars = UserEnvVars::new();
    let mut user_errors = Vec::new();
    reg.for_each_user_hive(
        &mut |sid, user_key| {
            f(sid, user_key, &UserEnv::of(&report, sid, &no_vars));
            Ok(())
        },
        &mut |_sid, e| user_errors.push(e),
    )?;
    for e in user_errors {
        on_error(e);
    }
    Ok(())
}

/// Opens `path` (`\`-separated) below `key`, returning `Ok(None)` when any component doesn't
/// exist; any other failure is returned. Absence is detected by listing subkeys rather than by
/// matching on the open error, because frnsc-liveregistry-rs still reports a missing key as
/// `missing_data`. Switch to `open_child` plus `ForensicError::is_registry_not_found()` once it
/// returns `RegistryError::KeyNotFound` like the other backends.
pub(crate) fn open_existing<'r>(
    key: &UserKey<'r>,
    path: &str,
) -> ForensicResult<Option<UserKey<'r>>> {
    let mut current: Option<UserKey<'r>> = None;
    for component in path.split('\\').filter(|c| !c.is_empty()) {
        let parent = current.as_ref().unwrap_or(key);
        let Some(entry) = parent
            .keys()?
            .into_iter()
            .find(|entry| entry.name.eq_ignore_ascii_case(component))
        else {
            return Ok(None);
        };
        current = Some(parent.open_child(&entry.name)?);
    }
    Ok(current)
}
