//! Explorer `FeatureUsage`: per-user taskbar interaction counters (Windows 10 1903+).
//!
//! `HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage` has one subkey
//! per interaction type; each value name identifies an application and its DWORD data is a
//! counter. The counters carry no timestamp of their own: the subkey's last-write time only
//! says when *some* counter in it last changed.

use forensic_rs::{dictionary, prelude::*};

use crate::{
    app_id::AppId,
    users::{UserEnv, UserKey, for_each_user, open_existing},
};

const FEATURE_USAGE_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage";

/// Which `FeatureUsage` subkey a counter came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Counter {
    /// `AppBadgeUpdated`: times the app's taskbar badge was updated (e.g. unread notifications).
    BadgeUpdates,
    /// `AppLaunch`: times an app pinned to the taskbar was launched from it.
    Launches,
    /// `AppSwitched`: times the app was switched to by left-clicking its taskbar button.
    Switches,
    /// `ShowJumpView`: times the app's jump list was opened (right-click on its button).
    JumpViewClicks,
    /// `TrayButtonClicked`: times a built-in taskbar button (clock, Start, ...) was clicked.
    TrayClicks,
}

impl Counter {
    pub const ALL: [Counter; 5] = [
        Counter::BadgeUpdates,
        Counter::Launches,
        Counter::Switches,
        Counter::JumpViewClicks,
        Counter::TrayClicks,
    ];

    /// Name of the registry subkey holding this counter.
    pub fn subkey(self) -> &'static str {
        match self {
            Counter::BadgeUpdates => "AppBadgeUpdated",
            Counter::Launches => "AppLaunch",
            Counter::Switches => "AppSwitched",
            Counter::JumpViewClicks => "ShowJumpView",
            Counter::TrayClicks => "TrayButtonClicked",
        }
    }
}

/// One counter value for one application of one user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureUsageEntry {
    /// SID of the user whose hive holds the value.
    pub user_sid: String,
    pub counter: Counter,
    /// Registry value name exactly as stored.
    pub raw_name: String,
    /// `raw_name` classified and, for paths, resolved against the user's environment.
    pub app: AppId,
    pub count: u32,
    /// Last-write time of the counter's subkey, when the backend provides it. Applies to the
    /// whole subkey, not to this application.
    pub key_last_write: Option<ForensicTimestamp>,
    /// Environment variables an [`AppId::Executable`] path was resolved through that the
    /// registry didn't provide, so a Windows default was used (`windir` = `C:\Windows`, ...).
    /// Empty when every variable was read.
    pub assumed_vars: Vec<String>,
}

/// Reads the `FeatureUsage` counters of every user hive under `HKU`.
///
/// Records come out ordered by SID, then counter, then value order in the key. A value that
/// can't be read or isn't a DWORD, or a user or subkey that can't be opened, becomes one `Err`
/// item and reading continues. Users or subkeys that simply don't exist produce nothing.
pub fn read_feature_usage(reg: &dyn Registry) -> Vec<ForensicResult<FeatureUsageEntry>> {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    let res = for_each_user(
        reg,
        &mut |e| errors.push(Err(e)),
        &mut |sid, user_key, env| read_user(sid, &user_key, env, &mut out),
    );
    if let Err(e) = res {
        out.push(Err(e));
    }
    // Setup errors (ProfileList, unopenable users) first, so they're not buried at the end.
    errors.extend(out);
    errors
}

fn read_user<'r>(
    sid: &str,
    user_key: &UserKey<'r>,
    env: &UserEnv<'_>,
    out: &mut Vec<ForensicResult<FeatureUsageEntry>>,
) {
    let feature_usage = match open_existing(user_key, FEATURE_USAGE_PATH) {
        Ok(Some(key)) => key,
        Ok(None) => {
            debug!("HKU\\{sid}\\{FEATURE_USAGE_PATH} not present");
            return;
        }
        Err(e) => {
            out.push(Err(e));
            return;
        }
    };
    for counter in Counter::ALL {
        let key = match open_existing(&feature_usage, counter.subkey()) {
            Ok(Some(key)) => key,
            Ok(None) => continue,
            Err(e) => {
                out.push(Err(e));
                continue;
            }
        };
        // The counters are still read without the key's timestamp; the failure is its own item.
        let key_last_write = match key.info() {
            Ok(info) => info.last_write_time,
            Err(e) => {
                out.push(Err(e));
                None
            }
        };
        let values = match key.values() {
            Ok(values) => values,
            Err(e) => {
                out.push(Err(e));
                continue;
            }
        };
        for (raw_name, value) in values {
            // The unnamed default value isn't a counter.
            if raw_name.is_empty() {
                continue;
            }
            let count = match value.as_dword() {
                Some(count) => count,
                None => {
                    out.push(Err(ForensicError::registry_invalid_type(
                        "REG_DWORD",
                        format!(
                            r"{value:?} in HKU\{sid}\{FEATURE_USAGE_PATH}\{}\{raw_name}",
                            counter.subkey()
                        ),
                    )));
                    continue;
                }
            };
            let app = AppId::classify(&raw_name, env.vars);
            let assumed_vars = match app {
                AppId::Executable(_) => AppId::csidl_vars(&raw_name, env.vars)
                    .into_iter()
                    .filter(|var| env.assumed.contains(var.as_str()))
                    .collect(),
                _ => Vec::new(),
            };
            out.push(Ok(FeatureUsageEntry {
                user_sid: sid.to_string(),
                counter,
                app,
                raw_name,
                count,
                key_last_write,
                assumed_vars,
            }));
        }
    }
}

/// [`ArtifactParserFactory`] emitting one [`ForensicData`] per [`FeatureUsageEntry`].
pub struct FeatureUsageParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for FeatureUsageParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.registry.feature_usage",
                "Taskbar FeatureUsage",
                "Per-user taskbar interaction counters from Explorer\\FeatureUsage",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![RegistryArtifacts::FeatureUsage.into()])
            .with_requirements(vec![Requirement::Registry(KeySpec::new(format!(
                r"HKU\*\{FEATURE_USAGE_PATH}"
            )))]),
        }
    }
}

impl FeatureUsageParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for FeatureUsageParserFactory {
    fn descriptor(&self) -> &ParserDescriptor {
        &self.descriptor
    }

    fn can_parse(&self, ctx: &ParseContext<'_>) -> bool {
        ctx.registry().is_some()
    }

    fn open(&self, ctx: &ParseContext<'_>) -> ForensicResult<ParserRun> {
        let registry = ctx.registry().ok_or_else(|| {
            ForensicError::missing_data(
                "Registry source required",
                CompactString::const_new("FeatureUsageParserFactory"),
            )
        })?;
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let source = match acquisition {
            Acquisition::LiveApi => SourceKey::Live {
                host: host.clone(),
                api: "Registry".into(),
            },
            _ => SourceKey::Path(format!(r"HKU\*\{FEATURE_USAGE_PATH}")),
        };
        let source = ctx.register_source(source);
        let entries = read_feature_usage(registry.as_ref());
        Ok(ParserRun::pull(entries.into_iter().map(move |entry| {
            entry.map(|entry| {
                let provenance = source.mint(acquisition, Recovery::Allocated);
                to_forensic_data(&host, provenance, entry)
            })
        })))
    }
}

fn to_forensic_data(
    host: &str,
    provenance: ProvenanceId,
    entry: FeatureUsageEntry,
) -> ForensicData {
    let mut data = ForensicData::new(host, RegistryArtifacts::FeatureUsage.into(), provenance);
    data.set(dictionary::USER_ID, entry.user_sid);
    data.set(
        dictionary::EVENT_ACTION,
        format!("taskbar-{}", entry.counter.subkey()),
    );
    data.set("feature_usage.counter", entry.counter.subkey());
    data.set("feature_usage.count", entry.count);
    data.set("registry.value", entry.raw_name);
    data.set("feature_usage.app.kind", entry.app.kind());
    match entry.app {
        AppId::Executable(path) => data.set(dictionary::PROCESS_EXECUTABLE, path),
        AppId::Aumid(aumid) => data.set("windows.aumid", aumid),
        AppId::Process(pid) => data.set("process.pid", pid),
        // The raw value name above already carries these verbatim.
        AppId::UnresolvedCsidl(_) | AppId::MalformedPid(_) => {}
    }
    if let Some(ts) = entry.key_last_write {
        data.set("registry.key.last_write", ts);
    }
    if !entry.assumed_vars.is_empty() {
        data.insert(
            Text::Borrowed("feature_usage.app.assumed_vars"),
            Field::Array(entry.assumed_vars.into_iter().map(Text::Owned).collect()),
        );
    }
    data
}
