//! Run, RunOnce and RunOnceEx: programs Windows starts at boot or logon, machine-wide and per user.
//!
//! Every value of a `Run`/`RunOnce` key (and of `Policies\Explorer\Run`, and their `Wow6432Node`
//! twins) is one autostart entry: its name is a label, its data the command line. `RunOnceEx` keeps
//! its entries one level down, in numbered subkeys. A value has no time of its own; the key's
//! last-write time only says when *something* in the key last changed.

use std::collections::BTreeMap;

use forensic_rs::{dictionary, prelude::*};

use crate::locate::locate_keys;

/// The ForensicArtifacts definition of the Run keys, which this parser reads.
pub const DEFINITION: &str = "WindowsRunKeys";

/// The definition's keys, for a run with no artifact catalog.
const BUILTIN_PATTERNS: [&str; 20] = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\*",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\*",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup\*",
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\*",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\*",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\*",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup\*",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx\*",
    r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*",
    r"HKU\*\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*",
    r"HKU\*\Software\Microsoft\Windows\CurrentVersion\Run\*",
    r"HKU\*\Software\Microsoft\Windows\CurrentVersion\RunOnce\*",
    r"HKU\*\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup\*",
    r"HKU\*\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\*",
    r"HKU\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*",
    r"HKU\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run\*",
    r"HKU\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\*",
    r"HKU\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce\Setup\*",
    r"HKU\*\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx\*",
];

/// One autostart entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunEntry {
    /// The key the value is in, as matched (`HKEY_LOCAL_MACHINE\...` or `HKU\<sid>\...`).
    pub key: String,
    /// SID of the user whose hive holds the key; `None` for a machine key.
    pub user_sid: Option<String>,
    /// The value's name, as stored: a label, not necessarily the program.
    pub name: String,
    /// The value's data as stored.
    pub data: RegValue,
    /// Last-write time of the key, when the backend provides it.
    pub key_last_write: Option<ForensicTimestamp>,
}

impl RunEntry {
    /// The command line, when the data is a string (`REG_SZ` or `REG_EXPAND_SZ`, unexpanded).
    pub fn command_line(&self) -> Option<&str> {
        match &self.data {
            RegValue::SZ(s) | RegValue::ExpandSZ(s) => Some(s),
            _ => None,
        }
    }

    /// Whether the entry runs once (`RunOnce`, `RunOnceEx`) rather than at every boot or logon.
    pub fn once(&self) -> bool {
        self.key
            .split('\\')
            .any(|s| s.eq_ignore_ascii_case("RunOnce") || s.eq_ignore_ascii_case("RunOnceEx"))
    }

    /// Whether the key is a 32-bit view (`Wow6432Node`).
    pub fn wow64(&self) -> bool {
        self.key
            .split('\\')
            .any(|s| s.eq_ignore_ascii_case("Wow6432Node"))
    }
}

/// The SID a `HKU\<sid>\...` (or `HKEY_USERS\...`) path is under.
fn sid_of(key: &str) -> Option<String> {
    let mut segments = key.split('\\');
    let hive = segments.next()?;
    (hive.eq_ignore_ascii_case("HKU") || hive.eq_ignore_ascii_case("HKEY_USERS"))
        .then(|| segments.next().map(str::to_string))
        .flatten()
}

/// Reads every value of the key at `key`. A missing key is nothing; one that can't be read is one
/// `Err` item.
pub fn read_key(registry: &dyn Registry, key: &str) -> Vec<ForensicResult<RunEntry>> {
    let opened = match registry.key(key) {
        Ok(opened) => opened,
        Err(e) if e.is_registry_not_found() => return Vec::new(),
        Err(e) => return vec![Err(e)],
    };
    let mut out = Vec::new();
    let key_last_write = match opened.info() {
        Ok(info) => info.last_write_time,
        Err(e) => {
            out.push(Err(e));
            None
        }
    };
    match opened.values() {
        Ok(values) => out.extend(values.into_iter().map(|(name, data)| {
            Ok(RunEntry {
                key: key.to_string(),
                user_sid: sid_of(key),
                name,
                data,
                key_last_write,
            })
        })),
        Err(e) => out.push(Err(e)),
    }
    out
}

/// [`ArtifactParserFactory`] emitting one [`ForensicData`] per [`RunEntry`].
pub struct RunKeysParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for RunKeysParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.registry.run_keys",
                "Run keys",
                "Autostart entries of the Run, RunOnce and RunOnceEx keys, machine-wide and per \
                 user",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![RegistryArtifacts::AutoRuns.into()])
            .with_requirements(vec![Requirement::Artifact(ArtifactRef::from_static(
                DEFINITION,
            ))]),
        }
    }
}

impl RunKeysParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for RunKeysParserFactory {
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
                CompactString::const_new("RunKeysParserFactory"),
            )
        })?;
        let located = locate_keys(ctx, registry.as_ref(), DEFINITION, &BUILTIN_PATTERNS);
        let definition = located.by_catalog.then_some(DEFINITION);
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let live = (acquisition == Acquisition::LiveApi).then(|| {
            ctx.register_source(SourceKey::Live {
                host: host.clone(),
                api: "Registry".into(),
            })
        });
        let mut out: Vec<ForensicResult<ForensicData>> =
            located.errors.into_iter().map(Err).collect();
        let mut sources: BTreeMap<String, SourceHandle> = BTreeMap::new();
        // Both the keys a `\*` matched (RunOnceEx's numbered entries) and the keys it is under
        // (Run's own values): the definition names both.
        for key in located.keys {
            let source = sources
                .entry(key.path.clone())
                .or_insert_with(|| match &live {
                    Some(live) => live.clone(),
                    None => ctx.register_source(SourceKey::Path(key.path.clone())),
                })
                .clone();
            for entry in read_key(registry.as_ref(), &key.path) {
                out.push(entry.map(|mut entry| {
                    // A `%%users.sid%%` expansion knows the user even under an unusual hive name.
                    if entry.user_sid.is_none() {
                        entry.user_sid = key.sid.clone();
                    }
                    let provenance = source.mint(acquisition, Recovery::Allocated);
                    to_forensic_data(&host, provenance, definition, entry)
                }));
            }
        }
        Ok(ParserRun::pull(out.into_iter()))
    }
}

fn to_forensic_data(
    host: &str,
    provenance: ProvenanceId,
    definition: Option<&'static str>,
    entry: RunEntry,
) -> ForensicData {
    let mut data = ForensicData::new(host, RegistryArtifacts::AutoRuns.into(), provenance);
    if let Some(sid) = &entry.user_sid {
        data.set(dictionary::USER_ID, sid.clone());
    }
    data.set(dictionary::EVENT_ACTION, "autostart-entry");
    if let Some(command) = entry.command_line() {
        // Unexpanded: `%LOCALAPPDATA%` stays as written.
        data.set(dictionary::PROCESS_COMMAND_LINE, command.to_string());
    }
    data.set("run_keys.once", u64::from(entry.once()));
    data.set("run_keys.wow64", u64::from(entry.wow64()));
    let (_, key) = entry
        .key
        .split_once('\\')
        .unwrap_or(("", entry.key.as_str()));
    data.set(dictionary::REGISTRY_KEY, key.to_string());
    data.set(
        dictionary::REGISTRY_PATH,
        format!("{}\\{}", entry.key, entry.name),
    );
    data.set(dictionary::REGISTRY_VALUE, entry.name.clone());
    data.set(
        dictionary::REGISTRY_DATA_TYPE,
        entry.data.value_type().name().into_owned(),
    );
    if entry.command_line().is_none() {
        // Not a string: kept as stored, for whoever put a non-string here.
        data.set("run_keys.data", format!("{:?}", entry.data));
    }
    if let Some(ts) = entry.key_last_write {
        data.set(dictionary::REGISTRY_KEY_LAST_WRITE, ts);
    }
    if let Some(definition) = definition {
        data.set(dictionary::ARTIFACT_DEFINITION, definition);
    }
    data
}
