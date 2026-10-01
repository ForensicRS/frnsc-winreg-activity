//! Background and Desktop Activity Moderator (BAM/DAM): when each executable last ran, per user.
//!
//! `HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<sid>` (Windows 10 1809+; plain
//! `bam\UserSettings\<sid>` on 1709-1803, and the same under `dam`) has one value per executable.
//! The value's name is the executable, as a device path (`\Device\HarddiskVolume3\...\cmd.exe`) or
//! a packaged app's family name; its `REG_BINARY` data starts with the `FILETIME` of the last run.
//! `Version` and `SequenceNumber` are the key's own bookkeeping, not executables.
//!
//! BAM keeps roughly a week of entries and only for programs run while the service was active, so
//! an absent entry says nothing about whether a program ran.

use std::collections::BTreeMap;

use forensic_rs::{dictionary, prelude::*};

use crate::locate::locate_keys;

/// The ForensicArtifacts definition of the BAM and DAM keys, which this parser reads.
pub const DEFINITION: &str = "WindowsBackgroundActivityModeratorKeys";

/// The definition's keys, for a run with no artifact catalog.
const BUILTIN_PATTERNS: [&str; 4] = [
    r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*",
    r"HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*",
    r"HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings\*",
    r"HKLM\SYSTEM\CurrentControlSet\Services\dam\UserSettings\*",
];

/// Values of a user's key that describe the key, not an executable.
const BOOKKEEPING: [&str; 2] = ["Version", "SequenceNumber"];

/// Which moderator recorded an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Moderator {
    /// Background Activity Moderator (`bam`): desktop programs.
    Bam,
    /// Desktop Activity Moderator (`dam`): connected-standby devices.
    Dam,
}

impl Moderator {
    pub fn as_str(self) -> &'static str {
        match self {
            Moderator::Bam => "bam",
            Moderator::Dam => "dam",
        }
    }

    /// The moderator a key path is under, from its `Services\<bam|dam>` segment.
    fn of(path: &str) -> Option<Moderator> {
        let mut segments = path.split('\\');
        segments.find(|s| s.eq_ignore_ascii_case("Services"))?;
        match segments.next()?.to_ascii_lowercase().as_str() {
            "bam" => Some(Moderator::Bam),
            "dam" => Some(Moderator::Dam),
            _ => None,
        }
    }
}

/// One executable's last run, for one user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BamEntry {
    pub moderator: Moderator,
    /// SID of the user, from the name of the key the value is in.
    pub user_sid: String,
    /// The key the value is in.
    pub key: String,
    /// The value's name, as stored: a device path or a packaged app's family name.
    pub executable: String,
    /// The `FILETIME` the data starts with, as stored.
    pub last_run_raw: u64,
    /// `last_run_raw` as a time; `None` when it is zero (never a made-up date).
    pub last_run: Option<ForensicTimestamp>,
    /// The value's whole data, as stored.
    pub data: Vec<u8>,
}

/// Reads one user's BAM/DAM key: one entry per executable value. A value whose data is not a
/// `REG_BINARY` of at least 8 bytes is one `Err` item, and reading goes on.
pub fn read_user_key(registry: &dyn Registry, key: &str) -> Vec<ForensicResult<BamEntry>> {
    let Some(moderator) = Moderator::of(key) else {
        return vec![Err(ForensicError::other(
            "bam",
            format!("{key} is not under Services\\bam or Services\\dam"),
        ))];
    };
    let user_sid = key.rsplit('\\').next().unwrap_or_default().to_string();
    let values = match registry.key(key).and_then(|k| k.values()) {
        Ok(values) => values,
        Err(e) if e.is_registry_not_found() => return Vec::new(),
        Err(e) => return vec![Err(e)],
    };
    values
        .into_iter()
        .filter(|(name, _)| {
            !name.is_empty() && !BOOKKEEPING.iter().any(|b| b.eq_ignore_ascii_case(name))
        })
        .map(|(name, value)| {
            let data = match value {
                RegValue::Binary(data) => data,
                other => {
                    return Err(ForensicError::registry_invalid_type(
                        "REG_BINARY",
                        format!(r"{other:?} in {key}\{name}"),
                    ));
                }
            };
            let Some(raw) = data.get(..8) else {
                return Err(ForensicError::other(
                    "bam",
                    format!(
                        r"{key}\{name}: {} byte(s), too short for the last-run FILETIME",
                        data.len()
                    ),
                ));
            };
            let mut filetime = [0u8; 8];
            filetime.copy_from_slice(raw);
            let last_run_raw = u64::from_le_bytes(filetime);
            Ok(BamEntry {
                moderator,
                user_sid: user_sid.clone(),
                key: key.to_string(),
                executable: name,
                last_run_raw,
                last_run: (last_run_raw != 0)
                    .then(|| ForensicTimestamp::from_win_filetime(last_run_raw)),
                data,
            })
        })
        .collect()
}

/// [`ArtifactParserFactory`] emitting one [`ForensicData`] per [`BamEntry`].
pub struct BamParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for BamParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.registry.bam",
                "BAM/DAM",
                "Last run time of each executable, per user, from the Background and Desktop \
                 Activity Moderator keys",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![RegistryArtifacts::Bam.into()])
            .with_requirements(vec![Requirement::Artifact(ArtifactRef::from_static(
                DEFINITION,
            ))]),
        }
    }
}

impl BamParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for BamParserFactory {
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
                CompactString::const_new("BamParserFactory"),
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
        // Problems first, so they're not buried after the records.
        let mut out: Vec<ForensicResult<ForensicData>> =
            located.errors.into_iter().map(Err).collect();
        let mut sources: BTreeMap<String, SourceHandle> = BTreeMap::new();
        // The per-user keys; a `\*` pattern's parent (`UserSettings` itself) holds no entries.
        for key in located.keys.into_iter().filter(|k| !k.values_of_wildcard) {
            let source = sources
                .entry(key.path.clone())
                .or_insert_with(|| match &live {
                    Some(live) => live.clone(),
                    None => ctx.register_source(SourceKey::Path(key.path.clone())),
                })
                .clone();
            for entry in read_user_key(registry.as_ref(), &key.path) {
                out.push(entry.map(|entry| {
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
    entry: BamEntry,
) -> ForensicData {
    let mut data = ForensicData::new(host, RegistryArtifacts::Bam.into(), provenance);
    data.set(dictionary::USER_ID, entry.user_sid);
    data.set(
        dictionary::EVENT_ACTION,
        format!("{}-last-run", entry.moderator.as_str()),
    );
    data.set("bam.moderator", entry.moderator.as_str());
    // As stored: a device path is not mapped to a drive letter here.
    data.set(dictionary::PROCESS_EXECUTABLE, entry.executable.clone());
    let (_, key) = entry
        .key
        .split_once('\\')
        .unwrap_or(("", entry.key.as_str()));
    data.set(dictionary::REGISTRY_KEY, key.to_string());
    data.set(
        dictionary::REGISTRY_PATH,
        format!("{}\\{}", entry.key, entry.executable),
    );
    data.set(dictionary::REGISTRY_VALUE, entry.executable);
    data.set("bam.last_run_raw", entry.last_run_raw);
    // The whole value, as stored: only its first 8 bytes are understood.
    data.set(
        "bam.data",
        entry
            .data
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    if let Some(ts) = entry.last_run {
        // The run itself, as BAM recorded it: a real event time.
        data.set(dictionary::TIMESTAMP, ts);
    }
    if let Some(definition) = definition {
        data.set(dictionary::ARTIFACT_DEFINITION, definition);
    }
    data
}
