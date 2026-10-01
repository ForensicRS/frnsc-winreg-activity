//! Application Compatibility Cache (ShimCache): executables Windows checked for compatibility
//! shims, in `HKLM\SYSTEM\<control set>\Control\Session Manager\AppCompatCache\AppCompatCache`
//! (`...\AppCompatibility\AppCompatCache` on XP).
//!
//! The value is one binary blob whose layout depends on the Windows version; [`parse`] recognizes
//! XP, 2003/Vista/2008, 7/2008 R2 (32- and 64-bit), 8, 8.1 and 10/11. Entries are most recent
//! first. What an entry proves is limited and easily over-read:
//!
//! * its time is the *file's* last-modification time when it was cached, not when it ran, so it
//!   is `file.mtime`, never `@timestamp`;
//! * presence alone is not execution. Only 7 and 8.x record an "executed" insertion flag; other
//!   versions say nothing either way, and `executed` is then absent, not `false`;
//! * the cache is written at shutdown, so a live system's latest entries may not be in it yet.
//!
//! Format references: libyal winreg-kb "Application Compatibility Cache key"; Mandiant's
//! ShimCacheParser; Eric Zimmerman's AppCompatCacheParser.

use std::collections::BTreeMap;

use forensic_rs::catalog::{Os, expand};
use forensic_rs::host_profile::HostProfile;
use forensic_rs::{dictionary, prelude::*};

/// The ForensicArtifacts definition of the cache value, which this parser reads.
pub const DEFINITION: &str = "WindowsAppCompatCache";

const VALUE: &str = "AppCompatCache";
/// The definition's keys, for a run with no artifact catalog.
const BUILTIN_KEYS: [&str; 2] = [
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility",
];
/// The same keys in every control set: older ones hold older caches.
const OTHER_CONTROL_SETS: [&str; 2] = [
    r"HKLM\SYSTEM\ControlSet*\Control\Session Manager\AppCompatCache",
    r"HKLM\SYSTEM\ControlSet*\Control\Session Manager\AppCompatibility",
];

/// The cache layouts [`parse`] knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    WindowsXp,
    /// 2003, Vista and 2008 share a signature; the width is the entry size.
    Windows2003Vista32,
    Windows2003Vista64,
    Windows7_32,
    Windows7_64,
    Windows8,
    Windows81,
    Windows10,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Format::WindowsXp => "windows_xp",
            Format::Windows2003Vista32 => "windows_2003_vista_32",
            Format::Windows2003Vista64 => "windows_2003_vista_64",
            Format::Windows7_32 => "windows_7_32",
            Format::Windows7_64 => "windows_7_64",
            Format::Windows8 => "windows_8",
            Format::Windows81 => "windows_8_1",
            Format::Windows10 => "windows_10",
        }
    }
}

/// One cache entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShimEntry {
    /// 0 for the most recent entry.
    pub position: usize,
    /// The path as stored (UTF-16 decoded; an invalid sequence is replaced, and `path_lossy` set).
    pub path: String,
    pub path_lossy: bool,
    /// The file's last-modification `FILETIME` as stored.
    pub last_modified_raw: u64,
    /// `last_modified_raw` as a time; `None` when zero.
    pub last_modified: Option<ForensicTimestamp>,
    pub insertion_flags: Option<u32>,
    pub shim_flags: Option<u32>,
    /// From the insertion flags, on the versions that record it (7, 8, 8.1).
    pub executed: Option<bool>,
    /// File size, on XP.
    pub file_size: Option<u64>,
    /// The 2003/Vista entry's last 8 bytes: a file size on 2003, insertion and shim flags on
    /// Vista. The blob doesn't say which, so they're kept uninterpreted.
    pub size_or_flags: Option<u64>,
    /// The package name, on 8.1.
    pub package: Option<String>,
    /// The entry's trailing data, as stored.
    pub data: Vec<u8>,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// UTF-16LE at `b[at..at + len]`, and whether anything had to be replaced.
fn utf16_at(b: &[u8], at: usize, len: usize) -> Option<(String, bool)> {
    let units: Vec<u16> = b
        .get(at..at.checked_add(len)?)?
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect();
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    let units = &units[..end];
    Some(match String::from_utf16(units) {
        Ok(s) => (s, false),
        Err(_) => (String::from_utf16_lossy(units), true),
    })
}

fn filetime(raw: u64) -> Option<ForensicTimestamp> {
    (raw != 0).then(|| ForensicTimestamp::from_win_filetime(raw))
}

fn truncated(format: Format, position: usize, what: &str) -> ForensicError {
    ForensicError::other(
        "shimcache",
        format!(
            "{} entry {position}: {what} runs past the end of the cache",
            format.as_str()
        ),
    )
}

/// The layout of `blob`, from its header.
pub fn detect(blob: &[u8]) -> ForensicResult<Format> {
    let head = u32_at(blob, 0).ok_or_else(|| {
        ForensicError::other("shimcache", format!("{} byte(s): no header", blob.len()))
    })?;
    let entry_signature = |at: usize| blob.get(at..at + 4);
    Ok(match head {
        0xdead_beef => Format::WindowsXp,
        // The 64-bit entry puts 4 bytes of padding where the 32-bit one has the path offset.
        0xbadc_0ffe if u32_at(blob, 8 + 4) == Some(0) => Format::Windows2003Vista64,
        0xbadc_0ffe => Format::Windows2003Vista32,
        0xbadc_0fee if u32_at(blob, 128 + 4) == Some(0) => Format::Windows7_64,
        0xbadc_0fee => Format::Windows7_32,
        0x80 if entry_signature(128) == Some(b"00ts") => Format::Windows8,
        0x80 if entry_signature(128) == Some(b"10ts") => Format::Windows81,
        0x30 | 0x34 if entry_signature(head as usize) == Some(b"10ts") => Format::Windows10,
        other => {
            return Err(ForensicError::other(
                "shimcache",
                format!("unknown cache layout: header starts {other:#010x}"),
            ));
        }
    })
}

/// Every entry of the cache, most recent first. An entry that can't be read is one `Err` item;
/// the fixed-size layouts go on with the next, the variable-size ones stop, having nothing to
/// resynchronize on. An unknown layout is a single `Err`.
pub fn parse(blob: &[u8]) -> (Option<Format>, Vec<ForensicResult<ShimEntry>>) {
    let format = match detect(blob) {
        Ok(format) => format,
        Err(e) => return (None, vec![Err(e)]),
    };
    let entries = match format {
        Format::WindowsXp => parse_xp(blob),
        Format::Windows2003Vista32 | Format::Windows2003Vista64 => parse_fixed(blob, format),
        Format::Windows7_32 | Format::Windows7_64 => parse_fixed(blob, format),
        Format::Windows8 | Format::Windows81 => parse_signed(blob, format, 128),
        Format::Windows10 => parse_signed(blob, format, u32_at(blob, 0).unwrap_or(0x34) as usize),
    };
    (Some(format), entries)
}

/// The header's entry count, but never more than one past what fits in the blob: a corrupt
/// count is then one truncation error, not millions.
fn bounded_count(blob: &[u8], header: usize, size: usize) -> usize {
    let declared = u32_at(blob, 4).unwrap_or(0) as usize;
    let fits = blob.len().saturating_sub(header) / size;
    declared.min(fits + 1)
}

/// XP: 400-byte header with the count at 4, then 552-byte entries holding the path inline.
fn parse_xp(blob: &[u8]) -> Vec<ForensicResult<ShimEntry>> {
    const HEADER: usize = 400;
    const ENTRY: usize = 552;
    let count = bounded_count(blob, HEADER, ENTRY);
    (0..count)
        .map(|position| {
            let at = HEADER + position * ENTRY;
            let entry = blob
                .get(at..at + ENTRY)
                .ok_or_else(|| truncated(Format::WindowsXp, position, "the entry"))?;
            let (path, path_lossy) = utf16_at(entry, 0, 520).unwrap_or_default();
            let last_modified_raw = u64_at(entry, 528).unwrap_or(0);
            Ok(ShimEntry {
                position,
                path,
                path_lossy,
                last_modified_raw,
                last_modified: filetime(last_modified_raw),
                file_size: u64_at(entry, 536),
                ..ShimEntry::default()
            })
        })
        .collect()
}

/// 2003/Vista and 7: a count, then fixed-size entries pointing at their path (and on 7, data)
/// elsewhere in the blob.
fn parse_fixed(blob: &[u8], format: Format) -> Vec<ForensicResult<ShimEntry>> {
    let (header, size, wide) = match format {
        Format::Windows2003Vista32 => (8, 24, false),
        Format::Windows2003Vista64 => (8, 32, true),
        Format::Windows7_32 => (128, 32, false),
        _ => (128, 48, true),
    };
    let seven = matches!(format, Format::Windows7_32 | Format::Windows7_64);
    let count = bounded_count(blob, header, size);
    (0..count)
        .map(|position| {
            let at = header + position * size;
            let e = blob
                .get(at..at + size)
                .ok_or_else(|| truncated(format, position, "the entry"))?;
            let path_len = u16_at(e, 0).unwrap_or(0) as usize;
            let (path_offset, rest) = if wide {
                (u64_at(e, 8).unwrap_or(0) as usize, 16)
            } else {
                (u32_at(e, 4).unwrap_or(0) as usize, 8)
            };
            let (path, path_lossy) = utf16_at(blob, path_offset, path_len)
                .ok_or_else(|| truncated(format, position, "the path"))?;
            let last_modified_raw = u64_at(e, rest).unwrap_or(0);
            let mut entry = ShimEntry {
                position,
                path,
                path_lossy,
                last_modified_raw,
                last_modified: filetime(last_modified_raw),
                ..ShimEntry::default()
            };
            if seven {
                let insertion = u32_at(e, rest + 8).unwrap_or(0);
                entry.insertion_flags = Some(insertion);
                entry.shim_flags = u32_at(e, rest + 12);
                entry.executed = Some(insertion & 0x2 != 0);
                let (data_len, data_offset) = if wide {
                    (
                        u64_at(e, rest + 16).unwrap_or(0) as usize,
                        u64_at(e, rest + 24).unwrap_or(0) as usize,
                    )
                } else {
                    (
                        u32_at(e, rest + 16).unwrap_or(0) as usize,
                        u32_at(e, rest + 20).unwrap_or(0) as usize,
                    )
                };
                if data_len > 0 {
                    entry.data = blob
                        .get(data_offset..data_offset.saturating_add(data_len))
                        .ok_or_else(|| truncated(format, position, "the data"))?
                        .to_vec();
                }
            } else {
                entry.size_or_flags = u64_at(e, rest + 8);
            }
            Ok(entry)
        })
        .collect()
}

/// 8, 8.1 and 10: entries signed `00ts`/`10ts`, each saying how long it is, from `start`.
fn parse_signed(blob: &[u8], format: Format, start: usize) -> Vec<ForensicResult<ShimEntry>> {
    let signature: &[u8] = if format == Format::Windows8 {
        b"00ts"
    } else {
        b"10ts"
    };
    let mut out = Vec::new();
    let mut at = start;
    let mut position = 0;
    while at < blob.len() {
        if blob.get(at..at + 4) != Some(signature) {
            out.push(Err(ForensicError::other(
                "shimcache",
                format!(
                    "{} entry {position} at offset {at}: no {} signature; the rest of the cache \
                     can't be framed",
                    format.as_str(),
                    String::from_utf8_lossy(signature)
                ),
            )));
            break;
        }
        let Some(entry_size) = u32_at(blob, at + 8) else {
            out.push(Err(truncated(format, position, "the entry size")));
            break;
        };
        let body = at + 12;
        let next = body.saturating_add(entry_size as usize);
        out.push(parse_signed_entry(blob, format, position, body, next));
        at = next;
        position += 1;
    }
    out
}

fn parse_signed_entry(
    blob: &[u8],
    format: Format,
    position: usize,
    body: usize,
    end: usize,
) -> ForensicResult<ShimEntry> {
    let e = blob
        .get(..end)
        .ok_or_else(|| truncated(format, position, "the entry"))?;
    let mut at = body;
    let path_len =
        u16_at(e, at).ok_or_else(|| truncated(format, position, "the path size"))? as usize;
    let (path, path_lossy) =
        utf16_at(e, at + 2, path_len).ok_or_else(|| truncated(format, position, "the path"))?;
    at += 2 + path_len;
    let mut entry = ShimEntry {
        position,
        path,
        path_lossy,
        ..ShimEntry::default()
    };
    if format == Format::Windows81 {
        let package_len =
            u16_at(e, at).ok_or_else(|| truncated(format, position, "the package size"))? as usize;
        let (package, _) = utf16_at(e, at + 2, package_len)
            .ok_or_else(|| truncated(format, position, "the package"))?;
        entry.package = (!package.is_empty()).then_some(package);
        at += 2 + package_len;
    }
    if format != Format::Windows10 {
        let insertion = u32_at(e, at).ok_or_else(|| truncated(format, position, "the flags"))?;
        entry.insertion_flags = Some(insertion);
        entry.shim_flags = u32_at(e, at + 4);
        entry.executed = Some(insertion & 0x2 != 0);
        at += 8;
    }
    entry.last_modified_raw =
        u64_at(e, at).ok_or_else(|| truncated(format, position, "the time"))?;
    entry.last_modified = filetime(entry.last_modified_raw);
    let data_len =
        u32_at(e, at + 8).ok_or_else(|| truncated(format, position, "the data size"))? as usize;
    entry.data = e
        .get(at + 12..at + 12 + data_len)
        .ok_or_else(|| truncated(format, position, "the data"))?
        .to_vec();
    Ok(entry)
}

/// One `AppCompatCache` value to read: its key, and the control set the key is in as written.
struct CacheValue {
    key: String,
    control_set: String,
}

/// The control-set segment of a key path (`CurrentControlSet`, `ControlSet002`).
fn control_set_of(key: &str) -> String {
    key.split('\\')
        .find(|s| s.to_ascii_lowercase().contains("controlset"))
        .unwrap_or_default()
        .to_string()
}

/// [`ArtifactParserFactory`] emitting one [`ForensicData`] per [`ShimEntry`] of every control
/// set's cache.
pub struct ShimCacheParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for ShimCacheParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.registry.shimcache",
                "ShimCache",
                "Application Compatibility Cache entries (XP to 11), from the current control set \
                 and every other one",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![RegistryArtifacts::ShimCache.into()])
            .with_requirements(vec![Requirement::Artifact(ArtifactRef::from_static(
                DEFINITION,
            ))]),
        }
    }
}

impl ShimCacheParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

/// The cache values to read: the definition's (or the built-in keys), then every other control
/// set's, skipping the one `Select\Current` says `CurrentControlSet` is.
fn locate(
    ctx: &ParseContext<'_>,
    registry: &dyn Registry,
) -> (Vec<CacheValue>, bool, Vec<ForensicError>) {
    let mut errors = Vec::new();
    let from_catalog = ctx
        .sources()
        .catalog()
        .and_then(|catalog| catalog.get(DEFINITION).map(|def| (catalog, def)));
    let by_catalog = from_catalog.is_some();
    let primary: Vec<String> = match from_catalog {
        Some((catalog, def)) => {
            let empty = HostProfile::default();
            let host = ctx.host_profile().unwrap_or(&empty);
            expand(def, catalog.as_ref(), host, Os::Windows)
                .values
                .into_iter()
                .filter(|v| v.value.eq_ignore_ascii_case(VALUE))
                .map(|v| v.key)
                .collect()
        }
        None => BUILTIN_KEYS.iter().map(|k| k.to_string()).collect(),
    };
    let current = registry
        .value(r"HKLM\SYSTEM\Select", "Current")
        .ok()
        .and_then(|v| v.as_dword())
        .map(|n| format!("ControlSet{n:03}"));
    let mut found: BTreeMap<String, CacheValue> = BTreeMap::new();
    for pattern in primary.iter().map(String::as_str).chain(OTHER_CONTROL_SETS) {
        match registry.expand_key_pattern(pattern) {
            Ok(keys) => {
                for key in keys {
                    let control_set = control_set_of(&key);
                    if current
                        .as_deref()
                        .is_some_and(|c| c.eq_ignore_ascii_case(&control_set))
                    {
                        continue;
                    }
                    found
                        .entry(key.clone())
                        .or_insert(CacheValue { key, control_set });
                }
            }
            Err(e) => errors.push(ForensicError::other(
                "shimcache",
                format!("expanding {pattern}: {e}"),
            )),
        }
    }
    (found.into_values().collect(), by_catalog, errors)
}

impl ArtifactParserFactory for ShimCacheParserFactory {
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
                CompactString::const_new("ShimCacheParserFactory"),
            )
        })?;
        let (values, by_catalog, errors) = locate(ctx, registry.as_ref());
        let definition = by_catalog.then_some(DEFINITION);
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let mut out: Vec<ForensicResult<ForensicData>> = errors.into_iter().map(Err).collect();
        for value in values {
            let blob = match registry.value(&value.key, VALUE) {
                Ok(RegValue::Binary(blob)) => blob,
                Ok(other) => {
                    out.push(Err(ForensicError::registry_invalid_type(
                        "REG_BINARY",
                        format!(r"{:?} in {}\{VALUE}", other.value_type(), value.key),
                    )));
                    continue;
                }
                Err(e) if e.is_registry_not_found() => continue,
                Err(e) => {
                    out.push(Err(ForensicError::other(
                        "shimcache",
                        format!(r"{}\{VALUE}: {e}", value.key),
                    )));
                    continue;
                }
            };
            let source = match acquisition {
                Acquisition::LiveApi => SourceKey::Live {
                    host: host.clone(),
                    api: "Registry".into(),
                },
                _ => SourceKey::Path(format!(r"{}\{VALUE}", value.key)),
            };
            let source = ctx.register_source(source);
            let (format, entries) = parse(&blob);
            for entry in entries {
                out.push(
                    entry
                        .map(|entry| {
                            let provenance = source.mint(acquisition, Recovery::Allocated);
                            to_forensic_data(&host, provenance, definition, &value, format, entry)
                        })
                        .map_err(|e| {
                            ForensicError::other(
                                "shimcache",
                                format!(r"{}\{VALUE}: {e}", value.key),
                            )
                        }),
                );
            }
        }
        Ok(ParserRun::pull(out.into_iter()))
    }
}

fn to_forensic_data(
    host: &str,
    provenance: ProvenanceId,
    definition: Option<&'static str>,
    value: &CacheValue,
    format: Option<Format>,
    entry: ShimEntry,
) -> ForensicData {
    let mut data = ForensicData::new(host, RegistryArtifacts::ShimCache.into(), provenance);
    data.set(dictionary::EVENT_ACTION, "shimcache-entry");
    data.set(dictionary::FILE_PATH, entry.path);
    if entry.path_lossy {
        data.set("shimcache.path_lossy", 1u64);
    }
    // The file's modification time when cached: not when it ran, so not @timestamp.
    if let Some(ts) = entry.last_modified {
        data.set("file.mtime", ts);
    }
    data.set("shimcache.last_modified_raw", entry.last_modified_raw);
    data.set("shimcache.position", entry.position as u64);
    data.set("shimcache.control_set", value.control_set.clone());
    if let Some(format) = format {
        data.set("shimcache.format", format.as_str());
    }
    if let Some(executed) = entry.executed {
        data.set("shimcache.executed", u64::from(executed));
    }
    if let Some(flags) = entry.insertion_flags {
        data.set("shimcache.insertion_flags", u64::from(flags));
    }
    if let Some(flags) = entry.shim_flags {
        data.set("shimcache.shim_flags", u64::from(flags));
    }
    if let Some(size) = entry.file_size {
        data.set(dictionary::FILE_SIZE, size);
    }
    if let Some(raw) = entry.size_or_flags {
        data.set("shimcache.size_or_flags", raw);
    }
    if let Some(package) = entry.package {
        data.set("shimcache.package", package);
    }
    if !entry.data.is_empty() {
        data.set(
            "shimcache.data",
            entry
                .data
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
    }
    let (_, key) = value
        .key
        .split_once('\\')
        .unwrap_or(("", value.key.as_str()));
    data.set(dictionary::REGISTRY_KEY, key.to_string());
    data.set(dictionary::REGISTRY_VALUE, VALUE);
    if let Some(definition) = definition {
        data.set(dictionary::ARTIFACT_DEFINITION, definition);
    }
    data
}
