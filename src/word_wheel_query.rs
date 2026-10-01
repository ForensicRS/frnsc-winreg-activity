//! WordWheelQuery: terms a user typed into Explorer's search box.
//!
//! `HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery` holds one
//! `REG_BINARY` value per term, named `0`, `1`, ..., each a NUL-terminated UTF-16 string, and
//! `MRUListEx`: those names as little-endian `u32`s, most recent first, ended by `0xFFFFFFFF`.
//!
//! No term has a time. The key's last-write time is when the list last changed, usually the most
//! recent search, but a re-search reorders it too, so it is carried, not put in `@timestamp`.

use std::collections::BTreeMap;

use forensic_rs::{dictionary, prelude::*};

use crate::locate::locate_keys;

/// The ForensicArtifacts definition of the key, which this parser reads.
pub const DEFINITION: &str = "WindowsWordWheelQueryRegistryKey";

const BUILTIN_PATTERNS: [&str; 1] =
    [r"HKU\*\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery\*"];

/// One search term.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchTerm {
    pub user_sid: Option<String>,
    pub key: String,
    /// The value's name, as stored (`0`, `1`, ...).
    pub index: String,
    /// The term, as stored (UTF-16 decoded; an invalid sequence replaced, and `lossy` set).
    pub term: String,
    pub lossy: bool,
    /// Where `MRUListEx` puts the term, 0 being the most recent; `None` when it isn't listed.
    pub mru_position: Option<usize>,
    pub key_last_write: Option<ForensicTimestamp>,
}

/// The value names `MRUListEx` lists, in order. A trailing partial entry is ignored, as Windows
/// would; the list ends at `0xFFFFFFFF`.
fn mru_order(data: &[u8]) -> Vec<String> {
    data.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .take_while(|&i| i != u32::MAX)
        .map(|i| i.to_string())
        .collect()
}

/// Every term of the key at `key`. A missing key is nothing; one that can't be read, or a term
/// value that isn't `REG_BINARY`, is one `Err` item.
pub fn read_search_terms(
    registry: &dyn Registry,
    key: &str,
    user_sid: Option<String>,
) -> Vec<ForensicResult<SearchTerm>> {
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
    let values = match opened.values() {
        Ok(values) => values,
        Err(e) => {
            out.push(Err(e));
            return out;
        }
    };
    let order = values
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("MRUListEx"))
        .and_then(|(_, v)| match v {
            RegValue::Binary(data) => Some(mru_order(data)),
            _ => None,
        })
        .unwrap_or_default();
    for (name, value) in values {
        if name.eq_ignore_ascii_case("MRUListEx") || name.is_empty() {
            continue;
        }
        let data = match value {
            RegValue::Binary(data) => data,
            other => {
                out.push(Err(ForensicError::registry_invalid_type(
                    "REG_BINARY",
                    format!(r"{other:?} in {key}\{name}"),
                )));
                continue;
            }
        };
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        let (term, lossy) = match String::from_utf16(&units[..end]) {
            Ok(term) => (term, false),
            Err(_) => (String::from_utf16_lossy(&units[..end]), true),
        };
        out.push(Ok(SearchTerm {
            user_sid: user_sid.clone(),
            key: key.to_string(),
            mru_position: order.iter().position(|i| *i == name),
            index: name,
            term,
            lossy,
            key_last_write,
        }));
    }
    out
}

/// The SID a `HKU\<sid>\...` (or `HKEY_USERS\...`) path is under.
fn sid_of(key: &str) -> Option<String> {
    let mut segments = key.split('\\');
    let hive = segments.next()?;
    (hive.eq_ignore_ascii_case("HKU") || hive.eq_ignore_ascii_case("HKEY_USERS"))
        .then(|| segments.next().map(str::to_string))
        .flatten()
}

/// [`ArtifactParserFactory`] emitting one [`ForensicData`] per [`SearchTerm`].
pub struct WordWheelQueryParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for WordWheelQueryParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.registry.word_wheel_query",
                "WordWheelQuery",
                "Terms each user searched for in Explorer, with their most-recent-first order",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![RegistryArtifacts::WordWheelQuery.into()])
            .with_requirements(vec![Requirement::Artifact(ArtifactRef::from_static(
                DEFINITION,
            ))]),
        }
    }
}

impl WordWheelQueryParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for WordWheelQueryParserFactory {
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
                CompactString::const_new("WordWheelQueryParserFactory"),
            )
        })?;
        let located = locate_keys(ctx, registry.as_ref(), DEFINITION, &BUILTIN_PATTERNS);
        let definition = located.by_catalog.then_some(DEFINITION);
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let mut out: Vec<ForensicResult<ForensicData>> =
            located.errors.into_iter().map(Err).collect();
        let mut sources: BTreeMap<String, SourceHandle> = BTreeMap::new();
        // The `WordWheelQuery` key itself (the `\*` pattern's parent) and any subkeys under it.
        for key in located.keys {
            let source = sources
                .entry(key.path.clone())
                .or_insert_with(|| {
                    ctx.register_source(match acquisition {
                        Acquisition::LiveApi => SourceKey::Live {
                            host: host.clone(),
                            api: "Registry".into(),
                        },
                        _ => SourceKey::Path(key.path.clone()),
                    })
                })
                .clone();
            let sid = key.sid.clone().or_else(|| sid_of(&key.path));
            for term in read_search_terms(registry.as_ref(), &key.path, sid) {
                out.push(term.map(|term| {
                    let provenance = source.mint(acquisition, Recovery::Allocated);
                    to_forensic_data(&host, provenance, definition, term)
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
    term: SearchTerm,
) -> ForensicData {
    let mut data = ForensicData::new(host, RegistryArtifacts::WordWheelQuery.into(), provenance);
    data.set(dictionary::EVENT_ACTION, "explorer-search");
    if let Some(sid) = term.user_sid {
        data.set(dictionary::USER_ID, sid);
    }
    data.set("word_wheel_query.term", term.term);
    if term.lossy {
        data.set("word_wheel_query.lossy", 1u64);
    }
    if let Some(position) = term.mru_position {
        data.set("word_wheel_query.mru_position", position as u64);
    }
    let (_, key) = term.key.split_once('\\').unwrap_or(("", term.key.as_str()));
    data.set(dictionary::REGISTRY_KEY, key.to_string());
    data.set(dictionary::REGISTRY_VALUE, term.index);
    if let Some(ts) = term.key_last_write {
        data.set(dictionary::REGISTRY_KEY_LAST_WRITE, ts);
    }
    if let Some(definition) = definition {
        data.set(dictionary::ARTIFACT_DEFINITION, definition);
    }
    data
}
