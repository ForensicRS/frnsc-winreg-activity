//! Services and drivers: `HKLM\SYSTEM\CurrentControlSet\Services\<name>`.
//!
//! Each subkey is a service or a driver. What it runs is `ImagePath`, or, for a service hosted in
//! `svchost.exe`, the `ServiceDll` of its `Parameters` subkey; `Start` says when (boot, system,
//! automatic, on demand, disabled) and `Type` what it is. The key's last-write time often moves
//! when a service is installed or reconfigured, but it is not an install time: it changes for any
//! edit of the key.

use std::collections::BTreeMap;

use forensic_rs::{dictionary, prelude::*};

use crate::locate::locate_keys;

/// The ForensicArtifacts definition of the services keys, which this parser reads.
pub const DEFINITION: &str = "WindowsServices";

/// The definition's keys, for a run with no artifact catalog.
const BUILTIN_PATTERNS: [&str; 1] = [r"HKLM\SYSTEM\CurrentControlSet\Services\*"];

/// One service or driver.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceEntry {
    /// The service's key, as matched.
    pub key: String,
    /// The key's name: the service name.
    pub name: String,
    pub display_name: Option<String>,
    pub description: Option<String>,
    /// `ImagePath` as stored (unexpanded; `\SystemRoot\...` and `system32\...` forms kept).
    pub image_path: Option<String>,
    /// `Parameters\ServiceDll` as stored.
    pub service_dll: Option<String>,
    /// `ObjectName`: the account the service runs as (`LocalSystem`, `NT AUTHORITY\...`).
    pub object_name: Option<String>,
    pub start: Option<u32>,
    pub service_type: Option<u32>,
    pub error_control: Option<u32>,
    pub group: Option<String>,
    pub key_last_write: Option<ForensicTimestamp>,
}

/// The name Windows gives a `Start` value.
pub fn start_name(start: u32) -> &'static str {
    match start {
        0 => "boot",
        1 => "system",
        2 => "automatic",
        3 => "manual",
        4 => "disabled",
        _ => "unknown",
    }
}

/// The names of the `Type` bits that are set (`own_process`, `kernel_driver`, ...), in bit order.
pub fn type_names(service_type: u32) -> Vec<&'static str> {
    [
        (0x1, "kernel_driver"),
        (0x2, "file_system_driver"),
        (0x4, "adapter"),
        (0x8, "recognizer_driver"),
        (0x10, "own_process"),
        (0x20, "share_process"),
        (0x50, "user_own_process"),
        (0x60, "user_share_process"),
        (0x100, "interactive_process"),
    ]
    .into_iter()
    // The user-service types are combinations; name them only when all their bits are set.
    .filter(|(bits, _)| service_type & bits == *bits)
    .map(|(_, name)| name)
    .collect()
}

/// A value that should be a string: `Ok(None)` when absent, an `Err` naming it when it has
/// another type.
fn string(key: &str, values: &[(String, RegValue)], name: &str) -> ForensicResult<Option<String>> {
    match values.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
        None => Ok(None),
        Some((_, RegValue::SZ(s) | RegValue::ExpandSZ(s))) => Ok(Some(s.clone())),
        Some((_, RegValue::MultiSZ(list))) => Ok(Some(list.join("\n"))),
        Some((_, other)) => Err(ForensicError::registry_invalid_type(
            "REG_SZ",
            format!(r"{other:?} in {key}\{name}"),
        )),
    }
}

/// A value that should be a `REG_DWORD`, as [`string`] does for strings.
fn dword(key: &str, values: &[(String, RegValue)], name: &str) -> ForensicResult<Option<u32>> {
    match values.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)) {
        None => Ok(None),
        Some((_, RegValue::DWord(v))) => Ok(Some(*v)),
        Some((_, other)) => Err(ForensicError::registry_invalid_type(
            "REG_DWORD",
            format!(r"{other:?} in {key}\{name}"),
        )),
    }
}

/// Reads one service key. A value of the wrong type is one extra `Err` item beside the service's
/// record, which still carries everything else; a key that can't be read at all is one `Err`.
pub fn read_service(registry: &dyn Registry, key: &str) -> Vec<ForensicResult<ServiceEntry>> {
    let opened = match registry.key(key) {
        Ok(opened) => opened,
        Err(e) if e.is_registry_not_found() => return Vec::new(),
        Err(e) => return vec![Err(e)],
    };
    let mut problems: Vec<ForensicError> = Vec::new();
    let key_last_write = match opened.info() {
        Ok(info) => info.last_write_time,
        Err(e) => {
            problems.push(e);
            None
        }
    };
    let values = match opened.values() {
        Ok(values) => values,
        Err(e) => return vec![Err(e)],
    };
    let mut take_string = |name: &str| {
        string(key, &values, name).unwrap_or_else(|e| {
            problems.push(e);
            None
        })
    };
    let display_name = take_string("DisplayName");
    let description = take_string("Description");
    let image_path = take_string("ImagePath");
    let object_name = take_string("ObjectName");
    let group = take_string("Group");
    let mut take_dword = |name: &str| {
        dword(key, &values, name).unwrap_or_else(|e| {
            problems.push(e);
            None
        })
    };
    let start = take_dword("Start");
    let service_type = take_dword("Type");
    let error_control = take_dword("ErrorControl");
    let parameters = format!(r"{key}\Parameters");
    let service_dll = match registry.key(&parameters).and_then(|k| k.values()) {
        Ok(values) => string(&parameters, &values, "ServiceDll").unwrap_or_else(|e| {
            problems.push(e);
            None
        }),
        Err(e) if e.is_registry_not_found() => None,
        Err(e) => {
            problems.push(e);
            None
        }
    };
    let entry = ServiceEntry {
        key: key.to_string(),
        name: key.rsplit('\\').next().unwrap_or_default().to_string(),
        display_name,
        description,
        image_path,
        service_dll,
        object_name,
        start,
        service_type,
        error_control,
        group,
        key_last_write,
    };
    std::iter::once(Ok(entry))
        .chain(problems.into_iter().map(Err))
        .collect()
}

/// [`ArtifactParserFactory`] emitting one [`ForensicData`] per [`ServiceEntry`].
pub struct ServicesParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for ServicesParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.registry.services",
                "Services",
                "Every service and driver configured under CurrentControlSet\\Services: what it \
                 runs, when it starts and as whom",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![RegistryArtifacts::Services.into()])
            .with_requirements(vec![Requirement::Artifact(ArtifactRef::from_static(
                DEFINITION,
            ))]),
        }
    }
}

impl ServicesParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for ServicesParserFactory {
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
                CompactString::const_new("ServicesParserFactory"),
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
        // The service keys a `\*` matched, not `Services` itself.
        for key in located.keys.into_iter().filter(|k| !k.values_of_wildcard) {
            let source = sources
                .entry(key.path.clone())
                .or_insert_with(|| match &live {
                    Some(live) => live.clone(),
                    None => ctx.register_source(SourceKey::Path(key.path.clone())),
                })
                .clone();
            for entry in read_service(registry.as_ref(), &key.path) {
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
    entry: ServiceEntry,
) -> ForensicData {
    let mut data = ForensicData::new(host, RegistryArtifacts::Services.into(), provenance);
    data.set(dictionary::EVENT_ACTION, "service-configured");
    data.set(dictionary::SERVICE_NAME, entry.name);
    let (_, key) = entry
        .key
        .split_once('\\')
        .unwrap_or(("", entry.key.as_str()));
    data.set(dictionary::REGISTRY_KEY, key.to_string());
    data.set(dictionary::REGISTRY_PATH, entry.key.clone());
    let mut text = |field: &'static str, value: Option<String>| {
        if let Some(value) = value {
            data.set(field, value);
        }
    };
    text("service.display_name", entry.display_name);
    text("service.description", entry.description);
    text("service.image_path", entry.image_path);
    text("service.dll", entry.service_dll);
    text("service.account", entry.object_name);
    text("service.group", entry.group);
    if let Some(start) = entry.start {
        data.set("service.start", u64::from(start));
        data.set("service.start_name", start_name(start));
    }
    if let Some(service_type) = entry.service_type {
        data.set("service.type", u64::from(service_type));
        let names = type_names(service_type);
        if !names.is_empty() {
            data.insert(
                Text::Borrowed("service.type_names"),
                Field::Array(names.into_iter().map(Text::Borrowed).collect()),
            );
        }
    }
    if let Some(error_control) = entry.error_control {
        data.set("service.error_control", u64::from(error_control));
    }
    if let Some(ts) = entry.key_last_write {
        data.set(dictionary::REGISTRY_KEY_LAST_WRITE, ts);
    }
    if let Some(definition) = definition {
        data.set(dictionary::ARTIFACT_DEFINITION, definition);
    }
    data
}
