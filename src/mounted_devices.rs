//! `HKLM\SYSTEM\MountedDevices`: what each drive letter and volume was mounted from.
//!
//! A value is named by a mount point, `\DosDevices\C:` (a drive letter) or `\??\Volume{guid}` (a
//! volume), and its data says what it pointed at:
//!
//! * 12 bytes: an MBR disk, as its 4-byte disk signature and the partition's byte offset;
//! * `DMIO:ID:` and a 16-byte GUID: a GPT partition, by its partition GUID;
//! * a UTF-16 device path (`\??\USBSTOR#Disk&Ven_...`, `_??_USBSTOR#...`): removable media and
//!   other devices, by their PnP instance path.
//!
//! The key keeps entries for devices long gone, which is what makes it useful: a drive letter or
//! a volume GUID seen elsewhere (a LNK target, a BAM device path) maps back to a disk here. There
//! is no per-value time.

use std::collections::BTreeMap;

use forensic_rs::{dictionary, prelude::*};

use crate::locate::locate_keys;

/// The ForensicArtifacts definition of the key, which this parser reads.
pub const DEFINITION: &str = "WindowsMountedDevices";

const BUILTIN_PATTERNS: [&str; 1] = [r"HKLM\SYSTEM\MountedDevices"];

/// What a mount point pointed at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// An MBR partition: the disk's signature and the partition's byte offset.
    Mbr {
        disk_signature: u32,
        partition_offset: u64,
    },
    /// A GPT partition, by its partition GUID (`{xxxxxxxx-...}`).
    Gpt { partition_guid: String },
    /// A device path, as stored.
    Device { path: String },
    /// Data none of the above describes, kept as stored.
    Unknown,
}

/// One mount point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountedDevice {
    /// The value's name, as stored: `\DosDevices\C:` or `\??\Volume{guid}`.
    pub mount_point: String,
    /// `C:` for a drive-letter mount point.
    pub drive_letter: Option<String>,
    /// The volume GUID for a `\??\Volume{guid}` mount point.
    pub volume_guid: Option<String>,
    pub target: Target,
    /// The value's data, as stored.
    pub data: Vec<u8>,
}

/// A 16-byte little-endian (mixed-endian) GUID as `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
fn guid(b: &[u8]) -> Option<String> {
    let b: &[u8; 16] = b.try_into().ok()?;
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    Some(format!(
        "{{{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    ))
}

/// What `data` describes. Only a decode the data unambiguously supports is made.
pub fn decode_target(data: &[u8]) -> Target {
    if data.len() == 12 {
        let mut signature = [0u8; 4];
        signature.copy_from_slice(&data[..4]);
        let mut offset = [0u8; 8];
        offset.copy_from_slice(&data[4..12]);
        return Target::Mbr {
            disk_signature: u32::from_le_bytes(signature),
            partition_offset: u64::from_le_bytes(offset),
        };
    }
    if let Some(rest) = data.strip_prefix(b"DMIO:ID:") {
        if let Some(partition_guid) = guid(rest) {
            return Target::Gpt { partition_guid };
        }
    }
    if data.len() >= 4 && data.len() % 2 == 0 {
        let units: Vec<u16> = data
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        if let Ok(path) = String::from_utf16(&units) {
            let path = path.trim_end_matches('\0').to_string();
            // A device path is printable text; anything else is binary that happened to decode.
            if !path.is_empty() && path.chars().all(|c| !c.is_control()) {
                return Target::Device { path };
            }
        }
    }
    Target::Unknown
}

/// Every value of the key at `key`. A missing key is nothing; one that can't be read is one `Err`.
pub fn read_mounted_devices(
    registry: &dyn Registry,
    key: &str,
) -> Vec<ForensicResult<MountedDevice>> {
    let values = match registry.key(key).and_then(|k| k.values()) {
        Ok(values) => values,
        Err(e) if e.is_registry_not_found() => return Vec::new(),
        Err(e) => return vec![Err(e)],
    };
    values
        .into_iter()
        .map(|(mount_point, value)| {
            let data = match value {
                RegValue::Binary(data) => data,
                other => {
                    return Err(ForensicError::registry_invalid_type(
                        "REG_BINARY",
                        format!(r"{other:?} in {key}\{mount_point}"),
                    ));
                }
            };
            let drive_letter = mount_point
                .strip_prefix(r"\DosDevices\")
                .map(str::to_string);
            let volume_guid = mount_point.strip_prefix(r"\??\Volume").map(str::to_string);
            Ok(MountedDevice {
                target: decode_target(&data),
                mount_point,
                drive_letter,
                volume_guid,
                data,
            })
        })
        .collect()
}

/// [`ArtifactParserFactory`] emitting one [`ForensicData`] per [`MountedDevice`].
pub struct MountedDevicesParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for MountedDevicesParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.registry.mounted_devices",
                "MountedDevices",
                "Drive letters and volume GUIDs, and the MBR disk, GPT partition or device each was \
                 mounted from",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![RegistryArtifacts::MountedDevices.into()])
            .with_requirements(vec![Requirement::Artifact(ArtifactRef::from_static(DEFINITION))]),
        }
    }
}

impl MountedDevicesParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for MountedDevicesParserFactory {
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
                CompactString::const_new("MountedDevicesParserFactory"),
            )
        })?;
        let located = locate_keys(ctx, registry.as_ref(), DEFINITION, &BUILTIN_PATTERNS);
        let definition = located.by_catalog.then_some(DEFINITION);
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let mut out: Vec<ForensicResult<ForensicData>> =
            located.errors.into_iter().map(Err).collect();
        let mut sources: BTreeMap<String, SourceHandle> = BTreeMap::new();
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
            let last_write = match registry.key(&key.path).and_then(|k| k.info()) {
                Ok(info) => info.last_write_time,
                Err(e) if e.is_registry_not_found() => None,
                Err(e) => {
                    out.push(Err(e));
                    None
                }
            };
            for device in read_mounted_devices(registry.as_ref(), &key.path) {
                out.push(device.map(|device| {
                    let provenance = source.mint(acquisition, Recovery::Allocated);
                    to_forensic_data(&host, provenance, definition, &key.path, last_write, device)
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
    key: &str,
    last_write: Option<ForensicTimestamp>,
    device: MountedDevice,
) -> ForensicData {
    let mut data = ForensicData::new(host, RegistryArtifacts::MountedDevices.into(), provenance);
    data.set(dictionary::EVENT_ACTION, "mount-point");
    data.set("mounted_device.mount_point", device.mount_point.clone());
    if let Some(letter) = device.drive_letter {
        data.set("mounted_device.drive_letter", letter);
    }
    if let Some(guid) = device.volume_guid {
        data.set("mounted_device.volume_guid", guid);
    }
    match device.target {
        Target::Mbr {
            disk_signature,
            partition_offset,
        } => {
            data.set("mounted_device.kind", "mbr");
            data.set(
                "mounted_device.disk_signature",
                format!("{disk_signature:08x}"),
            );
            data.set("mounted_device.partition_offset", partition_offset);
        }
        Target::Gpt { partition_guid } => {
            data.set("mounted_device.kind", "gpt");
            data.set("mounted_device.partition_guid", partition_guid);
        }
        Target::Device { path } => {
            data.set("mounted_device.kind", "device");
            data.set("mounted_device.device_path", path);
        }
        Target::Unknown => data.set("mounted_device.kind", "unknown"),
    }
    data.set(
        "mounted_device.data",
        device
            .data
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
    );
    let (_, sub) = key.split_once('\\').unwrap_or(("", key));
    data.set(dictionary::REGISTRY_KEY, sub.to_string());
    data.set(dictionary::REGISTRY_VALUE, device.mount_point);
    if let Some(ts) = last_write {
        data.set(dictionary::REGISTRY_KEY_LAST_WRITE, ts);
    }
    if let Some(definition) = definition {
        data.set(dictionary::ARTIFACT_DEFINITION, definition);
    }
    data
}
