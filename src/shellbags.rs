//! ShellBags: the folders a user opened in Explorer, kept so each one reopens with its last view.
//!
//! `HKU\<sid>\Software\Microsoft\Windows\Shell\BagMRU` (`NTUSER.DAT`) and
//! `HKU\<sid>_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` (`UsrClass.dat`,
//! where Windows 7 and later keep most of them) are a tree mirroring the shell namespace. Each key
//! holds one `REG_BINARY` value per child folder, named `0`, `1`, ..., whose data is that folder's
//! shell item (one entry of an ITEMIDLIST), and `MRUListEx`: those names as little-endian `u32`s,
//! most recent first, ended by `0xFFFFFFFF`. A child's own children are under the subkey of the
//! same name, whose `NodeSlot` names its view settings under `Bags`.
//!
//! A folder's path is its ancestors' items joined: `My Computer` / `C:\` / `Users` / ...; a
//! volume, a UNC location and a namespace root start a path of their own.
//!
//! Times: a file entry item carries the folder's modified time and, in its `0xbeef0004`
//! extension, its created and accessed times, as they were when the item was recorded; all are
//! FAT times (UTC, 2 s precision). A key's last-write time is when its list last changed, which
//! is for the child `MRUListEx` puts first: for that child it is when the folder was last opened.

use std::collections::BTreeMap;

use forensic_rs::{dictionary, prelude::*};

use crate::locate::locate_keys;

/// The name this parser looks for in the run's artifact catalog.
pub const DEFINITION: &str = "WindowsShellBags";

const BUILTIN_PATTERNS: [&str; 2] = [
    r"HKU\*\Software\Microsoft\Windows\Shell\BagMRU",
    r"HKU\*\Local Settings\Software\Microsoft\Windows\Shell\BagMRU",
];

/// What a user's class hive is loaded under in `HKU`, after the user's SID.
const CLASSES_SUFFIX: &str = "_Classes";

/// Signature of a `0x1F` item that holds a drive letter rather than a namespace GUID.
const DRIVE_SIGNATURE: [u8; 4] = 0xF5A6_B710u32.to_le_bytes();

/// Deeper than any real folder tree; stops a key that loops back on itself.
const MAX_DEPTH: usize = 128;

/// Known namespace roots of `0x1F` items and shell folders of `0x2E` items, by GUID.
const KNOWN_FOLDERS: [(&str, &str); 26] = [
    ("20D04FE0-3AEA-1069-A2D8-08002B30309D", "My Computer"),
    ("208D2C60-3AEA-1069-A2D7-08002B30309D", "My Network Places"),
    ("F02C1A0D-BE21-4350-88B0-7367FC96EF3C", "Network"),
    ("59031A47-3F72-44A7-89C5-5595FE6B30EE", "Users Files"),
    ("645FF040-5081-101B-9F08-00AA002F954E", "Recycle Bin"),
    ("450D8FBA-AD25-11D0-98A8-0800361B1103", "My Documents"),
    ("031E4825-7B94-4DC3-B131-E946B44C8DD5", "Libraries"),
    ("679F85CB-0220-4080-B29B-5540CC05AAB6", "Quick Access"),
    ("F874310E-B6B7-47DC-BC84-B9E6B38F5903", "Home"),
    ("26EE0668-A00A-44D7-9371-BEB064C98683", "Control Panel"),
    (
        "21EC2020-3AEA-1069-A2DD-08002B30309D",
        "All Control Panel Items",
    ),
    ("871C5380-42A0-1069-A2EA-08002B30309D", "Internet Explorer"),
    ("018D5C66-4533-4307-9B53-224DE2ED1FE6", "OneDrive"),
    ("088E3905-0323-4B02-9826-5D99428E115F", "Downloads"),
    ("374DE290-123F-4565-9164-39C4925E467B", "Downloads"),
    ("B4BFCC3A-DB2C-424C-B029-7FE99A87C641", "Desktop"),
    ("D3162B92-9365-467A-956B-92703ACA08AF", "Documents"),
    ("FDD39AD0-238F-46AF-ADB4-6C85480369C7", "Documents"),
    ("24AD3AD4-A569-4530-98E1-AB02F9417AA8", "Pictures"),
    ("33E28130-4E1E-4676-835A-98395C3BC3BB", "Pictures"),
    ("3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE", "Music"),
    ("4BD8D571-6D19-48D3-BE97-422220080E43", "Music"),
    ("F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A", "Videos"),
    ("18989B1D-99B5-455B-841C-AB7C74E4DDFC", "Videos"),
    ("0DB7E03F-FC29-4DC6-9020-FF41B59E513A", "3D Objects"),
    ("A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0", "Documents"),
];

/// A file entry: a folder (or file, or archive) on a volume or share.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileEntry {
    /// The class type says directory (`0x31`) rather than file (`0x32`).
    pub is_directory: bool,
    /// The 8.3 or primary name the item starts with.
    pub short_name: String,
    /// The full name, from the `0xbeef0004` extension, when there is one.
    pub long_name: Option<String>,
    pub size: u32,
    pub modified: Option<ForensicTimestamp>,
    pub created: Option<ForensicTimestamp>,
    pub accessed: Option<ForensicTimestamp>,
    /// NTFS MFT entry and sequence number, from an extension version 7 or later.
    pub mft_entry: Option<u64>,
    pub mft_sequence: Option<u16>,
    /// Wrapped in a `0x74` delegate item (how Windows 10+ records a user's own folders).
    pub delegate: bool,
}

impl FileEntry {
    pub fn name(&self) -> &str {
        self.long_name
            .as_deref()
            .filter(|n| !n.is_empty())
            .unwrap_or(&self.short_name)
    }
}

/// A network item: a server, a share (`\\server\share`), or a provider.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetworkLocation {
    pub location: String,
    pub description: Option<String>,
    pub comment: Option<String>,
}

/// An item inside a ZIP archive Explorer opened as a folder. Its class byte is left
/// uninitialized by Windows, so it's recognized by its layout instead: `0x0010` at `0x20`, the
/// entry's modified time as display text at `0x24` (`N/A` for a folder), the lengths of the name
/// and of its parent's path in the archive at `0x54` and `0x58`, then both strings from `0x5C`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub name: String,
    /// The parent folder inside the archive, `/`-separated (`a/`), when not at the root.
    pub parent_in_archive: Option<String>,
    /// The modified time as Explorer displayed it, in the user's locale (`09/03/2025  00:34:18`).
    pub modified_text: Option<String>,
}

/// One decoded shell item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellItem {
    /// A namespace root (`0x1F`): My Computer, Network, a user's files... `name` when known.
    RootFolder {
        guid: String,
        name: Option<&'static str>,
    },
    /// A volume (`0x2X`), `C:\`, or a shell folder under My Computer named by GUID (`0x2E`).
    Volume { name: String },
    /// A file entry (`0x3X`), alone or wrapped in a `0x74` delegate.
    File(FileEntry),
    /// A network item (`0x4X`, `0xC3`).
    Network(NetworkLocation),
    /// A folder or file inside a ZIP archive opened as a folder.
    ArchiveEntry(ArchiveEntry),
    /// A Control Panel item (`0x71`).
    ControlPanel { guid: String },
    /// A URI (`0x61`): an FTP folder, a web folder. `uri` is the best readable string in it.
    Uri { uri: Option<String> },
    /// Anything else, e.g. a folder inside a ZIP archive or a device. `name` is the best
    /// readable string in the item, a guess; `data` is the item.
    Other {
        class_type: u8,
        name: Option<String>,
        data: Vec<u8>,
    },
}

impl ShellItem {
    /// The item's name, as a path segment.
    pub fn name(&self) -> String {
        match self {
            ShellItem::RootFolder { guid, name } => {
                name.map_or_else(|| format!("{{{guid}}}"), str::to_string)
            }
            ShellItem::Volume { name } => name.clone(),
            ShellItem::File(file) => file.name().to_string(),
            ShellItem::Network(net) => net.location.clone(),
            ShellItem::ArchiveEntry(entry) => entry.name.clone(),
            ShellItem::ControlPanel { guid } => format!("{{{guid}}}"),
            ShellItem::Uri { uri } => uri.clone().unwrap_or_else(|| "<uri>".into()),
            ShellItem::Other {
                class_type, name, ..
            } => name
                .clone()
                .unwrap_or_else(|| format!("<0x{class_type:02x}>")),
        }
    }

    /// A short name for the item's kind.
    pub fn kind(&self) -> &'static str {
        match self {
            ShellItem::RootFolder { .. } => "root",
            ShellItem::Volume { .. } => "volume",
            ShellItem::File(f) if f.is_directory => "directory",
            ShellItem::File(_) => "file",
            ShellItem::Network(_) => "network",
            ShellItem::ArchiveEntry(_) => "archive-entry",
            ShellItem::ControlPanel { .. } => "control-panel",
            ShellItem::Uri { .. } => "uri",
            ShellItem::Other { .. } => "other",
        }
    }

    /// Whether the item starts a path of its own rather than extending its parent's.
    fn is_absolute(&self) -> bool {
        match self {
            ShellItem::RootFolder { .. } => true,
            ShellItem::Volume { name } => name.as_bytes().get(1) == Some(&b':'),
            ShellItem::Network(net) => net.location.starts_with(r"\\"),
            _ => false,
        }
    }
}

/// Decodes one shell item: its `u16` size, class type, then the class's fields. A truncated or
/// malformed item is an error; an unknown class is [ShellItem::Other].
pub fn parse_shell_item(data: &[u8]) -> ForensicResult<ShellItem> {
    let size = ByteReader::new(data).read_u16_le()? as usize;
    if size < 3 {
        return Err(corrupted(0, format!("shell item size {size}")));
    }
    let item = data.get(..size).unwrap_or(data);
    if let Some(entry) = archive_entry(item) {
        return Ok(ShellItem::ArchiveEntry(entry));
    }
    let class_type = item[2];
    Ok(match class_type {
        // A drive under a namespace root, as Windows 10+ records it: signature at 6, letter at 13.
        0x1F if item.len() >= 16 && item[3] == 0 && item[6..10] == DRIVE_SIGNATURE => {
            let mut r = ByteReader::new(item);
            r.skip(13)?;
            ShellItem::Volume {
                name: ascii_cstr(&mut r)?,
            }
        }
        0x1F => {
            let guid = guid_at(item, 4)?;
            ShellItem::RootFolder {
                name: known_folder(&guid),
                guid,
            }
        }
        0x2E if item.len() >= 20 => {
            let guid = guid_at(item, 4)?;
            ShellItem::Volume {
                name: known_folder(&guid).map_or_else(|| format!("{{{guid}}}"), str::to_string),
            }
        }
        0x20..=0x2F => {
            let mut r = ByteReader::new(item);
            r.skip(3)?;
            ShellItem::Volume {
                name: ascii_cstr(&mut r)?,
            }
        }
        0x30..=0x3F => ShellItem::File(file_entry(item, item, false)?),
        0x40..=0x4F | 0xC3 => ShellItem::Network(network(item)?),
        0x71 => ShellItem::ControlPanel {
            guid: guid_at(item, 14)?,
        },
        0x74 => ShellItem::File(delegate(item)?),
        0x61 => ShellItem::Uri {
            uri: readable_string(item),
        },
        _ => ShellItem::Other {
            class_type,
            name: readable_string(item),
            data: item.to_vec(),
        },
    })
}

/// The item as an [ArchiveEntry], when its layout is one.
fn archive_entry(item: &[u8]) -> Option<ArchiveEntry> {
    if item.len() < 0x5E || item[0x20..0x22] != [0x10, 0x00] {
        return None;
    }
    let mut r = ByteReader::new(item);
    r.skip(0x24).ok()?;
    let modified_text = utf16_cstr(&mut r).ok().filter(|t| is_text(t))?;
    let mut r = ByteReader::new(item);
    r.skip(0x54).ok()?;
    let name_len = r.read_u32_le().ok()? as usize;
    let parent_len = r.read_u32_le().ok()? as usize;
    let name = r
        .read_utf16le_string(name_len.checked_mul(2)?)
        .ok()
        .filter(|n| !n.is_empty() && is_text(n))?;
    let parent_in_archive = (parent_len > 0)
        .then(|| {
            r.skip(2).ok()?;
            r.read_utf16le_string(parent_len.checked_mul(2)?).ok()
        })
        .flatten()
        .filter(|p| is_text(p));
    Some(ArchiveEntry {
        name,
        parent_in_archive,
        modified_text: Some(modified_text).filter(|t| !t.is_empty()),
    })
}

/// No control characters and no unpaired surrogates (decoded as U+FFFD).
fn is_text(s: &str) -> bool {
    s.chars()
        .all(|c| !c.is_control() && c != char::REPLACEMENT_CHARACTER)
}

/// A file entry starting at `head` (its own size first); its extension is searched for in
/// `scope`, which is `head` itself unless the entry is wrapped in a delegate.
fn file_entry(head: &[u8], scope: &[u8], delegate: bool) -> ForensicResult<FileEntry> {
    let mut r = ByteReader::new(head);
    r.skip(2)?;
    let class_type = r.read_u8()?;
    r.skip(1)?;
    let size = r.read_u32_le()?;
    let modified = fat_time(r.read_u32_le()?);
    let _attributes = r.read_u16_le()?;
    let short_name = if class_type & 0x04 != 0 {
        utf16_cstr(&mut r)?
    } else {
        ascii_cstr(&mut r)?
    };
    let mut entry = FileEntry {
        is_directory: class_type & 0x01 != 0,
        short_name,
        size,
        modified,
        delegate,
        ..Default::default()
    };
    if let Some(start) = find_signature(scope, 0xbeef_0004) {
        // A broken extension leaves the entry with its primary name, not an error.
        let _ = beef0004(&scope[start..], &mut entry);
    }
    Ok(entry)
}

/// The `0xbeef0004` extension block: created and accessed times, MFT reference, long name.
fn beef0004(block: &[u8], entry: &mut FileEntry) -> ForensicResult<()> {
    let mut r = ByteReader::new(block);
    let size = r.read_u16_le()? as usize;
    let block = block.get(..size).unwrap_or(block);
    let mut r = ByteReader::new(block);
    r.skip(2)?;
    let version = r.read_u16_le()?;
    r.skip(4)?; // signature
    entry.created = fat_time(r.read_u32_le()?);
    entry.accessed = fat_time(r.read_u32_le()?);
    r.skip(2)?;
    if version >= 7 {
        r.skip(2)?;
        let reference = r.read_u64_le()?;
        entry.mft_entry = Some(reference & 0xFFFF_FFFF_FFFF);
        entry.mft_sequence = Some((reference >> 48) as u16);
        r.skip(8)?;
    }
    if version >= 3 {
        r.skip(2)?;
    }
    if version >= 9 {
        r.skip(4)?;
    }
    if version >= 8 {
        r.skip(4)?;
    }
    if version >= 3 {
        entry.long_name = Some(utf16_cstr(&mut r)?);
    }
    Ok(())
}

/// A `0x74` delegate item wraps a file entry after the `CFSF` signature; its extension follows
/// the wrapped entry inside the delegate.
fn delegate(item: &[u8]) -> ForensicResult<FileEntry> {
    let at = item
        .windows(4)
        .position(|w| w == b"CFSF")
        .ok_or_else(|| corrupted(0, "delegate item without CFSF".into()))?;
    file_entry(&item[at + 4..], item, true)
}

fn network(item: &[u8]) -> ForensicResult<NetworkLocation> {
    let mut r = ByteReader::new(item);
    r.skip(4)?;
    let flags = r.read_u8()?;
    let location = ascii_cstr(&mut r)?;
    let description = if flags & 0x80 != 0 {
        Some(ascii_cstr(&mut r)?)
    } else {
        None
    };
    let comment = if flags & 0x40 != 0 {
        Some(ascii_cstr(&mut r)?)
    } else {
        None
    };
    Ok(NetworkLocation {
        location,
        description,
        comment,
    })
}

/// A FAT date (low 16 bits) and time (high 16 bits), UTC; `None` when unset or impossible.
fn fat_time(raw: u32) -> Option<ForensicTimestamp> {
    if raw == 0 {
        return None;
    }
    let (date, time) = (raw & 0xFFFF, raw >> 16);
    let calendar = ForensicTimestamp::try_with_ymd_and_hms_nanos(
        1980 + (date >> 9) as i64,
        ((date >> 5) & 0x0F) as u8,
        (date & 0x1F) as u8,
        (time >> 11) as u8,
        ((time >> 5) & 0x3F) as u8,
        ((time & 0x1F) * 2) as u8,
        0,
        Some(0),
    )
    .ok()?;
    ForensicTimestamp::try_from_parts(
        calendar.utc_seconds(),
        0,
        Some(0),
        TimestampFlags::new(TimestampPrecision::Seconds, TimestampSource::Calendar),
    )
    .ok()
}

/// Where the extension block whose signature is `signature` starts (its size, 4 bytes before
/// the signature).
fn find_signature(data: &[u8], signature: u32) -> Option<usize> {
    let needle = signature.to_le_bytes();
    data.windows(4)
        .enumerate()
        .skip(4)
        .find(|(_, w)| *w == needle)
        .map(|(at, _)| at - 4)
}

/// The GUID at `at`, in registry form without braces.
fn guid_at(item: &[u8], at: usize) -> ForensicResult<String> {
    let mut r = ByteReader::new(item);
    r.skip(at)?;
    let d1 = r.read_u32_le()?;
    let d2 = r.read_u16_le()?;
    let d3 = r.read_u16_le()?;
    let d4 = r.read_fixed::<8>()?;
    Ok(format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
    ))
}

fn known_folder(guid: &str) -> Option<&'static str> {
    KNOWN_FOLDERS
        .iter()
        .find(|(g, _)| g.eq_ignore_ascii_case(guid))
        .map(|(_, name)| *name)
}

/// A NUL-terminated single-byte string (Windows-1252 in practice; non-ASCII kept as Latin-1).
fn ascii_cstr(r: &mut ByteReader<'_>) -> ForensicResult<String> {
    let rest = r.remaining_slice();
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| corrupted(r.position() as u64, "unterminated string".into()))?;
    r.skip(end + 1)?;
    Ok(rest[..end].iter().map(|&b| b as char).collect())
}

/// A NUL-terminated UTF-16LE string.
fn utf16_cstr(r: &mut ByteReader<'_>) -> ForensicResult<String> {
    let mut units = Vec::new();
    loop {
        match r.read_u16_le()? {
            0 => break,
            u => units.push(u),
        }
    }
    Ok(String::from_utf16_lossy(&units))
}

/// The longest run of printable UTF-16LE (else single-byte) text in `data`, at least 3
/// characters: a best guess at the name of an item whose layout isn't decoded.
fn readable_string(data: &[u8]) -> Option<String> {
    let printable = |c: u16| (0x20..0xD800).contains(&c) && c != 0x7F;
    let mut best: Option<String> = None;
    let mut keep = |run: String| {
        if run.chars().count() >= 3
            && best
                .as_ref()
                .is_none_or(|b| run.chars().count() > b.chars().count())
        {
            best = Some(run);
        }
    };
    for offset in 0..2 {
        let mut run = Vec::new();
        for pair in data.get(offset..).unwrap_or_default().chunks_exact(2) {
            let unit = u16::from_le_bytes([pair[0], pair[1]]);
            if printable(unit) {
                run.push(unit);
            } else {
                keep(String::from_utf16_lossy(&run));
                run.clear();
            }
        }
        keep(String::from_utf16_lossy(&run));
    }
    // Text that only looks like UTF-16 because it's single-byte: two ASCII bytes form one
    // CJK-range unit. Prefer the single-byte reading then.
    let wide_ascii = best
        .as_ref()
        .is_some_and(|b| b.chars().all(|c| (c as u32) < 0x80));
    if !wide_ascii {
        let mut run = String::new();
        let mut ascii: Option<String> = None;
        for &b in data {
            if (0x20..0x7F).contains(&b) {
                run.push(b as char);
            } else {
                if run.len() >= 3 && ascii.as_ref().is_none_or(|a| run.len() > a.len()) {
                    ascii = Some(run.clone());
                }
                run.clear();
            }
        }
        if run.len() >= 3 && ascii.as_ref().is_none_or(|a| run.len() > a.len()) {
            ascii = Some(run);
        }
        if let Some(ascii) = ascii {
            if best.as_ref().is_none_or(|b| {
                b.chars().any(|c| (c as u32) >= 0x80) || ascii.len() > b.chars().count()
            }) {
                best = Some(ascii);
            }
        }
    }
    best
}

fn corrupted(position: u64, reason: String) -> ForensicError {
    ForensicError::format_corrupted("shell item", position, reason.into())
}

/// One folder (or file) a `BagMRU` tree records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellBagEntry {
    pub user_sid: Option<String>,
    /// The key holding the item's value: `BagMRU` or one of its subkeys.
    pub key: String,
    /// The value's name, as stored (`0`, `1`, ...).
    pub index: String,
    /// The value names from `BagMRU` down to this item, e.g. `[1, 0, 3]`.
    pub mru_path: Vec<u32>,
    pub item: ShellItem,
    /// The item's path, its ancestors' names joined.
    pub path: String,
    /// The item's `NodeSlot`: its view settings are under `Bags\<slot>`.
    pub node_slot: Option<u32>,
    /// Where the parent's `MRUListEx` puts the item, 0 being the most recent; `None` when it
    /// isn't listed.
    pub mru_position: Option<usize>,
    /// Last-write time of the key holding the item's value.
    pub key_last_write: Option<ForensicTimestamp>,
    /// Last-write time of the item's own subkey: when its list of children last changed.
    pub subkey_last_write: Option<ForensicTimestamp>,
}

impl ShellBagEntry {
    /// When the folder was last opened, as far as the tree says: the last-write time of the key
    /// holding it, when the item is first in that key's `MRUListEx`.
    pub fn last_opened(&self) -> Option<ForensicTimestamp> {
        (self.mru_position == Some(0))
            .then_some(self.key_last_write)
            .flatten()
    }
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

/// Every item of the `BagMRU` tree at `key`, parents before children. A missing key is
/// nothing; a key that can't be read, an item that isn't `REG_BINARY` or can't be decoded, is
/// one `Err` item, and the rest of the tree is still read.
pub fn read_shellbags(
    registry: &dyn Registry,
    key: &str,
    user_sid: Option<String>,
) -> Vec<ForensicResult<ShellBagEntry>> {
    let opened = match registry.key(key) {
        Ok(opened) => opened,
        Err(e) if e.is_registry_not_found() => return Vec::new(),
        Err(e) => return vec![Err(e)],
    };
    let mut out = Vec::new();
    let last_write = match opened.info() {
        Ok(info) => info.last_write_time,
        Err(e) => {
            out.push(Err(e));
            None
        }
    };
    let node = Node {
        key: key.to_string(),
        path: String::new(),
        mru_path: Vec::new(),
        last_write,
    };
    walk(&opened, &node, &user_sid, &mut out);
    out
}

/// Where the walk is: the key, the path its items extend, and the key's last-write time.
struct Node {
    key: String,
    path: String,
    mru_path: Vec<u32>,
    last_write: Option<ForensicTimestamp>,
}

fn walk(
    key: &RegKey<'_, dyn Registry + '_>,
    node: &Node,
    user_sid: &Option<String>,
    out: &mut Vec<ForensicResult<ShellBagEntry>>,
) {
    if node.mru_path.len() >= MAX_DEPTH {
        out.push(Err(ForensicError::other(
            "shellbags",
            format!("{}: deeper than {MAX_DEPTH} levels, not followed", node.key),
        )));
        return;
    }
    let values = match key.values() {
        Ok(values) => values,
        Err(e) => {
            out.push(Err(e));
            return;
        }
    };
    let subkeys: BTreeMap<String, Option<ForensicTimestamp>> = match key.keys() {
        Ok(keys) => keys.into_iter().map(|k| (k.name, k.last_write)).collect(),
        Err(e) => {
            out.push(Err(e));
            BTreeMap::new()
        }
    };
    let order = values
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("MRUListEx"))
        .and_then(|(_, v)| v.as_binary().map(mru_order))
        .unwrap_or_default();
    let mut items: Vec<(u32, String, RegValue)> = values
        .into_iter()
        .filter_map(|(name, value)| name.parse::<u32>().ok().map(|i| (i, name, value)))
        .collect();
    items.sort_by_key(|(i, _, _)| *i);
    for (slot, name, value) in items {
        let Some(data) = value.as_binary() else {
            out.push(Err(ForensicError::registry_invalid_type(
                "REG_BINARY",
                format!(r"{value:?} in {}\{name}", node.key),
            )));
            continue;
        };
        let mut mru_path = node.mru_path.clone();
        mru_path.push(slot);
        let (item, segment) = match parse_shell_item(data) {
            Ok(item) => {
                let segment = item.name();
                (Some(item), segment)
            }
            Err(e) => {
                out.push(Err(ForensicError::other(
                    "shellbags",
                    format!(r"{}\{name}: {e}", node.key),
                )));
                (
                    None,
                    format!("<0x{:02x}>", data.get(2).copied().unwrap_or_default()),
                )
            }
        };
        let path = match &item {
            Some(item) if item.is_absolute() || node.path.is_empty() => segment,
            _ => format!(r"{}\{segment}", node.path.trim_end_matches('\\')),
        };
        let child_key = format!(r"{}\{name}", node.key);
        let child = subkeys
            .contains_key(&name)
            .then(|| key.open_child(&name))
            .transpose();
        let child = match child {
            Ok(child) => child,
            Err(e) => {
                out.push(Err(e));
                None
            }
        };
        let node_slot = child
            .as_ref()
            .and_then(|c| c.value("NodeSlot").ok())
            .and_then(|v| v.as_dword());
        let subkey_last_write = subkeys.get(&name).copied().flatten();
        if let Some(item) = item {
            out.push(Ok(ShellBagEntry {
                user_sid: user_sid.clone(),
                key: node.key.clone(),
                mru_position: order.iter().position(|i| *i == name),
                index: name,
                mru_path: mru_path.clone(),
                item,
                path: path.clone(),
                node_slot,
                key_last_write: node.last_write,
                subkey_last_write,
            }));
        }
        if let Some(child) = child {
            let next = Node {
                key: child_key,
                path,
                mru_path,
                last_write: subkey_last_write,
            };
            walk(&child, &next, user_sid, out);
        }
    }
}

/// The user a `HKU\<sid>\...` or `HKU\<sid>_Classes\...` path is under.
fn sid_of(key: &str) -> Option<String> {
    let mut segments = key.split('\\');
    let hive = segments.next()?;
    (hive.eq_ignore_ascii_case("HKU") || hive.eq_ignore_ascii_case("HKEY_USERS"))
        .then(|| segments.next())
        .flatten()
        .map(|user| {
            user.strip_suffix(CLASSES_SUFFIX)
                .unwrap_or(user)
                .to_string()
        })
}

/// [`ArtifactParserFactory`] emitting one [`ForensicData`] per [`ShellBagEntry`].
pub struct ShellBagsParserFactory {
    descriptor: ParserDescriptor,
}

impl Default for ShellBagsParserFactory {
    fn default() -> Self {
        Self {
            descriptor: ParserDescriptor::new(
                "windows.registry.shellbags",
                "ShellBags",
                "Folders, shares and archives each user opened in Explorer, from NTUSER and UsrClass BagMRU",
                env!("CARGO_PKG_VERSION"),
            )
            .with_artifacts(vec![RegistryArtifacts::ShellBags.into()])
            .with_requirements(vec![Requirement::Artifact(ArtifactRef::from_static(DEFINITION))]),
        }
    }
}

impl ShellBagsParserFactory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ArtifactParserFactory for ShellBagsParserFactory {
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
                CompactString::const_new("ShellBagsParserFactory"),
            )
        })?;
        let located = locate_keys(ctx, registry.as_ref(), DEFINITION, &BUILTIN_PATTERNS);
        let definition = located.by_catalog.then_some(DEFINITION);
        let host = ctx.host().to_string();
        let acquisition = ctx.acquisition();
        let mut out: Vec<ForensicResult<ForensicData>> =
            located.errors.into_iter().map(Err).collect();
        for key in located.keys {
            let source = ctx.register_source(match acquisition {
                Acquisition::LiveApi => SourceKey::Live {
                    host: host.clone(),
                    api: "Registry".into(),
                },
                _ => SourceKey::Path(key.path.clone()),
            });
            let sid = key.sid.clone().or_else(|| sid_of(&key.path));
            for entry in read_shellbags(registry.as_ref(), &key.path, sid) {
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
    entry: ShellBagEntry,
) -> ForensicData {
    let last_opened = entry.last_opened();
    let mut data = ForensicData::new(host, RegistryArtifacts::ShellBags.into(), provenance);
    data.set(dictionary::EVENT_ACTION, "folder-opened");
    if let Some(sid) = entry.user_sid {
        data.set(dictionary::USER_ID, sid);
    }
    data.set(dictionary::FILE_PATH, entry.path);
    data.set(dictionary::FILE_NAME, entry.item.name());
    data.set("shellbags.item_type", entry.item.kind());
    match &entry.item {
        ShellItem::File(file) => {
            if let Some(ts) = file.modified {
                data.set(dictionary::FILE_MODIFIED, ts);
            }
            if let Some(ts) = file.created {
                data.set(dictionary::FILE_CREATED, ts);
            }
            if let Some(ts) = file.accessed {
                data.set(dictionary::FILE_ACCESSED, ts);
            }
            if let Some(entry) = file.mft_entry {
                data.set(dictionary::FILE_INODE, entry);
            }
            if let Some(seq) = file.mft_sequence {
                data.set("shellbags.mft_sequence", seq as u64);
            }
        }
        ShellItem::Network(net) => {
            if let Some(description) = &net.description {
                data.set("shellbags.network.description", description.clone());
            }
            if let Some(comment) = &net.comment {
                data.set("shellbags.network.comment", comment.clone());
            }
        }
        ShellItem::RootFolder { guid, .. } | ShellItem::ControlPanel { guid } => {
            data.set("shellbags.guid", guid.clone());
        }
        _ => {}
    }
    let mru_path: Vec<String> = entry.mru_path.iter().map(u32::to_string).collect();
    data.set("shellbags.mru_path", mru_path.join("/"));
    if let Some(position) = entry.mru_position {
        data.set("shellbags.mru_position", position as u64);
    }
    if let Some(slot) = entry.node_slot {
        data.set("shellbags.node_slot", slot as u64);
    }
    if let Some(ts) = entry.subkey_last_write {
        data.set("shellbags.subkey_last_write", ts);
    }
    if let Some(ts) = last_opened {
        data.set("shellbags.last_opened", ts);
    }
    let (_, key) = entry
        .key
        .split_once('\\')
        .unwrap_or(("", entry.key.as_str()));
    data.set(dictionary::REGISTRY_KEY, key.to_string());
    data.set(dictionary::REGISTRY_VALUE, entry.index);
    if let Some(ts) = entry.key_last_write {
        data.set(dictionary::REGISTRY_KEY_LAST_WRITE, ts);
    }
    if let Some(definition) = definition {
        data.set(dictionary::ARTIFACT_DEFINITION, definition);
    }
    data
}
