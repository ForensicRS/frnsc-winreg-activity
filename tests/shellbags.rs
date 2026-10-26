use std::sync::Arc;

use forensic_rs::prelude::testing::{TestingRegistry, collect_run};
use forensic_rs::{dictionary, prelude::*};
use frnsc_winreg_activity::shellbags::{
    ShellBagsParserFactory, ShellItem, parse_shell_item, read_shellbags,
};

const ALICE: &str = "S-1-5-21-1000-1000-1000-1001";
const CLASSES_BAGMRU: &str = r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU";
const NTUSER_BAGMRU: &str = r"Software\Microsoft\Windows\Shell\BagMRU";

/// A FAT date (low half) and time (high half).
fn fat(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> u32 {
    let date = ((year - 1980) << 9) | (month << 5) | day;
    let time = (hour << 11) | (minute << 5) | (second / 2);
    date | (time << 16)
}

fn with_size(mut item: Vec<u8>) -> Vec<u8> {
    let size = item.len() as u16;
    item[0..2].copy_from_slice(&size.to_le_bytes());
    item
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn my_computer() -> Vec<u8> {
    // {20D04FE0-3AEA-1069-A2D8-08002B30309D}
    let mut item = vec![0, 0, 0x1F, 0x50];
    item.extend_from_slice(&[
        0xE0, 0x4F, 0xD0, 0x20, 0xEA, 0x3A, 0x69, 0x10, 0xA2, 0xD8, 0x08, 0x00, 0x2B, 0x30, 0x30,
        0x9D,
    ]);
    with_size(item)
}

fn volume(letter: &str) -> Vec<u8> {
    let mut item = vec![0, 0, 0x2F];
    item.extend_from_slice(letter.as_bytes());
    item.resize(25, 0);
    with_size(item)
}

/// A `0x31` directory entry with a version 9 `0xbeef0004` extension.
fn directory(short: &str, long: &str, created: u32, accessed: u32, modified: u32) -> Vec<u8> {
    let mut item = vec![0, 0, 0x31, 0];
    item.extend_from_slice(&0u32.to_le_bytes());
    item.extend_from_slice(&modified.to_le_bytes());
    item.extend_from_slice(&0x10u16.to_le_bytes());
    item.extend_from_slice(short.as_bytes());
    item.push(0);
    if item.len() % 2 == 1 {
        item.push(0);
    }
    let ext_offset = item.len() as u16;
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0, 0]);
    ext.extend_from_slice(&9u16.to_le_bytes());
    ext.extend_from_slice(&0xbeef_0004u32.to_le_bytes());
    ext.extend_from_slice(&created.to_le_bytes());
    ext.extend_from_slice(&accessed.to_le_bytes());
    ext.extend_from_slice(&0x2Eu16.to_le_bytes());
    ext.extend_from_slice(&0u16.to_le_bytes());
    ext.extend_from_slice(&((3u64 << 48) | 0x1234).to_le_bytes()); // MFT entry 0x1234, sequence 3
    ext.extend_from_slice(&0u64.to_le_bytes());
    ext.extend_from_slice(&0u16.to_le_bytes());
    ext.extend_from_slice(&0u32.to_le_bytes());
    ext.extend_from_slice(&0u32.to_le_bytes());
    ext.extend_from_slice(&utf16z(long));
    ext.extend_from_slice(&ext_offset.to_le_bytes());
    let ext_size = ext.len() as u16;
    ext[0..2].copy_from_slice(&ext_size.to_le_bytes());
    item.extend_from_slice(&ext);
    item.extend_from_slice(&[0, 0]);
    with_size(item)
}

fn share(location: &str) -> Vec<u8> {
    let mut item = vec![0, 0, 0xC3, 0x01, 0x00];
    item.extend_from_slice(location.as_bytes());
    item.push(0);
    item.extend_from_slice(&[0, 0]);
    with_size(item)
}

/// A folder inside a ZIP archive, with a junk class byte the way Windows leaves it.
fn archive_entry(name: &str, parent: &str) -> Vec<u8> {
    let mut item = vec![0u8; 0x24];
    item[2] = 0xB5;
    item[0x20..0x24].copy_from_slice(&[0x10, 0x00, 0x01, 0x00]);
    item.extend_from_slice(&utf16z("09/03/2025  00:34:18"));
    item.resize(0x54, 0);
    item.extend_from_slice(&(name.encode_utf16().count() as u32).to_le_bytes());
    item.extend_from_slice(&(parent.encode_utf16().count() as u32).to_le_bytes());
    item.extend_from_slice(&utf16z(name));
    item.extend_from_slice(&utf16z(parent));
    item.extend_from_slice(&[0, 0]);
    with_size(item)
}

fn mru(order: &[u32]) -> RegValue {
    let mut data: Vec<u8> = order.iter().flat_map(|i| i.to_le_bytes()).collect();
    data.extend_from_slice(&u32::MAX.to_le_bytes());
    RegValue::Binary(data)
}

fn bin(data: Vec<u8>) -> RegValue {
    RegValue::Binary(data)
}

fn filetime(unix: i64) -> ForensicTimestamp {
    ForensicTimestamp::from_unix_secs(unix)
}

/// Alice's class hive: My Computer \ C:\ \ Users \ Plans.zip \ a \ VPN, a share, and a value that
/// isn't a shell item.
fn registry() -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    let root = format!(r"HKU\{ALICE}_Classes\{CLASSES_BAGMRU}");
    reg.add_value(&root, "0", bin(my_computer()));
    reg.add_value(&root, "1", bin(share(r"\\fileserver\projects")));
    reg.add_value(&root, "2", bin(vec![0x05, 0x00, 0x31])); // claims 5 bytes, has 3
    reg.add_value(&root, "MRUListEx", mru(&[1, 0, 2]));
    reg.set_last_write(&root, filetime(1_756_885_000));
    let computer = format!(r"{root}\0");
    reg.add_value(&computer, "0", bin(volume(r"C:\")));
    reg.add_value(&computer, "MRUListEx", mru(&[0]));
    reg.add_value(&computer, "NodeSlot", RegValue::DWord(4));
    reg.set_last_write(&computer, filetime(1_756_884_000));
    let drive = format!(r"{computer}\0");
    reg.add_value(
        &drive,
        "0",
        bin(directory(
            "Users",
            "Users",
            fat(2022, 5, 7, 5, 17, 24),
            fat(2025, 9, 3, 7, 2, 48),
            fat(2025, 9, 3, 7, 2, 48),
        )),
    );
    reg.add_value(&drive, "MRUListEx", mru(&[0]));
    let users = format!(r"{drive}\0");
    reg.add_value(
        &users,
        "0",
        bin(directory(
            "PLANS~1.ZIP",
            "Plans.zip",
            fat(2025, 9, 3, 7, 34, 24),
            fat(2025, 9, 3, 7, 34, 26),
            fat(2025, 9, 3, 7, 34, 26),
        )),
    );
    reg.add_value(&users, "MRUListEx", mru(&[0]));
    let zip = format!(r"{users}\0");
    reg.add_value(&zip, "0", bin(archive_entry("a", "")));
    reg.add_value(&zip, "MRUListEx", mru(&[0]));
    let a = format!(r"{zip}\0");
    reg.add_value(&a, "0", bin(archive_entry("VPN", "a/")));
    reg.add_value(&a, "MRUListEx", mru(&[0]));
    let ntuser = format!(r"HKU\{ALICE}\{NTUSER_BAGMRU}");
    reg.add_value(&ntuser, "0", bin(share(r"\\fileserver\projects")));
    reg.add_value(&ntuser, "MRUListEx", mru(&[0]));
    reg
}

#[test]
fn items_decode_by_class() {
    match parse_shell_item(&my_computer()).unwrap() {
        ShellItem::RootFolder { name, .. } => assert_eq!(name, Some("My Computer")),
        other => panic!("{other:?}"),
    }
    assert_eq!(parse_shell_item(&volume(r"C:\")).unwrap().name(), r"C:\");
    let ShellItem::File(dir) = parse_shell_item(&directory(
        "OTSTAT~1",
        "OT Station 3 internal VPN",
        fat(2025, 9, 3, 7, 10, 58),
        fat(2025, 9, 3, 7, 11, 50),
        fat(2025, 9, 3, 7, 11, 50),
    ))
    .unwrap() else {
        panic!("a file entry")
    };
    assert!(dir.is_directory);
    assert_eq!(dir.short_name, "OTSTAT~1");
    assert_eq!(dir.name(), "OT Station 3 internal VPN");
    let accessed = dir.accessed.unwrap();
    assert_eq!(
        (
            accessed.year(),
            accessed.month(),
            accessed.day(),
            accessed.hour(),
            accessed.minute(),
            accessed.second()
        ),
        (2025, 9, 3, 7, 11, 50)
    );
    assert_eq!((dir.mft_entry, dir.mft_sequence), (Some(0x1234), Some(3)));
    match parse_shell_item(&share(r"\\fileserver\projects")).unwrap() {
        ShellItem::Network(net) => assert_eq!(net.location, r"\\fileserver\projects"),
        other => panic!("{other:?}"),
    }
    match parse_shell_item(&archive_entry("OnePassword MasterPass", "a/")).unwrap() {
        ShellItem::ArchiveEntry(entry) => {
            assert_eq!(entry.name, "OnePassword MasterPass");
            assert_eq!(entry.parent_in_archive.as_deref(), Some("a/"));
            assert_eq!(entry.modified_text.as_deref(), Some("09/03/2025  00:34:18"));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_drive_under_a_namespace_root_is_a_volume() {
    let mut item = vec![0, 0, 0x1F, 0x00, 0x2F, 0x00];
    item.extend_from_slice(&0xF5A6_B710u32.to_le_bytes());
    item.extend_from_slice(&[0x29, 0x00, 0x2F]);
    item.extend_from_slice(b"D:\\\0");
    item.resize(0x30, 0);
    assert_eq!(
        parse_shell_item(&with_size(item)).unwrap(),
        ShellItem::Volume {
            name: r"D:\".into()
        }
    );
}

#[test]
fn malformed_items_are_errors_not_panics() {
    for data in [
        vec![],
        vec![0x02],
        vec![0x02, 0x00],
        vec![0x40, 0x00, 0x31, 0x00, 0x00],
        vec![0x14, 0x00, 0x1F, 0x50, 0xE0],
        vec![0x08, 0x00, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00],
        vec![0x08, 0x00, 0x2F, b'C', b':', b'\\', b'x', b'y'],
        vec![0xFF; 64],
    ] {
        let _ = parse_shell_item(&data);
    }
    // A FAT date with month 0 is no time at all, not an error.
    let ShellItem::File(dir) = parse_shell_item(&directory("X", "X", 0x0000_0001, 0, 0)).unwrap()
    else {
        panic!("a file entry")
    };
    assert_eq!(
        (dir.created, dir.accessed, dir.modified),
        (None, None, None)
    );
}

#[test]
fn the_tree_becomes_paths_with_their_times() {
    let entries = read_shellbags(
        &registry(),
        &format!(r"HKU\{ALICE}_Classes\{CLASSES_BAGMRU}"),
        Some(ALICE.into()),
    );
    let errors: Vec<String> = entries
        .iter()
        .filter_map(|e| e.as_ref().err())
        .map(|e| e.to_string())
        .collect();
    assert_eq!(errors.len(), 1, "{errors:?}");
    let entries: Vec<_> = entries.into_iter().filter_map(Result::ok).collect();
    let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "My Computer",
            r"C:\",
            r"C:\Users",
            r"C:\Users\Plans.zip",
            r"C:\Users\Plans.zip\a",
            r"C:\Users\Plans.zip\a\VPN",
            r"\\fileserver\projects",
        ]
    );
    let by = |p: &str| entries.iter().find(|e| e.path == p).unwrap();
    assert_eq!(by(r"\\fileserver\projects").mru_position, Some(0));
    assert_eq!(
        by(r"\\fileserver\projects").last_opened(),
        Some(filetime(1_756_885_000))
    );
    assert_eq!(by("My Computer").last_opened(), None);
    assert_eq!(by("My Computer").node_slot, Some(4));
    assert_eq!(
        by("My Computer").subkey_last_write,
        Some(filetime(1_756_884_000))
    );
    assert_eq!(by(r"C:\").key_last_write, Some(filetime(1_756_884_000)));
    assert_eq!(by(r"C:\Users\Plans.zip\a\VPN").mru_path, [0, 0, 0, 0, 0, 0]);
}

#[test]
fn a_missing_key_is_nothing() {
    assert!(
        read_shellbags(
            &TestingRegistry::empty(),
            &format!(r"HKU\{ALICE}\{NTUSER_BAGMRU}"),
            None
        )
        .is_empty()
    );
}

#[test]
fn the_factory_reads_both_hives_of_each_user() {
    let sources = TriageSources::builder()
        .registry(Arc::new(registry()))
        .acquisition(Acquisition::ImageRead)
        .build();
    let triage = TriageContext::new("HOST01", "t");
    let cancellation = CancellationToken::new();
    let ctx = ParseContext::new(&sources, &triage, &cancellation);
    let items = collect_run(ShellBagsParserFactory::new().open(&ctx).unwrap()).unwrap();
    let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
    assert_eq!(records.len(), 8);
    for r in &records {
        assert_eq!(r.field_as_str(dictionary::USER_ID), Some(ALICE));
        assert!(r.field(dictionary::TIMESTAMP).is_none());
    }
    let vpn = records
        .iter()
        .find(|r| r.field_as_str(dictionary::FILE_PATH) == Some(r"C:\Users\Plans.zip\a\VPN"))
        .unwrap();
    assert_eq!(
        vpn.field_as_str("shellbags.item_type"),
        Some("archive-entry")
    );
    let users = records
        .iter()
        .find(|r| r.field_as_str(dictionary::FILE_PATH) == Some(r"C:\Users"))
        .unwrap();
    assert!(users.field(dictionary::FILE_ACCESSED).is_some());
    assert_eq!(
        records
            .iter()
            .filter(|r| r.field_as_str(dictionary::FILE_PATH) == Some(r"\\fileserver\projects"))
            .count(),
        2,
        "one from NTUSER, one from UsrClass"
    );
}
