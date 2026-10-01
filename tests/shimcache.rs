//! Every cache layout, built byte by byte from the documented structures (libyal winreg-kb).

use std::sync::Arc;

use forensic_rs::prelude::testing::{TestingRegistry, collect_run};
use forensic_rs::{dictionary, prelude::*};
use frnsc_winreg_activity::shimcache::{Format, ShimCacheParserFactory, detect, parse};

const T1: u64 = 133_514_430_235_959_706;
const T2: u64 = 129_000_000_000_000_000;
const P1: &str = r"\??\C:\Windows\system32\cmd.exe";
const P2: &str = r"C:\Tools\tool.exe";

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn put(blob: &mut Vec<u8>, at: usize, bytes: &[u8]) {
    if blob.len() < at + bytes.len() {
        blob.resize(at + bytes.len(), 0);
    }
    blob[at..at + bytes.len()].copy_from_slice(bytes);
}

/// XP: 400-byte header, 552-byte entries with the path inline.
fn xp() -> Vec<u8> {
    let mut b = vec![0u8; 400];
    put(&mut b, 0, &0xdead_beef_u32.to_le_bytes());
    put(&mut b, 4, &2u32.to_le_bytes());
    for (i, (path, time, size)) in [(P1, T1, 1000u64), (P2, T2, 2000)].into_iter().enumerate() {
        let at = 400 + i * 552;
        put(&mut b, at, &utf16(path));
        put(&mut b, at + 528, &time.to_le_bytes());
        put(&mut b, at + 536, &size.to_le_bytes());
        put(&mut b, at + 544, &0u64.to_le_bytes());
    }
    b
}

/// 2003/Vista and 7: header, fixed entries, then the strings (and 7's data) they point at.
fn fixed(signature: u32, header: usize, wide: bool, seven: bool) -> Vec<u8> {
    let size = match (seven, wide) {
        (false, false) => 24,
        (false, true) => 32,
        (true, false) => 32,
        (true, true) => 48,
    };
    let entries = [(P1, T1, 0x2u32), (P2, T2, 0x0)];
    let mut b = vec![0u8; header + entries.len() * size];
    put(&mut b, 0, &signature.to_le_bytes());
    put(&mut b, 4, &(entries.len() as u32).to_le_bytes());
    for (i, (path, time, insertion)) in entries.into_iter().enumerate() {
        let path_offset = b.len();
        let path = utf16(path);
        b.extend_from_slice(&path);
        let data_offset = b.len();
        let data = [0xAA, 0xBB, 0xCC];
        if seven {
            b.extend_from_slice(&data);
        }
        let e = header + i * size;
        put(&mut b, e, &(path.len() as u16).to_le_bytes());
        put(&mut b, e + 2, &(path.len() as u16 + 2).to_le_bytes());
        let rest = if wide {
            put(&mut b, e + 8, &(path_offset as u64).to_le_bytes());
            16
        } else {
            put(&mut b, e + 4, &(path_offset as u32).to_le_bytes());
            8
        };
        put(&mut b, e + rest, &time.to_le_bytes());
        if seven {
            put(&mut b, e + rest + 8, &insertion.to_le_bytes());
            put(&mut b, e + rest + 12, &0x1u32.to_le_bytes());
            if wide {
                put(&mut b, e + rest + 16, &(data.len() as u64).to_le_bytes());
                put(&mut b, e + rest + 24, &(data_offset as u64).to_le_bytes());
            } else {
                put(&mut b, e + rest + 16, &(data.len() as u32).to_le_bytes());
                put(&mut b, e + rest + 20, &(data_offset as u32).to_le_bytes());
            }
        } else {
            put(&mut b, e + rest + 8, &4096u64.to_le_bytes());
        }
    }
    b
}

/// 8, 8.1 and 10: header, then self-sized signed entries.
fn signed(format: Format) -> Vec<u8> {
    let (header, signature): (usize, &[u8]) = match format {
        Format::Windows8 => (0x80, b"00ts"),
        Format::Windows81 => (0x80, b"10ts"),
        _ => (0x34, b"10ts"),
    };
    let mut b = vec![0u8; header];
    put(&mut b, 0, &(header as u32).to_le_bytes());
    for (path, time, insertion) in [(P1, T1, 0x2u32), (P2, T2, 0x0)] {
        let mut body = Vec::new();
        let path = utf16(path);
        body.extend_from_slice(&(path.len() as u16).to_le_bytes());
        body.extend_from_slice(&path);
        if format == Format::Windows81 {
            let package = utf16("Microsoft.App_8wekyb3d8bbwe");
            body.extend_from_slice(&(package.len() as u16).to_le_bytes());
            body.extend_from_slice(&package);
        }
        if format != Format::Windows10 {
            body.extend_from_slice(&insertion.to_le_bytes());
            body.extend_from_slice(&0x1u32.to_le_bytes());
        }
        body.extend_from_slice(&time.to_le_bytes());
        body.extend_from_slice(&3u32.to_le_bytes());
        body.extend_from_slice(&[1, 2, 3]);
        b.extend_from_slice(signature);
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&(body.len() as u32).to_le_bytes());
        b.extend_from_slice(&body);
    }
    b
}

fn check(blob: &[u8], expected: Format, executed: Option<bool>) {
    let (format, entries) = parse(blob);
    assert_eq!(format, Some(expected));
    let entries: Vec<_> = entries.into_iter().map(Result::unwrap).collect();
    assert_eq!(entries.len(), 2, "{expected:?}");
    assert_eq!(entries[0].position, 0);
    assert_eq!(entries[0].path, P1, "{expected:?}");
    assert_eq!(entries[1].path, P2, "{expected:?}");
    assert_eq!(entries[0].last_modified_raw, T1);
    assert_eq!(
        entries[0].last_modified,
        Some(ForensicTimestamp::from_win_filetime(T1))
    );
    assert_eq!(entries[0].executed, executed, "{expected:?}");
    if executed.is_some() {
        assert_eq!(entries[1].executed, Some(false));
    }
}

#[test]
fn every_layout_decodes_its_entries_in_cache_order() {
    check(&xp(), Format::WindowsXp, None);
    check(
        &fixed(0xbadc_0ffe, 8, false, false),
        Format::Windows2003Vista32,
        None,
    );
    check(
        &fixed(0xbadc_0ffe, 8, true, false),
        Format::Windows2003Vista64,
        None,
    );
    check(
        &fixed(0xbadc_0fee, 128, false, true),
        Format::Windows7_32,
        Some(true),
    );
    check(
        &fixed(0xbadc_0fee, 128, true, true),
        Format::Windows7_64,
        Some(true),
    );
    check(&signed(Format::Windows8), Format::Windows8, Some(true));
    check(&signed(Format::Windows81), Format::Windows81, Some(true));
    // 10 and 11 record no execution flag: absent, not false.
    check(&signed(Format::Windows10), Format::Windows10, None);
}

#[test]
fn layout_specific_fields_are_kept_as_stored() {
    let (_, xp) = parse(&xp());
    assert_eq!(xp[1].as_ref().unwrap().file_size, Some(2000));
    let (_, vista) = parse(&fixed(0xbadc_0ffe, 8, true, false));
    assert_eq!(vista[0].as_ref().unwrap().size_or_flags, Some(4096));
    let (_, seven) = parse(&fixed(0xbadc_0fee, 128, true, true));
    assert_eq!(seven[0].as_ref().unwrap().data, [0xAA, 0xBB, 0xCC]);
    let (_, eight_one) = parse(&signed(Format::Windows81));
    assert_eq!(
        eight_one[0].as_ref().unwrap().package.as_deref(),
        Some("Microsoft.App_8wekyb3d8bbwe")
    );
    let (_, ten) = parse(&signed(Format::Windows10));
    assert_eq!(ten[1].as_ref().unwrap().data, [1, 2, 3]);
}

#[test]
fn an_unknown_header_is_one_error() {
    let (format, entries) = parse(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(format, None);
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0]
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("unknown cache layout")
    );
    assert!(detect(&[1, 2]).is_err(), "too short for a header");
}

#[test]
fn a_corrupt_count_is_one_truncation_error_not_a_flood() {
    let mut blob = fixed(0xbadc_0fee, 128, false, true);
    blob[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    let (_, entries) = parse(&blob);
    let errors = entries.iter().filter(|e| e.is_err()).count();
    assert!(entries.len() < 100, "{} items", entries.len());
    assert!(errors >= 1);
}

#[test]
fn a_signed_layout_stops_at_a_broken_entry_and_says_so() {
    let mut blob = signed(Format::Windows10);
    let second = blob.windows(4).rposition(|w| w == b"10ts").unwrap();
    blob[second..second + 4].copy_from_slice(b"XXXX");
    let (_, entries) = parse(&blob);
    assert_eq!(entries.len(), 2);
    assert!(entries[0].is_ok());
    assert!(
        entries[1]
            .as_ref()
            .unwrap_err()
            .to_string()
            .contains("can't be framed")
    );
}

#[test]
fn a_zero_time_is_none_and_a_bad_path_is_flagged_not_dropped() {
    let mut blob = signed(Format::Windows10);
    let first_time = 0x34 + 12 + 2 + utf16(P1).len();
    blob[first_time..first_time + 8].copy_from_slice(&0u64.to_le_bytes());
    // An unpaired surrogate in the first path.
    blob[0x34 + 14..0x34 + 16].copy_from_slice(&0xD800u16.to_le_bytes());
    let (_, entries) = parse(&blob);
    let first = entries[0].as_ref().unwrap();
    assert_eq!(first.last_modified, None);
    assert!(first.path_lossy);
}

const CACHE: &str = r"Control\Session Manager\AppCompatCache";

fn registry() -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    reg.add_value(r"HKLM\SYSTEM\Select", "Current", RegValue::DWord(1));
    // The double has no CurrentControlSet link: the current cache is under both names, as a
    // hive reader would show it, and ControlSet001 must not be read twice.
    let current = fixed(0xbadc_0fee, 128, true, true);
    reg.add_value(
        &format!(r"HKLM\SYSTEM\CurrentControlSet\{CACHE}"),
        "AppCompatCache",
        RegValue::Binary(current.clone()),
    );
    reg.add_value(
        &format!(r"HKLM\SYSTEM\ControlSet001\{CACHE}"),
        "AppCompatCache",
        RegValue::Binary(current),
    );
    reg.add_value(
        &format!(r"HKLM\SYSTEM\ControlSet002\{CACHE}"),
        "AppCompatCache",
        RegValue::Binary(signed(Format::Windows10)),
    );
    reg
}

#[test]
fn every_control_set_s_cache_is_read_once_with_no_event_time() {
    let sources = TriageSources::builder()
        .registry(Arc::new(registry()))
        .acquisition(Acquisition::ImageRead)
        .build();
    let triage = TriageContext::new("HOST01", "t");
    let cancellation = CancellationToken::new();
    let ctx = ParseContext::new(&sources, &triage, &cancellation);
    let records: Vec<ForensicData> = collect_run(ShimCacheParserFactory::new().open(&ctx).unwrap())
        .unwrap()
        .into_iter()
        .map(Result::unwrap)
        .collect();
    let sets: Vec<(&str, &str)> = records
        .iter()
        .map(|r| {
            (
                r.field_as_str("shimcache.control_set").unwrap(),
                r.field_as_str("shimcache.format").unwrap(),
            )
        })
        .collect();
    assert_eq!(
        sets,
        [
            ("ControlSet002", "windows_10"),
            ("ControlSet002", "windows_10"),
            ("CurrentControlSet", "windows_7_64"),
            ("CurrentControlSet", "windows_7_64"),
        ]
    );
    let cmd = records
        .iter()
        .find(|r| {
            r.field_as_str("shimcache.control_set") == Some("CurrentControlSet")
                && r.field_as_u64("shimcache.position") == Some(0)
        })
        .unwrap();
    assert_eq!(cmd.field_as_str(dictionary::FILE_PATH), Some(P1));
    assert!(cmd.field("file.mtime").is_some());
    assert!(
        cmd.field(dictionary::TIMESTAMP).is_none(),
        "a file's mtime is not when it ran"
    );
    assert_eq!(cmd.field_as_u64("shimcache.executed"), Some(1));
}

/// Evidence bytes never panic the decoder: random bodies behind every known header, and every
/// truncation of every valid layout.
#[test]
fn random_and_truncated_caches_never_panic() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let heads: [&[u8]; 6] = [
        &0xdead_beef_u32.to_le_bytes(),
        &0xbadc_0ffe_u32.to_le_bytes(),
        &0xbadc_0fee_u32.to_le_bytes(),
        &0x80u32.to_le_bytes(),
        &0x30u32.to_le_bytes(),
        &0x34u32.to_le_bytes(),
    ];
    for _ in 0..2_000 {
        let len = (next() % 2048) as usize;
        let mut blob: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        put(&mut blob, 0, heads[(next() % heads.len() as u64) as usize]);
        if next() % 2 == 0 {
            put(
                &mut blob,
                128,
                if next() % 2 == 0 { b"00ts" } else { b"10ts" },
            );
        }
        let _ = parse(&blob);
    }
    for valid in [
        xp(),
        fixed(0xbadc_0ffe, 8, true, false),
        fixed(0xbadc_0fee, 128, false, true),
        signed(Format::Windows81),
        signed(Format::Windows10),
    ] {
        for cut in 0..valid.len() {
            let _ = parse(&valid[..cut]);
        }
    }
}
