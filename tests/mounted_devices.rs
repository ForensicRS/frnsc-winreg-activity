use std::sync::Arc;

use forensic_rs::prelude::testing::{TestingRegistry, collect_run};
use forensic_rs::{dictionary, prelude::*};
use frnsc_winreg_activity::mounted_devices::{
    MountedDevicesParserFactory, Target, decode_target, read_mounted_devices,
};

const KEY: &str = r"HKLM\SYSTEM\MountedDevices";

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn registry() -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    // MBR: disk signature 0x1a2b3c4d, partition at 1 MiB.
    let mut mbr = 0x1a2b_3c4d_u32.to_le_bytes().to_vec();
    mbr.extend_from_slice(&1_048_576u64.to_le_bytes());
    reg.add_value(KEY, r"\DosDevices\C:", RegValue::Binary(mbr));
    // GPT: DMIO:ID: + the partition GUID {01020304-0506-0708-090a-0b0c0d0e0f10}.
    let mut gpt = b"DMIO:ID:".to_vec();
    gpt.extend((1u8..=16).collect::<Vec<_>>());
    reg.add_value(
        KEY,
        r"\??\Volume{6f1c5b2e-0000-0000-0000-100000000000}",
        RegValue::Binary(gpt),
    );
    reg.add_value(
        KEY,
        r"\DosDevices\E:",
        RegValue::Binary(utf16(r"\??\USBSTOR#Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00#4C530001#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")),
    );
    reg.add_value(
        KEY,
        r"\DosDevices\Z:",
        RegValue::Binary(vec![0xff, 0x00, 0x01]),
    );
    reg
}

#[test]
fn mbr_gpt_and_device_targets_decode_and_anything_else_is_kept_raw() {
    let devices: Vec<_> = read_mounted_devices(&registry(), KEY)
        .into_iter()
        .map(Result::unwrap)
        .collect();
    let by = |mount: &str| devices.iter().find(|d| d.mount_point == mount).unwrap();
    let c = by(r"\DosDevices\C:");
    assert_eq!(c.drive_letter.as_deref(), Some("C:"));
    assert_eq!(
        c.target,
        Target::Mbr {
            disk_signature: 0x1a2b_3c4d,
            partition_offset: 1_048_576
        }
    );
    let volume = by(r"\??\Volume{6f1c5b2e-0000-0000-0000-100000000000}");
    assert_eq!(
        volume.volume_guid.as_deref(),
        Some("{6f1c5b2e-0000-0000-0000-100000000000}")
    );
    assert_eq!(
        volume.target,
        Target::Gpt {
            partition_guid: "{04030201-0605-0807-090a-0b0c0d0e0f10}".into()
        }
    );
    let Target::Device { path } = &by(r"\DosDevices\E:").target else {
        panic!()
    };
    assert!(path.starts_with(r"\??\USBSTOR#Disk&Ven_SanDisk"));
    let z = by(r"\DosDevices\Z:");
    assert_eq!(z.target, Target::Unknown);
    assert_eq!(z.data, [0xff, 0x00, 0x01], "kept as stored");
    // Binary that happens to decode as UTF-16 but isn't text is not called a device path.
    assert_eq!(decode_target(&[0x01, 0x00, 0x02, 0x00]), Target::Unknown);
}

#[test]
fn every_mount_point_is_one_record_with_no_event_time() {
    let sources = TriageSources::builder()
        .registry(Arc::new(registry()))
        .acquisition(Acquisition::ImageRead)
        .build();
    let triage = TriageContext::new("HOST01", "t");
    let cancellation = CancellationToken::new();
    let ctx = ParseContext::new(&sources, &triage, &cancellation);
    let records: Vec<ForensicData> =
        collect_run(MountedDevicesParserFactory::new().open(&ctx).unwrap())
            .unwrap()
            .into_iter()
            .map(Result::unwrap)
            .collect();
    assert_eq!(records.len(), 4);
    assert!(
        records
            .iter()
            .all(|r| r.field(dictionary::TIMESTAMP).is_none())
    );
    let c = records
        .iter()
        .find(|r| r.field_as_str("mounted_device.drive_letter") == Some("C:"))
        .unwrap();
    assert_eq!(c.field_as_str("mounted_device.kind"), Some("mbr"));
    assert_eq!(
        c.field_as_str("mounted_device.disk_signature"),
        Some("1a2b3c4d")
    );
}
