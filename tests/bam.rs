use std::borrow::Cow;
use std::sync::Arc;

use forensic_rs::catalog::{
    ArtifactCatalog, ArtifactDefinition, ArtifactSource, Os, SliceCatalog, SourceEntry,
};
use forensic_rs::prelude::testing::{TestingRegistry, collect_run};
use forensic_rs::{dictionary, prelude::*};
use frnsc_winreg_activity::bam::{self, BamParserFactory, Moderator, read_user_key};

const ALICE: &str = "S-1-5-21-1000-1000-1000-1001";
const BOB: &str = "S-1-5-21-1000-1000-1000-1002";
const STATE: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";
/// 2024-02-03 14:10:23.5959706 UTC.
const FILETIME: u64 = 133_514_430_235_959_706;
const CMD: &str = r"\Device\HarddiskVolume3\Windows\System32\cmd.exe";

/// What BAM stores: the FILETIME, then 16 more bytes nobody has documented.
fn bam_data(filetime: u64) -> RegValue {
    let mut data = filetime.to_le_bytes().to_vec();
    data.extend_from_slice(&[0u8; 16]);
    RegValue::Binary(data)
}

fn registry(root: &str) -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    let alice = format!(r"{root}\{ALICE}");
    reg.add_value(&alice, CMD, bam_data(FILETIME));
    reg.add_value(
        &alice,
        "Microsoft.Windows.Photos_8wekyb3d8bbwe",
        bam_data(FILETIME + 10_000_000),
    );
    reg.add_value(&alice, "Version", RegValue::DWord(1));
    reg.add_value(&alice, "SequenceNumber", RegValue::DWord(9));
    reg.add_value(
        &format!(r"{root}\{BOB}"),
        CMD,
        bam_data(FILETIME - 10_000_000),
    );
    reg
}

#[test]
fn one_entry_per_executable_with_the_filetime_and_no_bookkeeping() {
    let reg = registry(STATE);
    let entries: Vec<_> = read_user_key(&reg, &format!(r"{STATE}\{ALICE}"))
        .into_iter()
        .map(Result::unwrap)
        .collect();
    // In the backend's value order (sorted by name for `TestingRegistry`, on-disk for a hive).
    let mut names: Vec<&str> = entries.iter().map(|e| e.executable.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["Microsoft.Windows.Photos_8wekyb3d8bbwe", CMD]);
    let cmd = entries.iter().find(|e| e.executable == CMD).unwrap();
    assert_eq!(cmd.user_sid, ALICE);
    assert_eq!(cmd.moderator, Moderator::Bam);
    assert_eq!(cmd.last_run_raw, FILETIME);
    assert_eq!(
        cmd.last_run,
        Some(ForensicTimestamp::from_win_filetime(FILETIME))
    );
    assert_eq!(cmd.data.len(), 24, "the whole value is kept");
}

#[test]
fn a_zero_filetime_has_no_time_and_bad_data_is_one_error_each() {
    let key = format!(r"{STATE}\{ALICE}");
    let mut reg = TestingRegistry::empty();
    reg.add_value(&key, r"\Device\HarddiskVolume3\never.exe", bam_data(0));
    reg.add_value(
        &key,
        r"\Device\HarddiskVolume3\short.exe",
        RegValue::Binary(vec![1, 2, 3]),
    );
    reg.add_value(
        &key,
        r"\Device\HarddiskVolume3\string.exe",
        RegValue::new_sz("oops"),
    );
    reg.add_value(&key, r"\Device\HarddiskVolume3\ok.exe", bam_data(FILETIME));
    let items = read_user_key(&reg, &key);
    assert_eq!(items.len(), 4);
    let errors: Vec<String> = items
        .iter()
        .filter_map(|i| i.as_ref().err())
        .map(|e| e.to_string())
        .collect();
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("short.exe") && e.contains("3 byte")),
        "{errors:?}"
    );
    let never = items
        .iter()
        .filter_map(|i| i.as_ref().ok())
        .find(|e| e.executable.ends_with("never.exe"))
        .unwrap();
    assert_eq!(never.last_run_raw, 0);
    assert_eq!(never.last_run, None, "never a made-up 1601 date");
}

#[test]
fn the_desktop_moderator_and_the_1709_layout_are_read_too() {
    for root in [
        r"HKLM\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings",
        r"HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings",
    ] {
        let entries = read_user_key(&registry(root), &format!(r"{root}\{BOB}"));
        assert_eq!(entries.len(), 1, "{root}");
        let expected = if root.contains(r"\dam\") {
            Moderator::Dam
        } else {
            Moderator::Bam
        };
        assert_eq!(entries[0].as_ref().unwrap().moderator, expected);
    }
}

fn run(sources: TriageSources) -> (Vec<ForensicData>, ProvenanceStore) {
    let triage = TriageContext::new("HOST01", "t");
    let store = triage.provenance_store();
    let cancellation = CancellationToken::new();
    let ctx = ParseContext::new(&sources, &triage, &cancellation);
    let parser = BamParserFactory::new();
    assert!(parser.can_parse(&ctx));
    let records = collect_run(parser.open(&ctx).unwrap())
        .unwrap()
        .into_iter()
        .map(Result::unwrap)
        .collect();
    (records, store)
}

#[test]
fn without_a_catalog_each_user_is_a_record_set_of_its_own_with_the_run_time() {
    let (records, store) = run(TriageSources::builder()
        .registry(Arc::new(registry(STATE)))
        .acquisition(Acquisition::ImageRead)
        .build());
    assert_eq!(records.len(), 3);
    for record in &records {
        let sid = record.field_as_str(dictionary::USER_ID).unwrap();
        assert!(record.field(dictionary::TIMESTAMP).is_some());
        assert!(record.field(dictionary::ARTIFACT_DEFINITION).is_none());
        let source = store.get(record.provenance()).unwrap().source;
        assert_eq!(source, SourceKey::Path(format!(r"{STATE}\{sid}")));
    }
    let bob = records
        .iter()
        .find(|r| r.field_as_str(dictionary::USER_ID) == Some(BOB))
        .unwrap();
    assert_eq!(bob.field_as_str(dictionary::PROCESS_EXECUTABLE), Some(CMD));
    assert_eq!(
        bob.field_as_str(dictionary::EVENT_ACTION),
        Some("bam-last-run")
    );
}

/// `WindowsBackgroundActivityModeratorKeys` as ForensicArtifacts defines it, restated: the
/// published crate can't depend on frnsc-artifacts.
fn catalog() -> Arc<dyn ArtifactCatalog> {
    Arc::new(
        SliceCatalog::new(vec![ArtifactDefinition {
            name: Cow::Borrowed(bam::DEFINITION),
            aliases: Cow::Borrowed(&[]),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(vec![SourceEntry {
                source: ArtifactSource::RegistryKey {
                    keys: Cow::Borrowed(&[
                        Cow::Borrowed(r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\bam\UserSettings\*"),
                        Cow::Borrowed(r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\bam\State\UserSettings\*"),
                        Cow::Borrowed(r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\dam\UserSettings\*"),
                        Cow::Borrowed(r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\dam\State\UserSettings\*"),
                    ]),
                },
                supported_os: Cow::Borrowed(&[]),
            }]),
            supported_os: Cow::Borrowed(&[Os::Windows]),
            urls: Cow::Borrowed(&[]),
        }])
        .unwrap(),
    )
}

#[test]
fn with_a_catalog_the_definition_s_keys_are_read_and_named() {
    // `TestingRegistry` matches key names case-sensitively, so the keys use the KB's spelling.
    let root = r"HKLM\System\CurrentControlSet\Services\bam\State\UserSettings";
    let (records, _) = run(TriageSources::builder()
        .registry(Arc::new(registry(root)))
        .catalog(catalog())
        .acquisition(Acquisition::ImageRead)
        .build());
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|r| r.field_as_str(dictionary::ARTIFACT_DEFINITION) == Some(bam::DEFINITION))
    );
}
