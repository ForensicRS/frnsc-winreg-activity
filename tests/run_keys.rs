use std::borrow::Cow;
use std::sync::Arc;

use forensic_rs::catalog::{
    ArtifactCatalog, ArtifactDefinition, ArtifactSource, Os, SliceCatalog, SourceEntry,
};
use forensic_rs::prelude::testing::{TestingRegistry, collect_run};
use forensic_rs::{dictionary, prelude::*};
use frnsc_winreg_activity::run_keys::{self, RunKeysParserFactory};

const ALICE: &str = "S-1-5-21-1000-1000-1000-1001";
const CV: &str = r"Software\Microsoft\Windows\CurrentVersion";
const NT: &str = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion";

fn registry() -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    // ProfileList, so a catalog's %%users.sid%% knows Alice.
    reg.add_value(
        &format!(r"{NT}\ProfileList\{ALICE}"),
        "ProfileImagePath",
        RegValue::new_sz(r"C:\Users\alice"),
    );
    let machine_run = format!(r"HKLM\{CV}\Run");
    reg.add_value(
        &machine_run,
        "SecurityHealth",
        RegValue::ExpandSZ(r"%windir%\system32\SecurityHealthSystray.exe".into()),
    );
    reg.set_last_write(
        &machine_run,
        ForensicTimestamp::from_win_filetime(133_514_430_235_959_706),
    );
    reg.add_value(
        r"HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        "OldUpdater",
        RegValue::new_sz(r"C:\Program Files (x86)\Old\upd.exe /silent"),
    );
    reg.add_value(
        &format!(r"HKLM\{CV}\RunOnceEx\0001"),
        "1",
        RegValue::new_sz(r"C:\setup\step1.exe"),
    );
    reg.add_value(
        &format!(r"HKU\{ALICE}\{CV}\Run"),
        "OneDrive",
        RegValue::new_sz(
            r"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe /background",
        ),
    );
    reg.add_value(
        &format!(r"HKU\{ALICE}\{CV}\RunOnce"),
        "Weird",
        RegValue::DWord(7),
    );
    reg
}

fn run(sources: TriageSources) -> Vec<ForensicData> {
    let triage = TriageContext::new("HOST01", "t");
    let cancellation = CancellationToken::new();
    let ctx = ParseContext::new(&sources, &triage, &cancellation);
    let parser = RunKeysParserFactory::new();
    assert!(parser.can_parse(&ctx));
    collect_run(parser.open(&ctx).unwrap())
        .unwrap()
        .into_iter()
        .map(Result::unwrap)
        .collect()
}

fn by_value<'a>(records: &'a [ForensicData], name: &str) -> &'a ForensicData {
    records
        .iter()
        .find(|r| r.field_as_str(dictionary::REGISTRY_VALUE) == Some(name))
        .unwrap_or_else(|| panic!("no record for {name}"))
}

#[test]
fn machine_user_once_and_wow64_entries_are_each_one_record() {
    let records = run(TriageSources::builder()
        .registry(Arc::new(registry()))
        .acquisition(Acquisition::ImageRead)
        .build());
    assert_eq!(records.len(), 5);

    let health = by_value(&records, "SecurityHealth");
    assert_eq!(
        health.field_as_str(dictionary::PROCESS_COMMAND_LINE),
        Some(r"%windir%\system32\SecurityHealthSystray.exe"),
        "kept unexpanded"
    );
    assert!(health.field(dictionary::USER_ID).is_none());
    assert_eq!(
        health.field_as_str(dictionary::REGISTRY_DATA_TYPE),
        Some("REG_EXPAND_SZ")
    );
    assert!(health.field(dictionary::REGISTRY_KEY_LAST_WRITE).is_some());
    assert!(
        health.field(dictionary::TIMESTAMP).is_none(),
        "a Run value has no event time"
    );
    assert!(health.field(dictionary::ARTIFACT_DEFINITION).is_none());

    let onedrive = by_value(&records, "OneDrive");
    assert_eq!(onedrive.field_as_str(dictionary::USER_ID), Some(ALICE));
    assert_eq!(onedrive.field_as_u64("run_keys.once"), Some(0));

    assert_eq!(
        by_value(&records, "OldUpdater").field_as_u64("run_keys.wow64"),
        Some(1)
    );
    let step = by_value(&records, "1");
    assert_eq!(step.field_as_u64("run_keys.once"), Some(1));
    assert_eq!(
        step.field_as_str(dictionary::REGISTRY_KEY),
        Some(r"Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001")
    );

    let weird = by_value(&records, "Weird");
    assert!(weird.field(dictionary::PROCESS_COMMAND_LINE).is_none());
    assert_eq!(
        weird.field_as_str(dictionary::REGISTRY_DATA_TYPE),
        Some("REG_DWORD")
    );
    assert!(
        weird.field("run_keys.data").is_some(),
        "non-string data is kept, not dropped"
    );
}

/// A slice of `WindowsRunKeys` as ForensicArtifacts writes it.
fn catalog() -> Arc<dyn ArtifactCatalog> {
    Arc::new(
        SliceCatalog::new(vec![ArtifactDefinition {
            name: Cow::Borrowed(run_keys::DEFINITION),
            aliases: Cow::Borrowed(&[]),
            doc: Cow::Borrowed(""),
            sources: Cow::Owned(vec![SourceEntry {
                source: ArtifactSource::RegistryKey {
                    keys: Cow::Borrowed(&[
                        Cow::Borrowed(r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\*"),
                        Cow::Borrowed(r"HKEY_USERS\%%users.sid%%\Software\Microsoft\Windows\CurrentVersion\Run\*"),
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
fn with_a_catalog_only_the_definition_s_keys_are_read_and_named() {
    let records = run(TriageSources::builder()
        .registry(Arc::new(registry()))
        .catalog(catalog())
        .acquisition(Acquisition::ImageRead)
        .build());
    let mut names: Vec<&str> = records
        .iter()
        .map(|r| r.field_as_str(dictionary::REGISTRY_VALUE).unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["OneDrive", "SecurityHealth"]);
    assert!(
        records
            .iter()
            .all(|r| r.field_as_str(dictionary::ARTIFACT_DEFINITION) == Some(run_keys::DEFINITION))
    );
    assert_eq!(
        by_value(&records, "OneDrive").field_as_str(dictionary::USER_ID),
        Some(ALICE)
    );
}
