use std::sync::Arc;

use forensic_rs::prelude::testing::{TestingRegistry, collect_run};
use forensic_rs::{dictionary, prelude::*};
use frnsc_winreg_activity::services::{
    ServicesParserFactory, read_service, start_name, type_names,
};

const SERVICES: &str = r"HKLM\SYSTEM\CurrentControlSet\Services";

fn registry() -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    let schedule = format!(r"{SERVICES}\Schedule");
    reg.add_value(
        &schedule,
        "ImagePath",
        RegValue::ExpandSZ(r"%systemroot%\system32\svchost.exe -k netsvcs -p".into()),
    );
    reg.add_value(
        &schedule,
        "DisplayName",
        RegValue::new_sz("@%SystemRoot%\\system32\\schedsvc.dll,-100"),
    );
    reg.add_value(&schedule, "ObjectName", RegValue::new_sz("LocalSystem"));
    reg.add_value(&schedule, "Start", RegValue::DWord(2));
    reg.add_value(&schedule, "Type", RegValue::DWord(0x20));
    reg.add_value(
        &format!(r"{schedule}\Parameters"),
        "ServiceDll",
        RegValue::ExpandSZ(r"%systemroot%\system32\schedsvc.dll".into()),
    );
    reg.set_last_write(
        &schedule,
        ForensicTimestamp::from_win_filetime(133_514_430_235_959_706),
    );
    let driver = format!(r"{SERVICES}\evil");
    reg.add_value(
        &driver,
        "ImagePath",
        RegValue::new_sz(r"\??\C:\Users\Public\evil.sys"),
    );
    reg.add_value(&driver, "Start", RegValue::DWord(1));
    reg.add_value(&driver, "Type", RegValue::DWord(1));
    // A Start of the wrong type: reported, and the rest of the service still comes out.
    let odd = format!(r"{SERVICES}\Odd");
    reg.add_value(&odd, "ImagePath", RegValue::new_sz(r"C:\odd.exe"));
    reg.add_value(&odd, "Start", RegValue::new_sz("2"));
    reg
}

#[test]
fn a_svchost_service_carries_its_service_dll_start_and_account() {
    let reg = registry();
    let items = read_service(&reg, &format!(r"{SERVICES}\Schedule"));
    assert_eq!(items.len(), 1);
    let entry = items[0].as_ref().unwrap();
    assert_eq!(entry.name, "Schedule");
    assert_eq!(
        entry.service_dll.as_deref(),
        Some(r"%systemroot%\system32\schedsvc.dll")
    );
    assert_eq!(entry.object_name.as_deref(), Some("LocalSystem"));
    assert_eq!(entry.start, Some(2));
    assert_eq!(start_name(2), "automatic");
    assert_eq!(type_names(0x20), ["share_process"]);
    assert!(entry.key_last_write.is_some());
}

#[test]
fn a_value_of_the_wrong_type_is_one_error_beside_the_record() {
    let reg = registry();
    let items = read_service(&reg, &format!(r"{SERVICES}\Odd"));
    assert_eq!(items.len(), 2);
    let entry = items[0].as_ref().unwrap();
    assert_eq!(entry.image_path.as_deref(), Some(r"C:\odd.exe"));
    assert_eq!(entry.start, None, "never a guessed Start");
    let error = items[1].as_ref().unwrap_err().to_string();
    assert!(
        error.contains("Start") && error.contains("REG_DWORD"),
        "{error}"
    );
}

#[test]
fn every_service_is_one_record_with_no_event_time() {
    let sources = TriageSources::builder()
        .registry(Arc::new(registry()))
        .acquisition(Acquisition::ImageRead)
        .build();
    let triage = TriageContext::new("HOST01", "t");
    let cancellation = CancellationToken::new();
    let ctx = ParseContext::new(&sources, &triage, &cancellation);
    let items = collect_run(ServicesParserFactory::new().open(&ctx).unwrap()).unwrap();
    let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
    assert_eq!(records.len(), 3);
    assert_eq!(items.iter().filter(|i| i.is_err()).count(), 1);
    let evil = records
        .iter()
        .find(|r| r.field_as_str(dictionary::SERVICE_NAME) == Some("evil"))
        .unwrap();
    assert_eq!(
        evil.field_as_str("service.image_path"),
        Some(r"\??\C:\Users\Public\evil.sys")
    );
    assert_eq!(evil.field_as_str("service.start_name"), Some("system"));
    assert_eq!(
        evil.field("service.type_names"),
        Some(&Field::Array(vec![Text::Borrowed("kernel_driver")]))
    );
    assert!(
        records
            .iter()
            .all(|r| r.field(dictionary::TIMESTAMP).is_none())
    );
}
