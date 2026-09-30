use std::sync::Arc;

use forensic_rs::{dictionary, prelude::testing::TestingRegistry, prelude::*};
use frnsc_winreg_activity::{
    AppId, Counter, FeatureUsageEntry, FeatureUsageParserFactory, read_feature_usage,
};

const ALICE: &str = "S-1-5-21-1000-1000-1000-1001";
const BOB: &str = "S-1-5-21-1000-1000-1000-1002";
const POWERSHELL_CSIDL: &str =
    r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

fn counter_path(sid: &str, counter: &str) -> String {
    format!(r"HKU\{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\{counter}")
}

fn registry() -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    for (sid, switches) in [(ALICE, 5), (BOB, 7)] {
        reg.add_value(
            &counter_path(sid, "AppSwitched"),
            "Brave",
            RegValue::from_u32(switches),
        );
    }
    reg.add_value(
        &counter_path(ALICE, "AppSwitched"),
        "*PID00000f9c",
        RegValue::from_u32(2),
    );
    reg.add_value(
        &counter_path(ALICE, "AppLaunch"),
        POWERSHELL_CSIDL,
        RegValue::from_u32(3),
    );
    reg.add_value(
        &counter_path(ALICE, "TrayButtonClicked"),
        "Clock",
        RegValue::from_u32(11),
    );
    reg.add_value(
        &counter_path(BOB, "AppBadgeUpdated"),
        "Mail",
        RegValue::new_sz("not a counter"),
    );
    reg.add_value(
        &counter_path(BOB, "ShowJumpView"),
        "Brave",
        RegValue::from_u32(1),
    );
    // A user hive with no FeatureUsage key, and a Classes hive that must be skipped.
    reg.add_value(
        r"HKU\S-1-5-21-1000-1000-1000-1003\Environment",
        "TEMP",
        RegValue::new_sz("x"),
    );
    reg.add_value(
        &counter_path(&format!("{ALICE}_Classes"), "AppSwitched"),
        "Nope",
        RegValue::from_u32(1),
    );
    reg
}

fn with_profile(reg: &mut TestingRegistry, sid: &str, home: &str) {
    reg.add_value(
        &format!(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}"),
        "ProfileImagePath",
        RegValue::new_sz(home),
    );
}

fn ok_entries(entries: &[ForensicResult<FeatureUsageEntry>]) -> Vec<&FeatureUsageEntry> {
    entries.iter().filter_map(|e| e.as_ref().ok()).collect()
}

#[test]
fn users_are_kept_apart() {
    let entries = read_feature_usage(&registry());
    let brave_switches: Vec<_> = ok_entries(&entries)
        .into_iter()
        .filter(|e| e.counter == Counter::Switches && e.raw_name == "Brave")
        .map(|e| (e.user_sid.as_str(), e.count))
        .collect();
    assert_eq!(brave_switches, vec![(ALICE, 5), (BOB, 7)]);
}

#[test]
fn reads_every_counter_and_skips_classes_hive() {
    let entries = read_feature_usage(&registry());
    let ok = ok_entries(&entries);
    let summary: Vec<_> = ok
        .iter()
        .map(|e| {
            (
                &e.user_sid[e.user_sid.len() - 4..],
                e.counter,
                e.raw_name.as_str(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("1001", Counter::Launches, POWERSHELL_CSIDL),
            // Value order is the backend's; TestingRegistry keeps values sorted by name.
            ("1001", Counter::Switches, "*PID00000f9c"),
            ("1001", Counter::Switches, "Brave"),
            ("1001", Counter::TrayClicks, "Clock"),
            ("1002", Counter::Switches, "Brave"),
            ("1002", Counter::JumpViewClicks, "Brave"),
        ]
    );
    assert!(ok.iter().any(|e| e.app == AppId::Process(3996)));
}

#[test]
fn non_dword_value_is_one_error_and_reading_continues() {
    let entries = read_feature_usage(&registry());
    let errors: Vec<_> = entries.iter().filter_map(|e| e.as_ref().err()).collect();
    // ProfileList isn't seeded, so the env-var lookup also reports an error.
    assert!(
        errors
            .iter()
            .any(|e| e.to_string().contains("AppBadgeUpdated")),
        "{errors:?}"
    );
    assert_eq!(ok_entries(&entries).len(), 6);
}

#[test]
fn csidl_paths_resolve_with_a_profile_and_stay_raw_without() {
    let entries = read_feature_usage(&registry());
    let launch = ok_entries(&entries)
        .into_iter()
        .find(|e| e.counter == Counter::Launches)
        .unwrap()
        .clone();
    assert_eq!(launch.app, AppId::UnresolvedCsidl(POWERSHELL_CSIDL.into()));

    let mut reg = registry();
    with_profile(&mut reg, ALICE, r"C:\Users\alice");
    reg.add_value(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "SystemRoot",
        RegValue::new_sz(r"C:\Windows"),
    );
    let entries = read_feature_usage(&reg);
    let launch = ok_entries(&entries)
        .into_iter()
        .find(|e| e.counter == Counter::Launches)
        .unwrap()
        .clone();
    assert_eq!(launch.raw_name, POWERSHELL_CSIDL);
    assert_eq!(
        launch.app,
        AppId::Executable(r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe".into())
    );
    // `%windir%` was read from SystemRoot, not assumed.
    assert!(launch.assumed_vars.is_empty(), "{:?}", launch.assumed_vars);
}

#[test]
fn a_path_resolved_through_a_default_is_marked() {
    // A profile but no SystemRoot: `%windir%` falls back to `C:\Windows`.
    let mut reg = registry();
    with_profile(&mut reg, ALICE, r"C:\Users\alice");
    let entries = read_feature_usage(&reg);
    let launch = ok_entries(&entries)
        .into_iter()
        .find(|e| e.counter == Counter::Launches)
        .unwrap()
        .clone();
    assert_eq!(
        launch.app,
        AppId::Executable(r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe".into())
    );
    assert_eq!(launch.assumed_vars, vec!["windir".to_string()]);

    let records = run_pipeline(reg);
    let marked = records
        .iter()
        .find(|r| r.field("feature_usage.app.assumed_vars").is_some())
        .expect("the resolved path is marked");
    assert_eq!(
        marked
            .field(dictionary::PROCESS_EXECUTABLE)
            .map(|f| f.to_string()),
        Some(r"C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe".to_string())
    );
}

#[test]
fn counter_key_last_write_is_carried_through() {
    let ts = ForensicTimestamp::from_win_filetime(133_514_430_235_959_706);
    let mut reg = registry();
    reg.set_last_write(&counter_path(ALICE, "AppSwitched"), ts);
    let entries = read_feature_usage(&reg);
    for e in ok_entries(&entries) {
        let expected = (e.user_sid == ALICE && e.counter == Counter::Switches).then_some(ts);
        assert_eq!(e.key_last_write, expected, "{e:?}");
    }
    let records = run_pipeline(reg);
    assert_eq!(
        records
            .iter()
            .filter(|r| r.field("registry.key.last_write").is_some())
            .count(),
        2,
        "Alice's two AppSwitched values"
    );
    assert!(records.iter().all(|r| r.field("@timestamp").is_none()));
}

#[test]
fn output_is_deterministic() {
    let a: Vec<_> = read_feature_usage(&registry())
        .into_iter()
        .map(|e| format!("{e:?}"))
        .collect();
    let b: Vec<_> = read_feature_usage(&registry())
        .into_iter()
        .map(|e| format!("{e:?}"))
        .collect();
    assert_eq!(a, b);
}

#[derive(Default)]
struct Collect(Arc<std::sync::Mutex<Vec<ForensicData>>>);

impl TriageSink for Collect {
    fn name(&self) -> &str {
        "collect"
    }
    fn on_data(&mut self, data: &ForensicData) -> ForensicResult<()> {
        self.0.lock().unwrap().push(data.clone());
        Ok(())
    }
    fn on_finding(&mut self, _: &Finding) -> ForensicResult<()> {
        Ok(())
    }
}

fn run_pipeline(reg: TestingRegistry) -> Vec<ForensicData> {
    let records = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sources = TriageSources::builder().registry(Arc::new(reg)).build();
    TriagePipeline::builder()
        .context(TriageContext::new("HOST01", "tenant"))
        .parser(Arc::new(FeatureUsageParserFactory::new()))
        .sink(Box::new(Collect(records.clone())))
        .on_parser_error(ErrorAction::Continue)
        .build()
        .unwrap()
        .run(&sources)
        .unwrap();
    records.lock().unwrap().clone()
}

#[test]
fn factory_runs_in_the_triage_pipeline() {
    let records = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sources = TriageSources::builder()
        .registry(Arc::new(registry()))
        .build();
    let result = TriagePipeline::builder()
        .context(TriageContext::new("HOST01", "tenant"))
        .parser(Arc::new(FeatureUsageParserFactory::new()))
        .sink(Box::new(Collect(records.clone())))
        .on_parser_error(ErrorAction::Continue)
        .build()
        .unwrap()
        .run(&sources)
        .unwrap();

    assert_eq!(result.items_processed, 6);
    let records = records.lock().unwrap();
    assert_eq!(records.len(), 6);
    let bob = records
        .iter()
        .find(|r| r.field(dictionary::USER_ID).map(|f| f.to_string()) == Some(BOB.into()))
        .expect("record for Bob");
    assert_eq!(bob.host(), "HOST01");
    assert!(
        bob.field("@timestamp").is_none(),
        "counters have no event time"
    );
}
