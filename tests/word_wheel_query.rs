use std::sync::Arc;

use forensic_rs::prelude::testing::{TestingRegistry, collect_run};
use forensic_rs::{dictionary, prelude::*};
use frnsc_winreg_activity::word_wheel_query::{WordWheelQueryParserFactory, read_search_terms};

const ALICE: &str = "S-1-5-21-1000-1000-1000-1001";
const BOB: &str = "S-1-5-21-1000-1000-1000-1002";
const WWQ: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery";

fn term(s: &str) -> RegValue {
    let mut data: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    data.extend_from_slice(&[0, 0]);
    RegValue::Binary(data)
}

fn mru(order: &[u32]) -> RegValue {
    let mut data: Vec<u8> = order.iter().flat_map(|i| i.to_le_bytes()).collect();
    data.extend_from_slice(&u32::MAX.to_le_bytes());
    RegValue::Binary(data)
}

fn registry() -> TestingRegistry {
    let mut reg = TestingRegistry::empty();
    let alice = format!(r"HKU\{ALICE}\{WWQ}");
    reg.add_value(&alice, "0", term("passwords.xlsx"));
    reg.add_value(&alice, "1", term("mimikatz"));
    reg.add_value(&alice, "2", term("not in the list"));
    reg.add_value(&alice, "MRUListEx", mru(&[1, 0]));
    reg.set_last_write(
        &alice,
        ForensicTimestamp::from_win_filetime(133_514_430_235_959_706),
    );
    let bob = format!(r"HKU\{BOB}\{WWQ}");
    reg.add_value(&bob, "0", term("budget"));
    reg.add_value(&bob, "1", RegValue::Binary(vec![0x00, 0xD8, 0, 0])); // unpaired surrogate
    reg.add_value(&bob, "2", RegValue::DWord(5));
    reg.add_value(&bob, "MRUListEx", mru(&[0, 1]));
    reg
}

#[test]
fn terms_keep_their_most_recent_first_order() {
    let terms: Vec<_> = read_search_terms(
        &registry(),
        &format!(r"HKU\{ALICE}\{WWQ}"),
        Some(ALICE.into()),
    )
    .into_iter()
    .map(Result::unwrap)
    .collect();
    let by = |t: &str| terms.iter().find(|x| x.term == t).unwrap();
    assert_eq!(by("mimikatz").mru_position, Some(0));
    assert_eq!(by("passwords.xlsx").mru_position, Some(1));
    assert_eq!(by("not in the list").mru_position, None);
    assert!(by("mimikatz").key_last_write.is_some());
}

#[test]
fn each_user_s_terms_are_their_own_and_bad_values_are_reported() {
    let sources = TriageSources::builder()
        .registry(Arc::new(registry()))
        .acquisition(Acquisition::ImageRead)
        .build();
    let triage = TriageContext::new("HOST01", "t");
    let cancellation = CancellationToken::new();
    let ctx = ParseContext::new(&sources, &triage, &cancellation);
    let items = collect_run(WordWheelQueryParserFactory::new().open(&ctx).unwrap()).unwrap();
    let errors: Vec<String> = items
        .iter()
        .filter_map(|i| i.as_ref().err())
        .map(|e| e.to_string())
        .collect();
    assert_eq!(errors.len(), 1, "{errors:?}");
    let records: Vec<&ForensicData> = items.iter().filter_map(|i| i.as_ref().ok()).collect();
    assert_eq!(records.len(), 5);
    for r in &records {
        assert!(r.field(dictionary::TIMESTAMP).is_none());
        assert!(r.field(dictionary::USER_ID).is_some());
    }
    let budget = records
        .iter()
        .find(|r| r.field_as_str("word_wheel_query.term") == Some("budget"))
        .unwrap();
    assert_eq!(budget.field_as_str(dictionary::USER_ID), Some(BOB));
    assert!(
        records
            .iter()
            .any(|r| r.field_as_u64("word_wheel_query.lossy") == Some(1)),
        "an invalid term is flagged, not dropped"
    );
}
