# frnsc-winreg-activity

Pure Rust parsers for per-user Windows registry activity artifacts (`HKU\<sid>\...`).
Formerly `frnsc-taskbar`.

Part of the [ForensicRS](https://github.com/ForensicRS) ecosystem, built on
[`forensic-rs`](https://github.com/ForensicRS/forensic-rs). Works against any `Registry`
backend: live registry, parsed hive files, or `TestingRegistry`.

## Artifacts

| Module | Key | Parser id |
|---|---|---|
| `feature_usage` | `Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage` | `windows.registry.feature_usage` |

## Usage

```rust
use frnsc_winreg_activity::read_feature_usage;

for entry in read_feature_usage(&registry) {
    match entry {
        Ok(e) => println!("{} {:?} {:?} = {}", e.user_sid, e.counter, e.app, e.count),
        Err(e) => eprintln!("{e}"),
    }
}
```

Or register `FeatureUsageParserFactory` with a `TriagePipeline`.

## Coverage and limitations

- FeatureUsage subkeys read: `AppBadgeUpdated`, `AppLaunch`, `AppSwitched`, `ShowJumpView`,
  `TrayButtonClicked`. One record per user, counter and value; users are never merged.
- Counters have no per-application timestamp. `registry.key.last_write` is the subkey's
  last-write time (when *some* counter in it last changed), and no `@timestamp` is emitted.
- `{GUID}\...` paths are resolved from the user's `ProfileList` entry. When that isn't
  available they stay `UnresolvedCsidl`; the raw value name is always kept in `registry.value`.
- `*PID<hex>` names that aren't valid hex are reported as `MalformedPid` with the raw name.
