# frnsc-winreg-activity

Pure Rust parsers for Windows registry artifacts, machine (`HKLM\...`) and per user
(`HKU\<sid>\...`). Formerly `frnsc-taskbar`.

With an artifact catalog attached (as in `frnsc-pipeline`), each parser finds its keys through
its ForensicArtifacts definition; without one, through its own key patterns.

Part of the [ForensicRS](https://github.com/ForensicRS) ecosystem, built on
[`forensic-rs`](https://github.com/ForensicRS/forensic-rs). Works against any `Registry`
backend: live registry, parsed hive files, or `TestingRegistry`.

## Artifacts

| Module | Key | Parser id |
|---|---|---|
| `feature_usage` | `Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage` | `windows.registry.feature_usage` |
| `bam` | `HKLM\SYSTEM\CurrentControlSet\Services\{bam,dam}\[State\]UserSettings\<sid>` (`WindowsBackgroundActivityModeratorKeys`) | `windows.registry.bam` |
| `run_keys` | `Run`, `RunOnce`, `RunOnceEx`, `Policies\Explorer\Run` (+ `Wow6432Node`), HKLM and per user (`WindowsRunKeys`) | `windows.registry.run_keys` |
| `services` | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` (+ `Parameters\ServiceDll`) (`WindowsServices`) | `windows.registry.services` |

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
- BAM/DAM: one record per user and executable, `@timestamp` = the recorded last run (none for a
  zero `FILETIME`). Executables stay as stored (`\Device\HarddiskVolumeN\...` is not mapped to a
  drive letter); the whole value is kept in `bam.data`. BAM keeps about a week of entries, so an
  absent entry is not evidence that a program didn't run.
- Run keys: one record per value (RunOnceEx: per value of its numbered subkeys), with the command
  line unexpanded in `process.command_line`, `run_keys.once`/`run_keys.wow64`, and the key's
  last-write time; no `@timestamp`, since a value has no time of its own.
- Services: one record per service or driver key: `ImagePath` and `ServiceDll` as stored,
  `ObjectName` (the account), `Start`/`Type` raw with their names, the key's last-write time (not
  an install time, so not `@timestamp`). A value of the wrong type is an `Err` item beside the
  record, never a guessed value.
