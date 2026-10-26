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
| `shimcache` | `HKLM\SYSTEM\<control set>\Control\Session Manager\AppCompatCache` (`WindowsAppCompatCache`), every control set | `windows.registry.shimcache` |
| `mounted_devices` | `HKLM\SYSTEM\MountedDevices` (`WindowsMountedDevices`) | `windows.registry.mounted_devices` |
| `word_wheel_query` | `HKU\<sid>\...\Explorer\WordWheelQuery` (`WindowsWordWheelQueryRegistryKey`) | `windows.registry.word_wheel_query` |
| `shellbags` | `HKU\<sid>\Software\Microsoft\Windows\Shell\BagMRU`, `HKU\<sid>_Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` | `windows.registry.shellbags` |

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
- ShimCache: XP, 2003/Vista/2008, 7/2008 R2 (32/64-bit), 8, 8.1 and 10/11 layouts; one record per
  entry, most recent first (`shimcache.position`), from the current control set and every other
  one (`shimcache.control_set`). The entry's time is the file's modification time (`file.mtime`),
  not an execution time, so there is no `@timestamp`; `shimcache.executed` is set only on 7 and
  8.x, which record it. Validated on two real Windows 7 caches (32- and 64-bit: 330 and 217
  entries, no errors).
- MountedDevices: one record per mount point; the target decoded only when the data says so
  unambiguously (12-byte MBR signature + offset, `DMIO:ID:` GPT GUID, printable UTF-16 device
  path), otherwise `unknown`, always with the raw data. No time.
- WordWheelQuery: one record per search term, with its `MRUListEx` position (0 = most recent).
  The key's last-write time is carried but is not `@timestamp`: a re-search reorders the list too.
- ShellBags: one record per `BagMRU` item, NTUSER and UsrClass (`HKU\<sid>_Classes`), with the
  path rebuilt from its ancestors (`file.path`). Decoded: namespace roots, volumes and drives,
  file entries (long name, created/accessed/modified FAT times, MFT reference from `0xbeef0004`),
  delegate (`0x74`) entries, network locations and shares, Control Panel items and entries inside
  ZIP archives (name, parent in the archive, Explorer's modified-time text). Other classes are kept
  with their bytes and a best-guess readable name. `shellbags.last_opened` is the holding key's
  last-write time, set only for the item first in its `MRUListEx`; no `@timestamp`.
