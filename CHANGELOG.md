# Changelog

## [0.14.0] - Unreleased

### Changed

- Renamed from `frnsc-taskbar` to `frnsc-winreg-activity`, the home for per-user registry
  activity parsers. The taskbar parser is now the `feature_usage` module.
- Ported to forensic-rs 0.14: `Registry`/`RegistryExt`, `ArtifactParserFactory`
  (`FeatureUsageParserFactory`), errors instead of notifications.
- `read_feature_usage` returns one entry per user, counter and value instead of a map keyed
  by application, which merged users and let the last one overwrite the others' counters.

### Added

- `TrayButtonClicked` counters (the old `tray_clicks` field was never filled).
- Each entry keeps the user SID, the raw value name and the subkey's last-write time.
- `FeatureUsageEntry::assumed_vars` and the `feature_usage.app.assumed_vars` field: the
  environment variables a `{FOLDERID}` path was resolved through that the registry didn't
  provide (e.g. `windir` when `SystemRoot` is missing), so executable paths built from Windows
  defaults are marked. Uses forensic-rs's `get_env_vars_of_users_report`.

### Fixed

- `*PID` names with no, too many or non-hex digits no longer panic.
- Failures to read keys or non-DWORD values are returned instead of silently dropped; so is a
  counter key whose last-write time can't be read (its counters are still returned).
- Users are walked with forensic-rs's `RegistryExt::for_each_user_hive`, which now keeps going
  past a user that can't be opened, instead of a copy of that loop.
- `repository` URL pointed to frnsc-amcache.
