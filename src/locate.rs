//! Where a registry artifact's keys are: through the run's artifact catalog when it has the
//! definition, else through the parser's own key patterns.

use std::collections::BTreeMap;

use forensic_rs::catalog::{Os, expand};
use forensic_rs::host_profile::HostProfile;
use forensic_rs::prelude::*;

/// One key a pattern matched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct KeyMatch {
    pub path: String,
    /// The user it was expanded for, from a `%%users.sid%%` placeholder.
    pub sid: Option<String>,
    /// The parent of a pattern ending in `\*`, matched for its values: ForensicArtifacts reads
    /// `...\Run\*` as the Run key's values as well as its subkeys.
    pub values_of_wildcard: bool,
}

/// The keys of one definition, sorted by path, and how they were found.
pub(crate) struct LocatedKeys {
    pub keys: Vec<KeyMatch>,
    /// Whether the catalog's definition gave the patterns (else the parser's own did).
    pub by_catalog: bool,
    /// Patterns that couldn't be expanded or read, and definition sources that never became a
    /// pattern: parts of the evidence that weren't examined.
    pub errors: Vec<ForensicError>,
}

/// The keys `definition` names, expanded for this host, when the run's catalog has it; else the
/// keys `builtin` (patterns in [`RegistryExt::expand_key_pattern`] syntax) match.
pub(crate) fn locate_keys(
    ctx: &ParseContext<'_>,
    registry: &dyn Registry,
    definition: &str,
    builtin: &[&str],
) -> LocatedKeys {
    let mut errors = Vec::new();
    let from_catalog = ctx
        .sources()
        .catalog()
        .and_then(|catalog| catalog.get(definition).map(|def| (catalog, def)));
    let by_catalog = from_catalog.is_some();
    let patterns: Vec<(String, Option<String>)> = match from_catalog {
        Some((catalog, def)) => {
            let empty = HostProfile::default();
            let host = ctx.host_profile().unwrap_or(&empty);
            let expansion = expand(def, catalog.as_ref(), host, Os::Windows);
            errors.extend(expansion.unresolved.into_iter().map(|u| {
                ForensicError::other(
                    "catalog",
                    format!(
                        "{definition}: source {:?} was not searched: {}",
                        u.source, u.reason
                    ),
                )
            }));
            expansion
                .keys
                .into_iter()
                .map(|k| (k.pattern, k.sid))
                .collect()
        }
        None => builtin.iter().map(|p| (p.to_string(), None)).collect(),
    };

    let mut found: BTreeMap<String, KeyMatch> = BTreeMap::new();
    let mut expand_into =
        |pattern: &str, sid: &Option<String>, values_of_wildcard: bool| match registry
            .expand_key_pattern(pattern)
        {
            Ok(paths) => {
                for path in paths {
                    found.entry(path.clone()).or_insert(KeyMatch {
                        path,
                        sid: sid.clone(),
                        values_of_wildcard,
                    });
                }
            }
            Err(e) => errors.push(ForensicError::other(
                "registry",
                format!("{definition}: expanding {pattern}: {e}"),
            )),
        };
    for (pattern, sid) in &patterns {
        expand_into(pattern, sid, false);
        if let Some(parent) = pattern.strip_suffix("\\*") {
            expand_into(parent, sid, true);
        }
    }
    LocatedKeys {
        keys: found.into_values().collect(),
        by_catalog,
        errors,
    }
}
