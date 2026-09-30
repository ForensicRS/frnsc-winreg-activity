//! Parsers for per-user Windows registry activity artifacts.
//!
//! Every module reads from `HKU\<sid>\...` through the [`forensic_rs::prelude::Registry`]
//! trait, so the same code runs against a live registry, parsed hive files, or
//! [`forensic_rs::prelude::testing::TestingRegistry`] in tests. Each module exposes a typed
//! reader and an [`forensic_rs::prelude::ArtifactParserFactory`] for the triage pipeline.

pub mod app_id;
pub mod feature_usage;
mod users;

pub use app_id::AppId;
pub use feature_usage::{
    Counter, FeatureUsageEntry, FeatureUsageParserFactory, read_feature_usage,
};
