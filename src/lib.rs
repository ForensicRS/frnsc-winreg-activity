//! Parsers for Windows registry artifacts, machine (`HKLM`) and per user (`HKU\<sid>`).
//!
//! Every module reads through the [`forensic_rs::prelude::Registry`] trait, so the same code runs
//! against a live registry, parsed hive files, or
//! [`forensic_rs::prelude::testing::TestingRegistry`] in tests. Each module exposes a typed
//! reader and an [`forensic_rs::prelude::ArtifactParserFactory`] for the triage pipeline.

pub mod app_id;
pub mod bam;
pub mod feature_usage;
mod locate;
mod users;

pub use app_id::AppId;
pub use bam::{BamEntry, BamParserFactory, Moderator};
pub use feature_usage::{
    Counter, FeatureUsageEntry, FeatureUsageParserFactory, read_feature_usage,
};
