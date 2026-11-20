//! The process around the recommendation engine's heavy half: crawling, recomputing and
//! retention.
//!
//! The engine is `nodus_calculator`, in the recommender's workspace. This crate holds the
//! part a deployed unit needs — the engine pool, the worker, the maintenance clock — so
//! `nodus-calc` and `nodus calc` start the same process.

pub mod run;

pub use run::run;
