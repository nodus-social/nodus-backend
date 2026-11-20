//! The process around the pruning passes.
//!
//! Everything here is on a clock, so it is the one service whose absence is invisible until
//! disk pressure or a stale session appears. It keeps the same call and stop shape as every
//! other worker so a controller can ask for a pass now.

pub mod run;

pub use run::run;
