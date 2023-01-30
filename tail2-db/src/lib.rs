#![deny(clippy::disallowed_types)]
#![warn(missing_docs)]

//! Database layer for tail2
//! Use duckdb to save profiling data with order of magitude amortization.

/// Tail2 DB implementation
pub mod db;

/// Algorithm for tiling
/// Tile any given time interval with precomputed(amortized) results.
pub mod tile;