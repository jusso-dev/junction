//! Microsoft 365 security watchdog for Junction.
//!
//! Licence-aware, read-only audit collection and deterministic detections for
//! small organisations on free or donated Microsoft 365 plans. See
//! `docs/WATCH.md` for the operating model and its limits.
pub mod activity;
pub mod auth;
pub mod backoff;
pub mod capability;
pub mod catalog;
pub mod cli;
pub mod clock;
pub mod config;
pub mod event;
pub mod probe;
pub mod store;
pub mod upstream;
pub mod web;
