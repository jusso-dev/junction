//! Long-term Microsoft 365 audit and evidence archive for Junction.
//!
//! Pulls the Unified Audit Log, Entra ID sign-in and audit logs and a small set
//! of Defender records into storage the customer owns (Azure Blob with
//! version-level immutability, or Cloudflare R2 with bucket locks), then
//! searches it and exports hashed evidence bundles. See `docs/ARCHIVE.md`.
//!
//! The archive is read-only against the tenant. Its only write path is
//! create-only objects in the operator's own storage.
pub mod catalog;
pub mod cli;
pub mod config;
pub mod record;
pub mod store;
