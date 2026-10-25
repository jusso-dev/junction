//! Report renderers for a [`crate::model::RunReport`]: table (terminal),
//! Markdown, self-contained HTML (with a print stylesheet for PDF), the
//! Essential Eight maturity estimate, generated coverage and permission tables,
//! and the M365-Secure schema 1.1 compatibility export.
pub mod coverage;
pub mod html;
pub mod m365_secure;
pub mod markdown;
pub mod maturity;
pub mod table;

/// Branding and presentation choices for human-readable reports.
#[derive(Debug, Clone, Default)]
pub struct ReportOptions {
    pub title: Option<String>,
    pub organisation: Option<String>,
    /// Logo image bytes and MIME type, embedded as a data URI in HTML.
    pub logo: Option<(String, Vec<u8>)>,
}
