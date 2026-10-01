//! Interactive operator confirmation for approval-required operations.
//!
//! Confirmation is read from the controlling terminal, never from stdin or
//! command-line arguments, so piped input and agent-supplied flags cannot
//! approve a request. The operator must retype the operation identifier and a
//! fresh random code shown only on that terminal.
use anyhow::Result;
use std::io::{BufRead, Write};

const MAX_DISPLAYED_INPUT: usize = 8 * 1024;

/// Fixed, secret-free reason for an approval that did not complete.
#[derive(Debug, serde::Serialize)]
pub struct ApprovalFailure {
    pub status: &'static str,
    pub reason: &'static str,
}
impl std::fmt::Display for ApprovalFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason)
    }
}
impl std::error::Error for ApprovalFailure {}
pub fn failure(reason: &'static str) -> anyhow::Error {
    ApprovalFailure {
        status: "approval_failed",
        reason,
    }
    .into()
}

pub struct Summary<'a> {
    pub operation: &'a junction_core::JunctionOperation,
    pub reason: &'a str,
    pub tenant: &'a str,
    pub cloud: &'a junction_core::cloud::MicrosoftCloud,
    pub endpoint: &'a str,
    pub audience: &'a str,
    pub credential_profile: &'a str,
    pub input: &'a serde_json::Value,
}

fn open_terminal() -> Result<(std::fs::File, std::fs::File)> {
    #[cfg(windows)]
    let (input, output) = ("CONIN$", "CONOUT$");
    #[cfg(not(windows))]
    let (input, output) = ("/dev/tty", "/dev/tty");
    let reader = std::fs::OpenOptions::new()
        .read(true)
        .open(input)
        .map_err(|_| failure("operator_terminal_unavailable"))?;
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open(output)
        .map_err(|_| failure("operator_terminal_unavailable"))?;
    Ok((reader, writer))
}

fn confirmation_code() -> Result<String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 6];
    getrandom::fill(&mut bytes).map_err(|_| anyhow::anyhow!("random source unavailable"))?;
    Ok(bytes
        .iter()
        .map(|byte| ALPHABET[usize::from(*byte) % ALPHABET.len()] as char)
        .collect())
}

pub fn render(summary: &Summary<'_>) -> Result<String> {
    let operation = summary.operation;
    let input = serde_json::to_string_pretty(summary.input)?;
    if input.len() > MAX_DISPLAYED_INPUT {
        return Err(failure("input_too_large_to_review"));
    }
    let cloud = serde_json::to_value(summary.cloud)?;
    Ok(format!(
        "\nJunction approval required\n\
         operation:          {}\n\
         risk:               {}\n\
         reason:             {}\n\
         request:            {} {}\n\
         api version:        {}\n\
         tenant:             {}\n\
         cloud:              {}\n\
         endpoint:           {}\n\
         audience:           {}\n\
         credential profile: {}\n\
         input:\n{}\n",
        operation.id,
        serde_json::to_value(&operation.risk)?
            .as_str()
            .unwrap_or("unknown"),
        summary.reason,
        operation.method,
        operation.path,
        operation.api_version.as_deref().unwrap_or("none"),
        summary.tenant,
        cloud.as_str().unwrap_or("unknown"),
        summary.endpoint,
        summary.audience,
        summary.credential_profile,
        input,
    )
    // Catalog text and input come from outside the trusted terminal; never let
    // them emit terminal control sequences into the approval prompt.
    .chars()
    .map(|c| if c.is_control() && c != '\n' { '?' } else { c })
    .collect())
}

/// Show the exact request and require the operator to retype the operation
/// identifier and a one-time code. Any mismatch or terminal failure rejects.
pub fn confirm(summary: &Summary<'_>) -> Result<()> {
    let text = render(summary)?;
    let (reader, mut writer) = open_terminal()?;
    let code = confirmation_code()?;
    write!(writer, "{text}\nType the operation identifier to approve: ")?;
    writer.flush()?;
    let mut lines = std::io::BufReader::new(reader).lines();
    let typed = lines.next().transpose()?.unwrap_or_default();
    if typed.trim() != summary.operation.id.as_str() {
        writeln!(writer, "Approval declined.")?;
        return Err(failure("operator_declined"));
    }
    write!(writer, "Type confirmation code {code}: ")?;
    writer.flush()?;
    let typed = lines.next().transpose()?.unwrap_or_default();
    if typed.trim() != code {
        writeln!(writer, "Approval declined.")?;
        return Err(failure("operator_declined"));
    }
    writeln!(writer, "Approved for one execution.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn confirmation_codes_are_unambiguous_and_fresh() {
        let first = super::confirmation_code().unwrap();
        assert_eq!(first.len(), 6);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | '1' | 'I'))
        );
        let distinct = (0..8)
            .map(|_| super::confirmation_code().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(distinct.len() > 1);
    }
}
