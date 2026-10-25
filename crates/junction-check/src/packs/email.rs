//! `email` pack: SPF, DKIM and DMARC for the tenant's custom domains (public
//! DNS), and the Exchange Online protections that only Exchange Online
//! PowerShell can read (manual attestations).
//!
//! Domains come from Graph `GET /domains`: verified ones, without the initial
//! domain and `*.onmicrosoft.com` (Microsoft manages their DNS). Each domain is
//! - `exchange`: accepted by Exchange Online (`supportedServices` has `Email`);
//! - `other_mail`: has MX records or publishes SPF that authorises senders;
//! - `parked`: neither. It should publish `v=spf1 -all`; DKIM and DMARC skip it.
//!
//! A failed DNS lookup leaves that domain unresolved: the check is `unknown`
//! for it (listed in the evidence) and never fails because of it.
use crate::check::{
    ApiRequirement, Check, CheckMeta, Evaluation, Finding, ManualCheck, ManualSpec, Requirements,
};
use crate::context::{CallFailure, CheckContext};
use crate::dns::{DnsError, RecordType};
use crate::model::{CheckKind, Level, Pack, Severity, Status};
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;

pub fn checks() -> Vec<Arc<dyn Check>> {
    vec![
        Arc::new(SpfCheck),
        Arc::new(DkimCheck),
        Arc::new(DmarcCheck),
        Arc::new(ManualCheck(&PRESET_POLICIES)),
        Arc::new(ManualCheck(&EXTERNAL_SENDER_TAG)),
        Arc::new(ManualCheck(&AUTO_FORWARD_BLOCKED)),
        Arc::new(ManualCheck(&MAILBOX_AUDIT)),
    ]
}

const DOMAINS: ApiRequirement = ApiRequirement {
    operation: "graph.domains.list",
    permissions: &["Domain.Read.All"],
};

const EXCHANGE_ONLINE: &[&str] = &["exchange_online"];

/// Why the Exchange Online settings below are attested, not read.
const EXO_ONLY: &str = "This setting is only exposed by Exchange Online PowerShell (or its admin API), which is not in Junction's read-only operation catalogue.";

/// Domains resolved at once.
const DOMAIN_CONCURRENCY: usize = 8;
/// SPF records fetched per domain while counting lookups.
const MAX_SPF_RECORDS: usize = 20;

pub const SPF: CheckMeta = CheckMeta {
    id: "email.spf",
    title: "Every mail domain publishes one strict SPF record",
    pack: Pack::Email,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Low,
    impact: Level::High,
    description: "Lists verified custom domains and reads their SPF TXT records from public DNS. Each Exchange Online domain needs exactly one record that includes spf.protection.outlook.com, ends in -all or ~all, and stays within 10 DNS lookups (include, a, mx, ptr, exists and redirect, counted through nested records). Domains with no mail should publish `v=spf1 -all` so they cannot be spoofed. Without SPF, anyone can send mail that appears to come from the domain.",
    requires: Requirements {
        apis: &[DOMAINS],
        licences: EXCHANGE_ONLINE,
    },
    remediation: "Publish one TXT record per mail domain listing every legitimate sender and ending in -all (or ~all while senders are inventoried), for example `v=spf1 include:spf.protection.outlook.com -all`. Merge duplicate records, and flatten or remove includes when more than 10 lookups are needed. For domains that send no mail, publish `v=spf1 -all`.",
    links: &["https://learn.microsoft.com/defender-office-365/email-authentication-spf-configure"],
    references: &["CIS M365 2.1.8", "RFC 7208"],
    manual: None,
};

pub const DKIM: CheckMeta = CheckMeta {
    id: "email.dkim",
    title: "DKIM selector CNAMEs are published for every Exchange Online domain",
    pack: Pack::Email,
    kind: CheckKind::Automated,
    severity: Severity::Medium,
    effort: Level::Low,
    impact: Level::Medium,
    description: "For each Exchange Online domain, reads the selector1._domainkey and selector2._domainkey CNAME records Exchange Online needs to sign outbound mail with DKIM. Whether signing is switched on (Get-DkimSigningConfig) is only readable through Exchange Online PowerShell, so the CNAMEs decide and the evidence says so. Domains whose mail is hosted elsewhere, or that send no mail, are skipped.",
    requires: Requirements {
        apis: &[DOMAINS],
        licences: EXCHANGE_ONLINE,
    },
    remediation: "In the Defender portal open Email & collaboration > Policies & rules > Threat policies > Email authentication settings > DKIM, select the domain, publish the two CNAME records it shows, then enable signing. Confirm with `Get-DkimSigningConfig | fl Domain,Enabled,Status`.",
    links: &["https://learn.microsoft.com/defender-office-365/email-authentication-dkim-configure"],
    references: &["CIS M365 2.1.9"],
    manual: None,
};

pub const DMARC: CheckMeta = CheckMeta {
    id: "email.dmarc",
    title: "Every mail domain enforces DMARC with reporting",
    pack: Pack::Email,
    kind: CheckKind::Automated,
    severity: Severity::High,
    effort: Level::Medium,
    impact: Level::High,
    description: "For each domain that sends or receives mail, reads the `_dmarc` TXT record (falling back to a parent domain's record for subdomains). p=quarantine or p=reject with a rua= reporting address passes; p=none only monitors and warns, as do pct below 100, sp=none and a missing rua=. A missing or invalid record fails. Domains with no mail are skipped.",
    requires: Requirements {
        apis: &[DOMAINS],
        licences: EXCHANGE_ONLINE,
    },
    remediation: "Publish a TXT record at `_dmarc.<domain>`, for example `v=DMARC1; p=reject; rua=mailto:dmarc-reports@<domain>`. Start at p=none with reporting while legitimate senders are aligned, then move to quarantine and reject.",
    links: &[
        "https://learn.microsoft.com/defender-office-365/email-authentication-dmarc-configure",
    ],
    references: &["CIS M365 2.1.10", "RFC 7489"],
    manual: None,
};

pub const PRESET_POLICIES: CheckMeta = CheckMeta {
    severity: Severity::High,
    impact: Level::High,
    requires: Requirements {
        apis: &[],
        licences: EXCHANGE_ONLINE,
    },
    remediation: "In the Defender portal open Email & collaboration > Policies & rules > Threat policies > Preset security policies. Turn on Standard protection for all recipients (Exchange Online Protection, and Defender for Office 365 protections when licensed) and Strict protection for executives, finance and administrators.",
    links: &["https://learn.microsoft.com/defender-office-365/preset-security-policies"],
    references: &["CIS M365 2.1.7"],
    ..CheckMeta::manual(
        "email.preset_policies",
        "Standard or Strict preset security policy applies to all recipients",
        Pack::Email,
        ManualSpec {
            question: "Is the Standard or Strict preset security policy turned on and applied to all recipients, for Exchange Online Protection and (when licensed) Defender for Office 365?",
            guidance: "In Exchange Online PowerShell (read-only cmdlets, View-Only Configuration is enough) run `Get-EOPProtectionPolicyRule | fl Identity,State,SentTo,SentToMemberOf,RecipientDomainIs,ExceptIfSentTo,ExceptIfSentToMemberOf,ExceptIfRecipientDomainIs` and, with Defender for Office 365 Plan 1 or 2, `Get-ATPProtectionPolicyRule` with the same fields. Answer yes when the 'Standard Preset Security Policy' or 'Strict Preset Security Policy' rule is Enabled and covers everyone: RecipientDomainIs lists every accepted domain (or no recipient conditions), with only deliberate exceptions, in both cmdlets when Defender for Office 365 is licensed. Exchange Online Protection presets need no extra licence; the Safe Links and Safe Attachments parts need Defender for Office 365 Plan 1.",
            why_manual: EXO_ONLY,
        },
    )
};

pub const EXTERNAL_SENDER_TAG: CheckMeta = CheckMeta {
    severity: Severity::Medium,
    impact: Level::Medium,
    requires: Requirements {
        apis: &[],
        licences: EXCHANGE_ONLINE,
    },
    remediation: "Run `Set-ExternalInOutlook -Enabled $true` in Exchange Online PowerShell, and keep its AllowList to the few partner addresses that genuinely need it.",
    links: &["https://learn.microsoft.com/powershell/module/exchange/set-externalinoutlook"],
    references: &["CIS M365 6.2.3"],
    ..CheckMeta::manual(
        "email.external_sender_tag",
        "Mail from outside the organisation is tagged External in Outlook",
        Pack::Email,
        ManualSpec {
            question: "Is external sender identification (the External tag in Outlook) turned on?",
            guidance: "In Exchange Online PowerShell run `Get-ExternalInOutlook | fl Identity,Enabled,AllowList`. Answer yes when Enabled is True. Review AllowList: every listed sender or domain is shown without the tag.",
            why_manual: EXO_ONLY,
        },
    )
};

pub const AUTO_FORWARD_BLOCKED: CheckMeta = CheckMeta {
    severity: Severity::High,
    impact: Level::High,
    requires: Requirements {
        apis: &[],
        licences: EXCHANGE_ONLINE,
    },
    remediation: "In the Defender portal open Anti-spam policies > Anti-spam outbound policy (Default) and set Automatic forwarding rules to Off - Forwarding is disabled. Allow forwarding only through a separate outbound policy scoped to named, approved mailboxes, and remove mail flow rules that redirect or copy mail to external addresses.",
    links: &[
        "https://learn.microsoft.com/defender-office-365/outbound-spam-policies-external-email-forwarding",
    ],
    references: &["CIS M365 6.2.1"],
    ..CheckMeta::manual(
        "email.auto_forward_blocked",
        "Automatic forwarding to external recipients is blocked",
        Pack::Email,
        ManualSpec {
            question: "Does the outbound spam policy block automatic forwarding to external recipients, with no mail flow rule that forwards externally?",
            guidance: "In Exchange Online PowerShell run `Get-HostedOutboundSpamFilterPolicy | fl Name,IsDefault,AutoForwardingMode`, `Get-HostedOutboundSpamFilterRule | fl Name,State,HostedOutboundSpamFilterPolicy,From,FromMemberOf,SenderDomainIs` and `Get-TransportRule | fl Name,State,RedirectMessageTo,BlindCopyTo,AddToRecipients,CopyTo`. Answer yes when the default policy's AutoForwardingMode is Off (Automatic now also blocks), any policy set to On applies only to named, approved mailboxes or groups, and no enabled transport rule redirects, blind-copies or adds recipients outside your accepted domains.",
            why_manual: EXO_ONLY,
        },
    )
};

pub const MAILBOX_AUDIT: CheckMeta = CheckMeta {
    severity: Severity::High,
    impact: Level::High,
    requires: Requirements {
        apis: &[],
        licences: EXCHANGE_ONLINE,
    },
    remediation: "Run `Set-OrganizationConfig -AuditDisabled $false` in Exchange Online PowerShell, and remove audit bypass for any account with `Set-MailboxAuditBypassAssociation -Identity <account> -AuditBypassEnabled $false`.",
    links: &["https://learn.microsoft.com/purview/audit-mailboxes"],
    references: &["CIS M365 6.1.1"],
    ..CheckMeta::manual(
        "email.mailbox_audit",
        "Mailbox auditing is on by default for every mailbox",
        Pack::Email,
        ManualSpec {
            question: "Is mailbox auditing on by default for the organisation (AuditDisabled is False), with no mailbox bypassing it?",
            guidance: "In Exchange Online PowerShell run `Get-OrganizationConfig | fl AuditDisabled` and `Get-MailboxAuditBypassAssociation -ResultSize Unlimited | ? AuditBypassEnabled | fl Name`. Answer yes when AuditDisabled is False and the second command returns nothing (or only accounts you have accepted in writing).",
            why_manual: EXO_ONLY,
        },
    )
};

crate::check!(SpfCheck, &SPF, spf);
crate::check!(DkimCheck, &DKIM, dkim);
crate::check!(DmarcCheck, &DMARC, dmarc);

// ─── Domains ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Domain {
    name: String,
    /// An accepted domain for Exchange Online.
    exchange: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Exchange,
    OtherMail,
    Parked,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Exchange => "exchange",
            Self::OtherMail => "other_mail",
            Self::Parked => "parked",
        }
    }
}

/// `*.onmicrosoft.com` names belong to Microsoft, which manages their DNS.
pub fn microsoft_managed(domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    d == "onmicrosoft.com" || d.ends_with(".onmicrosoft.com")
}

/// Verified custom domains, sorted. Listing failures propagate (`unknown`).
async fn custom_domains(ctx: &CheckContext) -> Result<Vec<Domain>, CallFailure> {
    let rows = ctx
        .list_with(
            DOMAINS.operation,
            json!({"$select": ["id", "isVerified", "isInitial", "supportedServices"]}),
        )
        .await?;
    let mut out: Vec<Domain> = rows
        .iter()
        .filter(|d| d.get("isVerified").and_then(Value::as_bool) == Some(true))
        .filter(|d| d.get("isInitial").and_then(Value::as_bool) != Some(true))
        .filter_map(|d| {
            let name = d.get("id")?.as_str()?.to_ascii_lowercase();
            let valid = name.len() <= 253
                && name.contains('.')
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
            let exchange = d
                .get("supportedServices")
                .and_then(Value::as_array)
                .is_some_and(|s| {
                    s.iter()
                        .any(|v| v.as_str().is_some_and(|v| v.eq_ignore_ascii_case("Email")))
                });
            (valid && !microsoft_managed(&name)).then_some(Domain { name, exchange })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out.dedup_by(|a, b| a.name == b.name);
    Ok(out)
}

/// TXT records at `name`; a missing name is an empty list.
async fn txt(ctx: &CheckContext, name: &str) -> Result<Vec<String>, String> {
    match ctx.dns().lookup(name, RecordType::Txt).await {
        Ok(records) => Ok(records),
        Err(DnsError::NotFound) => Ok(vec![]),
        Err(DnsError::Failed(e)) => Err(format!("TXT lookup for {name} failed: {e}")),
    }
}

fn is_spf(record: &str) -> bool {
    let r = record.trim().to_ascii_lowercase();
    r == "v=spf1" || r.starts_with("v=spf1 ")
}

async fn spf_records(ctx: &CheckContext, name: &str) -> Result<Vec<String>, String> {
    Ok(txt(ctx, name)
        .await?
        .into_iter()
        .filter(|r| is_spf(r))
        .collect())
}

/// How `domain` uses mail. `Err` is the DNS failure that prevented deciding.
async fn role(ctx: &CheckContext, domain: &Domain) -> Result<Role, String> {
    if domain.exchange {
        return Ok(Role::Exchange);
    }
    match ctx.dns().lookup(&domain.name, RecordType::Mx).await {
        // A null MX (".", RFC 7505) says the domain takes no mail.
        Ok(hosts) if hosts.iter().any(|h| h != ".") => return Ok(Role::OtherMail),
        Ok(_) | Err(DnsError::NotFound) => {}
        Err(DnsError::Failed(e)) => {
            return Err(format!("MX lookup for {} failed: {e}", domain.name));
        }
    }
    let records = spf_records(ctx, &domain.name).await?;
    Ok(
        if records.iter().any(|r| parse_spf(r).authorises_senders()) {
            Role::OtherMail
        } else {
            Role::Parked
        },
    )
}

// ─── Per-domain results ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Warn,
    Fail,
    /// DNS failed; the domain's state is not known.
    Unresolved,
    /// The check does not apply to this domain.
    Skipped,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Unresolved => "unresolved",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone)]
struct DomainResult {
    domain: String,
    role: Option<Role>,
    verdict: Verdict,
    detail: String,
    record: Option<String>,
}

impl DomainResult {
    fn new(domain: &Domain, role: Option<Role>, verdict: Verdict, detail: String) -> Self {
        Self {
            domain: domain.name.clone(),
            role,
            verdict,
            detail,
            record: None,
        }
    }
    fn record(mut self, record: Option<&str>) -> Self {
        self.record = record.map(str::to_owned);
        self
    }
    fn json(&self) -> Value {
        let mut v = json!({
            "domain": self.domain,
            "role": self.role.map(Role::as_str),
            "result": self.verdict.as_str(),
            "detail": self.detail,
        });
        if let Some(record) = &self.record {
            v["record"] = json!(record);
        }
        v
    }
}

/// Run `evaluate` for each domain (bounded concurrency, order kept).
async fn per_domain<'a, F, Fut>(
    ctx: &'a CheckContext,
    domains: &'a [Domain],
    evaluate: F,
) -> Vec<DomainResult>
where
    F: Fn(&'a CheckContext, &'a Domain) -> Fut,
    Fut: std::future::Future<Output = DomainResult> + 'a,
{
    let pending: Vec<Fut> = domains.iter().map(|d| evaluate(ctx, d)).collect();
    futures_util::stream::iter(pending)
        .buffered(DOMAIN_CONCURRENCY)
        .collect()
        .await
}

/// "a (why); b (why)", at most five.
fn listing(results: &[&DomainResult]) -> String {
    let mut parts: Vec<String> = results
        .iter()
        .take(5)
        .map(|r| format!("{} ({})", r.domain, r.detail))
        .collect();
    if results.len() > 5 {
        parts.push(format!("and {} more", results.len() - 5));
    }
    parts.join("; ")
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

/// Combine per-domain verdicts. Any failure fails; otherwise an unresolved
/// domain makes the check `unknown` (its state could be anything); then warn;
/// then pass. Skipped domains are listed but not scored.
fn aggregate(label: &str, results: Vec<DomainResult>, skipped_note: &str, extra: Value) -> Finding {
    if results.is_empty() {
        return Finding::not_applicable(
            "no_custom_domains",
            "The tenant has no verified custom domains; Microsoft manages the DNS of the initial onmicrosoft domain.",
        );
    }
    let with = |v: Verdict| {
        results
            .iter()
            .filter(|r| r.verdict == v)
            .collect::<Vec<_>>()
    };
    let (fails, warns, unresolved, skipped) = (
        with(Verdict::Fail),
        with(Verdict::Warn),
        with(Verdict::Unresolved),
        with(Verdict::Skipped),
    );
    let assessed = results.len() - skipped.len();
    let mut data = json!({
        "assessed": assessed,
        "passed": with(Verdict::Pass).len(),
        "warned": warns.len(),
        "failed": fails.len(),
        "unresolved": unresolved.len(),
        "skipped": skipped.len(),
        "domains": results.iter().map(DomainResult::json).collect::<Vec<_>>(),
    });
    if let (Some(data), Some(extra)) = (data.as_object_mut(), extra.as_object()) {
        data.extend(extra.clone());
    }
    let affected: Vec<String> = fails
        .iter()
        .chain(&warns)
        .chain(&unresolved)
        .map(|r| r.domain.clone())
        .collect();
    if assessed == 0 {
        return Finding::not_applicable("no_mail_domains", skipped_note.to_owned()).data(data);
    }
    let unresolved_note = if unresolved.is_empty() {
        String::new()
    } else {
        format!(
            " DNS lookups failed for {}.",
            unresolved
                .iter()
                .map(|r| r.domain.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let finding = if !fails.is_empty() {
        Finding::fail(format!(
            "{label} fails for {} of {assessed} domain{}: {}.{unresolved_note}",
            fails.len(),
            plural(assessed),
            listing(&fails)
        ))
    } else if !unresolved.is_empty() {
        Finding::unknown(
            "dns_lookup_failed",
            format!(
                "{label} could not be confirmed for {} of {assessed} domain{}: {}.",
                unresolved.len(),
                plural(assessed),
                listing(&unresolved)
            ),
        )
    } else if !warns.is_empty() {
        Finding::warn(format!(
            "{label} needs attention for {} of {assessed} domain{}: {}.",
            warns.len(),
            plural(assessed),
            listing(&warns)
        ))
    } else {
        Finding::pass(format!(
            "{label} passes for {}{assessed} domain{}.",
            if assessed > 1 { "all " } else { "" },
            plural(assessed)
        ))
    };
    finding.data(data).affected(affected)
}

// ─── SPF ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpfRecord {
    /// Qualifier of the `all` mechanism (`-`, `~`, `?`, `+`), if present.
    pub all: Option<char>,
    /// Terms that cost a DNS lookup: include, a, mx, ptr, exists, redirect.
    pub lookups: usize,
    pub includes: Vec<String>,
    pub redirect: Option<String>,
    /// Mechanisms other than `all`.
    pub mechanisms: usize,
}

impl SpfRecord {
    /// Whether the record lets anyone send (anything beyond `-all`/`~all`/`?all`).
    pub fn authorises_senders(&self) -> bool {
        self.mechanisms > 0 || self.redirect.is_some() || self.all == Some('+')
    }
}

pub fn parse_spf(record: &str) -> SpfRecord {
    let mut spf = SpfRecord::default();
    for term in record.split_whitespace().skip(1) {
        let term = term.to_ascii_lowercase();
        if let Some(target) = term.strip_prefix("redirect=") {
            spf.lookups += 1;
            spf.redirect = Some(target.to_owned());
            continue;
        }
        if term.contains('=') {
            continue; // exp= and unknown modifiers
        }
        let (qualifier, body) = match term.chars().next() {
            Some(q @ ('+' | '-' | '~' | '?')) => (q, &term[1..]),
            _ => ('+', term.as_str()),
        };
        if body == "all" {
            spf.all = Some(qualifier);
            continue;
        }
        spf.mechanisms += 1;
        let mechanism = body.split([':', '/']).next().unwrap_or_default();
        if matches!(mechanism, "include" | "a" | "mx" | "ptr" | "exists") {
            spf.lookups += 1;
        }
        if let Some(target) = body.strip_prefix("include:") {
            spf.includes.push(target.to_owned());
        }
    }
    spf
}

/// An SPF record with its includes and redirects followed.
#[derive(Debug, Default)]
struct SpfTree {
    lookups: usize,
    /// Effective `all` qualifier (from a redirect target when the record has none).
    all: Option<char>,
    has_required: bool,
    /// Includes or redirects that do not resolve to one SPF record (PermError).
    broken: Vec<String>,
    /// A nested lookup failed, so the tree is incomplete.
    unresolved: Option<String>,
}

async fn walk_spf(
    ctx: &CheckContext,
    domain: &str,
    root: &SpfRecord,
    required: &str,
    limit: usize,
) -> SpfTree {
    let names_required = |spf: &SpfRecord| {
        spf.includes.iter().any(|i| i == required) || spf.redirect.as_deref() == Some(required)
    };
    let mut tree = SpfTree {
        lookups: root.lookups,
        all: root.all,
        has_required: names_required(root),
        ..SpfTree::default()
    };
    let mut seen = BTreeSet::from([domain.to_owned()]);
    // (target, reached only through redirects from a record without `all`)
    let mut queue: Vec<(String, bool)> = root.includes.iter().map(|i| (i.clone(), false)).collect();
    queue.extend(
        root.redirect
            .iter()
            .map(|r| (r.clone(), root.all.is_none())),
    );
    let mut fetched = 0;
    while let Some((target, via_redirect)) = queue.pop() {
        if tree.lookups > limit {
            break;
        }
        // Macros (%{d}) depend on the message and cannot be expanded here.
        if target.contains('%') || !seen.insert(target.clone()) {
            continue;
        }
        if fetched == MAX_SPF_RECORDS {
            tree.unresolved = Some(format!(
                "stopped after {MAX_SPF_RECORDS} nested SPF records"
            ));
            break;
        }
        fetched += 1;
        match spf_records(ctx, &target).await {
            Ok(records) => match records.as_slice() {
                [record] => {
                    let spf = parse_spf(record);
                    tree.lookups += spf.lookups;
                    tree.has_required |= names_required(&spf);
                    if via_redirect && spf.all.is_some() {
                        tree.all = spf.all;
                    }
                    let inner_redirect = via_redirect && spf.all.is_none();
                    queue.extend(spf.includes.into_iter().map(|i| (i, false)));
                    queue.extend(spf.redirect.map(|r| (r, inner_redirect)));
                }
                [] => tree.broken.push(format!("{target} has no SPF record")),
                many => tree
                    .broken
                    .push(format!("{target} has {} SPF records", many.len())),
            },
            Err(e) => {
                tree.unresolved.get_or_insert(e);
            }
        }
    }
    tree
}

struct SpfSettings {
    required: String,
    max_lookups: usize,
    require_hard_fail: bool,
}

async fn spf(ctx: &CheckContext) -> Evaluation {
    let id = SPF.id;
    let settings = SpfSettings {
        required: ctx
            .setting(
                id,
                "required_include",
                "spf.protection.outlook.com".to_owned(),
            )
            .to_ascii_lowercase(),
        max_lookups: ctx.setting(id, "max_lookups", 10),
        require_hard_fail: ctx.setting(id, "require_hard_fail", false),
    };
    let domains = custom_domains(ctx).await?;
    let settings = &settings;
    let results = per_domain(ctx, &domains, |ctx, d| spf_domain(ctx, d, settings)).await;
    Ok(aggregate(
        "SPF",
        results,
        "No custom domains need SPF.",
        json!({"required_include": settings.required, "max_lookups": settings.max_lookups}),
    ))
}

async fn spf_domain(ctx: &CheckContext, d: &Domain, settings: &SpfSettings) -> DomainResult {
    let role = match role(ctx, d).await {
        Ok(role) => role,
        Err(e) => return DomainResult::new(d, None, Verdict::Unresolved, e),
    };
    let records = match spf_records(ctx, &d.name).await {
        Ok(records) => records,
        Err(e) => return DomainResult::new(d, Some(role), Verdict::Unresolved, e),
    };
    let result = |verdict, detail: String| DomainResult::new(d, Some(role), verdict, detail);
    if role == Role::Parked {
        let strict = matches!(records.as_slice(), [r] if parse_spf(r).all == Some('-'));
        return if strict {
            result(Verdict::Pass, "no mail; publishes v=spf1 -all".into())
        } else if records.is_empty() {
            result(
                Verdict::Warn,
                "no MX and no SPF; publish `v=spf1 -all` so the domain cannot be spoofed".into(),
            )
        } else {
            result(
                Verdict::Warn,
                "no MX; publish a single `v=spf1 -all` record so the domain cannot be spoofed"
                    .into(),
            )
        }
        .record(records.first().map(String::as_str));
    }
    let record = match records.as_slice() {
        [] => return result(Verdict::Fail, "no SPF record".into()),
        [record] => record,
        many => {
            return result(
                Verdict::Fail,
                format!(
                    "{} SPF records; RFC 7208 allows one and receivers return PermError",
                    many.len()
                ),
            );
        }
    };
    let spf = parse_spf(record);
    let tree = walk_spf(ctx, &d.name, &spf, &settings.required, settings.max_lookups).await;
    let complete = tree.unresolved.is_none();
    let mut problems = vec![];
    match tree.all {
        Some('-' | '~') => {}
        Some('?') => problems.push("ends ?all (neutral), which gives receivers no signal".into()),
        Some(_) => problems.push("ends +all, which authorises every sender".into()),
        None if complete || spf.redirect.is_none() => {
            problems.push("has no all mechanism, so unlisted senders are not failed".into())
        }
        None => {}
    }
    if role == Role::Exchange && !tree.has_required && complete {
        problems.push(format!("does not include {}", settings.required));
    }
    if tree.lookups > settings.max_lookups {
        problems.push(format!(
            "needs at least {} DNS lookups, over the limit of {}",
            tree.lookups, settings.max_lookups
        ));
    }
    problems.extend(tree.broken.iter().map(|b| format!("{b} (PermError)")));
    let verdict = if !problems.is_empty() {
        result(Verdict::Fail, problems.join("; "))
    } else if let Some(e) = tree.unresolved {
        result(
            Verdict::Unresolved,
            format!("nested SPF records could not be read: {e}"),
        )
    } else if tree.all == Some('~') && settings.require_hard_fail {
        result(
            Verdict::Warn,
            "ends ~all (soft fail); move to -all once every sender is listed".into(),
        )
    } else {
        result(
            Verdict::Pass,
            format!(
                "ends {}all, {} of {} DNS lookups",
                tree.all.unwrap_or('-'),
                tree.lookups,
                settings.max_lookups
            ),
        )
    };
    verdict.record(Some(record))
}

// ─── DKIM ───────────────────────────────────────────────────────────────────

const SELECTORS: [&str; 2] = ["selector1", "selector2"];

async fn dkim(ctx: &CheckContext) -> Evaluation {
    let domains = custom_domains(ctx).await?;
    let results = per_domain(ctx, &domains, dkim_domain).await;
    let mut finding = aggregate(
        "DKIM",
        results,
        "No custom domain sends mail through Exchange Online.",
        json!({
            "method": "selector CNAME records in public DNS",
            "signing_state": "not read: Get-DkimSigningConfig needs Exchange Online PowerShell, which Junction does not call",
        }),
    );
    if finding.status == Status::Pass {
        finding.summary.push_str(
            " Signing state was not read (Get-DkimSigningConfig needs Exchange Online PowerShell); the published CNAMEs decided.",
        );
    }
    Ok(finding)
}

async fn dkim_domain<'a>(ctx: &'a CheckContext, d: &'a Domain) -> DomainResult {
    let role = match role(ctx, d).await {
        Ok(role) => role,
        Err(e) => return DomainResult::new(d, None, Verdict::Unresolved, e),
    };
    let result = |verdict, detail: String| DomainResult::new(d, Some(role), verdict, detail);
    match role {
        Role::Exchange => {}
        Role::OtherMail => {
            return result(
                Verdict::Skipped,
                "mail is not hosted in Exchange Online".into(),
            );
        }
        Role::Parked => return result(Verdict::Skipped, "no mail".into()),
    }
    let (mut published, mut missing, mut failed) = (vec![], vec![], vec![]);
    for selector in SELECTORS {
        let name = format!("{selector}._domainkey.{}", d.name);
        match ctx.dns().lookup(&name, RecordType::Cname).await {
            Ok(targets) => published.push(format!("{selector} -> {}", targets.join(", "))),
            Err(DnsError::NotFound) => missing.push(selector),
            Err(DnsError::Failed(e)) => failed.push(format!("CNAME lookup for {name} failed: {e}")),
        }
    }
    if !missing.is_empty() {
        result(
            Verdict::Fail,
            format!(
                "{} CNAME missing; Exchange Online cannot sign without both selectors",
                missing.join(" and ")
            ),
        )
    } else if !failed.is_empty() {
        result(Verdict::Unresolved, failed.join("; "))
    } else {
        result(
            Verdict::Pass,
            format!("selector CNAMEs published ({})", published.join("; ")),
        )
    }
}

// ─── DMARC ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    pub p: Option<String>,
    pub sp: Option<String>,
    pub pct: u32,
    pub rua: Vec<String>,
}

pub fn parse_dmarc(record: &str) -> DmarcRecord {
    let mut dmarc = DmarcRecord {
        p: None,
        sp: None,
        pct: 100,
        rua: vec![],
    };
    for tag in record.split(';') {
        let Some((key, value)) = tag.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "p" => dmarc.p = Some(value.to_ascii_lowercase()),
            "sp" => dmarc.sp = Some(value.to_ascii_lowercase()),
            "pct" => dmarc.pct = value.parse().unwrap_or(100),
            "rua" => {
                dmarc.rua = value
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            }
            _ => {}
        }
    }
    dmarc
}

fn is_dmarc(record: &str) -> bool {
    let r = record.trim_start().to_ascii_lowercase();
    r.strip_prefix("v=dmarc1")
        .is_some_and(|rest| rest.trim_start().is_empty() || rest.trim_start().starts_with(';'))
}

/// Verdict for one DMARC record. `inherited` when it was found on a parent
/// domain, whose `sp=` (or `p=`) then applies.
fn evaluate_dmarc(record: &str, inherited: bool) -> (Verdict, String) {
    let dmarc = parse_dmarc(record);
    let Some(p) = dmarc.p.clone() else {
        return (Verdict::Fail, "DMARC record has no p= tag".into());
    };
    let policy = if inherited {
        dmarc.sp.clone().unwrap_or(p)
    } else {
        p
    };
    let mut notes = vec![];
    match policy.as_str() {
        "none" => notes.push("p=none only monitors; spoofed mail is still delivered".to_owned()),
        "quarantine" | "reject" => {}
        other => return (Verdict::Fail, format!("p={other} is not a valid policy")),
    }
    if dmarc.pct < 100 {
        notes.push(format!(
            "pct={} applies the policy to part of the mail",
            dmarc.pct
        ));
    }
    if !inherited && dmarc.sp.as_deref() == Some("none") {
        notes.push("sp=none leaves subdomains unprotected".into());
    }
    if dmarc.rua.is_empty() {
        notes.push("no rua= address, so aggregate reports are not collected".into());
    }
    if notes.is_empty() {
        (
            Verdict::Pass,
            format!("p={policy} with aggregate reporting"),
        )
    } else {
        (Verdict::Warn, notes.join("; "))
    }
}

async fn dmarc(ctx: &CheckContext) -> Evaluation {
    let domains = custom_domains(ctx).await?;
    let results = per_domain(ctx, &domains, dmarc_domain).await;
    Ok(aggregate(
        "DMARC",
        results,
        "No custom domain sends or receives mail.",
        json!({}),
    ))
}

async fn dmarc_domain<'a>(ctx: &'a CheckContext, d: &'a Domain) -> DomainResult {
    let role = match role(ctx, d).await {
        Ok(role) => role,
        Err(e) => return DomainResult::new(d, None, Verdict::Unresolved, e),
    };
    let result = |verdict, detail: String| DomainResult::new(d, Some(role), verdict, detail);
    if role == Role::Parked {
        return result(Verdict::Skipped, "no mail".into());
    }
    // The domain itself, then parents with at least two labels.
    let labels: Vec<&str> = d.name.split('.').collect();
    for skip in 0..labels.len().saturating_sub(1) {
        let owner = labels[skip..].join(".");
        let name = format!("_dmarc.{owner}");
        let records: Vec<String> = match txt(ctx, &name).await {
            Ok(records) => records.into_iter().filter(|r| is_dmarc(r)).collect(),
            Err(e) => return result(Verdict::Unresolved, e),
        };
        match records.as_slice() {
            [] => continue,
            [record] => {
                let (verdict, detail) = evaluate_dmarc(record, skip > 0);
                let detail = if skip > 0 {
                    format!("inherits _dmarc.{owner}: {detail}")
                } else {
                    detail
                };
                return result(verdict, detail).record(Some(record));
            }
            many => {
                return result(
                    Verdict::Fail,
                    format!(
                        "{} DMARC records at {name}; receivers ignore DMARC when there is more than one",
                        many.len()
                    ),
                );
            }
        }
    }
    result(
        Verdict::Fail,
        format!("no DMARC record at _dmarc.{}", d.name),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spf_terms_and_lookups() {
        let spf = parse_spf(
            "v=spf1 include:spf.protection.outlook.com ip4:192.0.2.0/24 a mx:mail.contoso.example exists:%{i}.x.contoso.example a/24 exp=explain.contoso.example -all",
        );
        assert_eq!(spf.all, Some('-'));
        assert_eq!(spf.lookups, 5);
        assert_eq!(spf.mechanisms, 6);
        assert_eq!(spf.includes, ["spf.protection.outlook.com"]);

        let spf = parse_spf("v=spf1 redirect=_spf.contoso.example");
        assert_eq!(spf.all, None);
        assert_eq!(spf.redirect.as_deref(), Some("_spf.contoso.example"));
        assert_eq!(spf.lookups, 1);
        assert!(spf.authorises_senders());

        assert_eq!(parse_spf("v=spf1 ~all").all, Some('~'));
        assert_eq!(parse_spf("V=SPF1 ?ALL").all, Some('?'));
        assert_eq!(parse_spf("v=spf1 all").all, Some('+'));
        assert!(!parse_spf("v=spf1 -all").authorises_senders());
        assert!(parse_spf("v=spf1 +all").authorises_senders());
        assert!(is_spf("v=spf1 -all") && is_spf("v=spf1") && !is_spf("v=spf10 -all"));
    }

    #[test]
    fn dmarc_tags_not_substrings() {
        let d = parse_dmarc(
            "v=DMARC1; sp=reject; p=none; pct=50; rua=mailto:a@contoso.example, mailto:b@contoso.example",
        );
        assert_eq!(d.p.as_deref(), Some("none"));
        assert_eq!(d.sp.as_deref(), Some("reject"));
        assert_eq!(d.pct, 50);
        assert_eq!(d.rua.len(), 2);
        assert!(is_dmarc("v=DMARC1; p=reject") && is_dmarc("v=DMARC1"));
        assert!(!is_dmarc("v=DMARC10; p=reject") && !is_dmarc("v=spf1 -all"));
    }

    #[test]
    fn dmarc_verdicts() {
        let v = |r: &str| evaluate_dmarc(r, false).0;
        assert_eq!(
            v("v=DMARC1; p=reject; rua=mailto:d@contoso.example"),
            Verdict::Pass
        );
        assert_eq!(
            v("v=DMARC1; p=quarantine; rua=mailto:d@contoso.example"),
            Verdict::Pass
        );
        assert_eq!(v("v=DMARC1; p=reject"), Verdict::Warn);
        assert_eq!(
            v("v=DMARC1; p=none; rua=mailto:d@contoso.example"),
            Verdict::Warn
        );
        assert_eq!(
            v("v=DMARC1; p=reject; pct=20; rua=mailto:d@contoso.example"),
            Verdict::Warn
        );
        assert_eq!(
            v("v=DMARC1; p=reject; sp=none; rua=mailto:d@contoso.example"),
            Verdict::Warn
        );
        assert_eq!(v("v=DMARC1; rua=mailto:d@contoso.example"), Verdict::Fail);
        assert_eq!(v("v=DMARC1; p=block"), Verdict::Fail);
        // A parent's sp= applies to subdomains.
        assert_eq!(
            evaluate_dmarc(
                "v=DMARC1; p=reject; sp=none; rua=mailto:d@contoso.example",
                true
            )
            .0,
            Verdict::Warn
        );
    }

    #[test]
    fn microsoft_domains_are_excluded() {
        assert!(microsoft_managed("contoso.onmicrosoft.com"));
        assert!(microsoft_managed("contoso.mail.onmicrosoft.com."));
        assert!(!microsoft_managed("contoso.example"));
        assert!(!microsoft_managed("notonmicrosoft.com"));
    }
}
