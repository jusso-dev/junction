# Read-only runner contract test. All Exchange cmdlets are local doubles.
$ErrorActionPreference = 'Stop'
$directory = Join-Path ([IO.Path]::GetTempPath()) ("junction-watch-test-" + [Guid]::NewGuid())
function Connect-ExchangeOnline {}
function Disconnect-ExchangeOnline {}
function Get-OrganizationConfig { [pscustomobject]@{ ExternalDirectoryOrganizationId='11111111-1111-4111-8111-111111111111'; AuditDisabled=$null } }
function Get-Mailbox {
    [pscustomobject]@{ PrimarySmtpAddress='treasurer@club.example'; ForwardingSmtpAddress=''; ForwardingAddress='external-contact'; GrantSendOnBehalfTo=@(); AuditEnabled=$null; AuditAdmin=$null; AuditDelegate=@(); AuditOwner=@() }
}
function Get-Recipient { [pscustomobject]@{ ExternalEmailAddress='smtp:recipient@outside.example'; PrimarySmtpAddress='contact@club.example' } }
function Get-InboxRule { throw 'synthetic missing permission' }
function Get-MailboxPermission { @() }
function Get-RecipientPermission { @() }
function Get-TransportRule { @() }
function Get-AcceptedDomain { @() }
function Get-RemoteDomain { @() }
function Get-HostedOutboundSpamFilterPolicy { @() }
function Get-AdminAuditLogConfig { [pscustomobject]@{ UnifiedAuditLogIngestionEnabled=$null } }
function Get-MailboxAuditBypassAssociation { [pscustomobject]@{ AuditBypassEnabled=$null } }
try {
    $path = Join-Path $PSScriptRoot '../watch/collect-exchange.ps1'
    $source = Get-Content -LiteralPath $path -Raw
    # The test provides the module's functions; it must not load a real Exchange session.
    $source = $source -replace '(?m)^#requires -Modules ExchangeOnlineManagement\r?\n', ''
    $runner = [scriptblock]::Create($source)
    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
    & $runner -TenantId '11111111-1111-4111-8111-111111111111' -AppId '22222222-2222-4222-8222-222222222222' -Organization 'club.onmicrosoft.com' -Certificate $certificate -OutputDirectory $directory
    $mailboxes = Get-Content (Join-Path $directory 'mailboxes.json') -Raw | ConvertFrom-Json
    $mailbox = $mailboxes.resources.'treasurer@club.example'
    if ($mailboxes.status -ne 'complete') { throw 'Expected complete mailbox export' }
    if ($null -ne $mailbox.AuditEnabled -or $null -ne $mailbox.AuditAdmin) { throw 'Unknown fields must remain null, never disabled or empty' }
    if ($mailbox.ForwardingAddress -ne 'smtp:recipient@outside.example') { throw 'Named forwarding destination was not resolved' }
    $rules = Get-Content (Join-Path $directory 'inbox_rules.json') -Raw | ConvertFrom-Json
    if ($rules.status -ne 'partial') { throw 'A denied cmdlet must not produce a complete empty snapshot' }
    $audit = Get-Content (Join-Path $directory 'audit_configuration.json') -Raw | ConvertFrom-Json
    if ($null -ne $audit.resources.organization.AuditDisabled) { throw 'Null audit setting became false' }
    Write-Output 'Exchange runner contract tests passed.'
} finally {
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
}
