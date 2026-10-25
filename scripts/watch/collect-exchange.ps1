#requires -Version 7.2
#requires -Modules ExchangeOnlineManagement
<#
Read-only optional runner. Supply a certificate object from the host certificate
store or Azure Automation certificate asset. Never supply an administrator password.
Use a dedicated app with Exchange.ManageAsApp and a custom read-only Exchange role
containing only these Get-* cmdlets, scoped to the intended recipients. Test each
cmdlet: missing roles produce partial/failed snapshots, never an empty baseline.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][Guid]$TenantId,
    [Parameter(Mandatory)][Guid]$AppId,
    [Parameter(Mandatory)][ValidatePattern('^[a-zA-Z0-9.-]+\.onmicrosoft\.com$')][string]$Organization,
    [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
    [Parameter(Mandatory)][string]$OutputDirectory
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
# Protect OutputDirectory with host ACLs before scheduling; exports contain addresses.
function Export-Snapshot([string]$Type, [scriptblock]$Collect) {
    $script:Resources = @{}
    $script:CollectionFailed = $false
    try { & $Collect } catch { $script:CollectionFailed = $true }
    $status = if ($script:CollectionFailed) { 'partial' } else { 'complete' }
    $data = [ordered]@{
        tenant_id = $TenantId.ToString(); resource_type = $Type
        collected_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        source_api = 'exchange_online_powershell'; status = $status
        resources = $script:Resources
    }
    $path = Join-Path $OutputDirectory "$Type.json"
    $temporary = "$path.$([Guid]::NewGuid().ToString('N')).tmp"
    $data | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporary -Encoding utf8NoBOM
    Move-Item -LiteralPath $temporary -Destination $path -Force
    # No raw error text or configuration values enter logs.
    Write-Output "$Type : $status ($($script:Resources.Count) resources)"
}
function Read-Strings($Value) {
    if ($null -eq $Value) { return $null }
    return ,@($Value | ForEach-Object { [string]$_ })
}
function Read-Mailboxes([scriptblock]$Collect) {
    foreach ($mailbox in $script:Mailboxes) {
        try { & $Collect $mailbox } catch { $script:CollectionFailed = $true }
    }
}
try {
    Connect-ExchangeOnline -AppId $AppId.ToString() -Organization $Organization -Certificate $Certificate -ShowBanner:$false
    $org = Get-OrganizationConfig
    if ([string]$org.ExternalDirectoryOrganizationId -ne $TenantId.ToString()) { throw 'Tenant mismatch' }
    # Enumeration must succeed before any collection can be called complete.
    $script:Mailboxes = @(Get-Mailbox -ResultSize Unlimited)
    Export-Snapshot 'mailboxes' {
        foreach ($m in $script:Mailboxes) {
            $forwarding = [string]$m.ForwardingAddress
            if ($m.ForwardingAddress) {
                try {
                    $recipient = Get-Recipient -Identity $m.ForwardingAddress
                    $forwarding = if ($recipient.ExternalEmailAddress) { [string]$recipient.ExternalEmailAddress } else { [string]$recipient.PrimarySmtpAddress }
                } catch { $forwarding = $null; $script:CollectionFailed = $true }
            }
            $script:Resources[[string]$m.PrimarySmtpAddress] = @{
                ForwardingSmtpAddress = [string]$m.ForwardingSmtpAddress
                ForwardingAddress = $forwarding
                GrantSendOnBehalfTo = @($m.GrantSendOnBehalfTo | ForEach-Object { [string]$_ })
                AuditEnabled = $m.AuditEnabled
                AuditAdmin = Read-Strings $m.AuditAdmin
                AuditDelegate = Read-Strings $m.AuditDelegate
                AuditOwner = Read-Strings $m.AuditOwner
            }
        }
    }
    Export-Snapshot 'inbox_rules' {
        Read-Mailboxes { param($m)
            foreach ($r in @(Get-InboxRule -Mailbox $m.PrimarySmtpAddress -IncludeHidden)) {
                $script:Resources["$($m.PrimarySmtpAddress)\$($r.Name)"] = @{
                    Enabled = $r.Enabled; ForwardTo = @($r.ForwardTo | ForEach-Object { [string]$_ })
                    RedirectTo = @($r.RedirectTo | ForEach-Object { [string]$_ })
                    ForwardAsAttachmentTo = @($r.ForwardAsAttachmentTo | ForEach-Object { [string]$_ })
                    DeleteMessage = $r.DeleteMessage; MoveToFolder = [string]$r.MoveToFolder
                    MarkAsRead = $r.MarkAsRead; StopProcessingRules = $r.StopProcessingRules
                }
            }
        }
    }
    Export-Snapshot 'delegation' {
        Read-Mailboxes { param($m)
            foreach ($p in @(Get-MailboxPermission -Identity $m.PrimarySmtpAddress)) {
                if (-not $p.IsInherited -and -not $p.Deny -and [string]$p.User -ne 'NT AUTHORITY\SELF') {
                    $script:Resources["$($m.PrimarySmtpAddress)|FullAccess|$($p.User)"] = @{ AccessRights = @($p.AccessRights | ForEach-Object { [string]$_ }); User = [string]$p.User }
                }
            }
            foreach ($p in @(Get-RecipientPermission -Identity $m.PrimarySmtpAddress)) {
                if (-not $p.IsInherited -and [string]$p.Trustee -ne 'NT AUTHORITY\SELF') {
                    $script:Resources["$($m.PrimarySmtpAddress)|SendAs|$($p.Trustee)"] = @{ AccessRights = @($p.AccessRights | ForEach-Object { [string]$_ }); User = [string]$p.Trustee }
                }
            }
        }
    }
    Export-Snapshot 'transport_rules' {
        foreach ($r in @(Get-TransportRule -ResultSize Unlimited)) {
            $script:Resources[[string]$r.Guid] = @{ State = [string]$r.State; Mode = [string]$r.Mode
                RedirectMessageTo = @($r.RedirectMessageTo | ForEach-Object { [string]$_ })
                DeleteMessage = $r.DeleteMessage
                BlindCopyTo = @($r.BlindCopyTo | ForEach-Object { [string]$_ })
                AddToRecipients = @($r.AddToRecipients | ForEach-Object { [string]$_ })
                SetHeaderName = [string]$r.SetHeaderName
            }
        }
    }
    Export-Snapshot 'accepted_domains' { foreach ($d in @(Get-AcceptedDomain)) { $script:Resources[[string]$d.Guid] = @{ DomainName = [string]$d.DomainName; DomainType = [string]$d.DomainType } } }
    Export-Snapshot 'remote_domains' { foreach ($d in @(Get-RemoteDomain)) { $script:Resources[[string]$d.Guid] = @{ DomainName = [string]$d.DomainName; AutoForwardEnabled = $d.AutoForwardEnabled } } }
    Export-Snapshot 'anti_spam' { foreach ($p in @(Get-HostedOutboundSpamFilterPolicy)) { $script:Resources[[string]$p.Identity] = @{ AutoForwardingMode = [string]$p.AutoForwardingMode; BccSuspiciousOutboundMail = $p.BccSuspiciousOutboundMail } } }
    Export-Snapshot 'audit_configuration' { $script:Resources['organization'] = @{ AuditDisabled = $org.AuditDisabled }; $a = Get-AdminAuditLogConfig; $script:Resources['unified'] = @{ UnifiedAuditLogIngestionEnabled = $a.UnifiedAuditLogIngestionEnabled } }
    Export-Snapshot 'audit_bypass' { Read-Mailboxes { param($m) $b = Get-MailboxAuditBypassAssociation -Identity $m.PrimarySmtpAddress; $script:Resources[[string]$m.PrimarySmtpAddress] = @{ AuditBypassEnabled = $b.AuditBypassEnabled } } }
} catch {
    # No exception text: authentication failures can include sensitive context.
    Write-Error 'Exchange collection failed. No complete replacement snapshots were produced. Check certificate, tenant, cmdlet availability and scoped roles.'
    exit 1
} finally { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }
