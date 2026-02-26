[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/M365",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-ExchangeOnline_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- Exchange Online Security Audit ---" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
    }
    
    Connect-ExchangeOnline -ShowBanner:$false
    
    $results = @()
    
    Write-Host "`n[Mailbox Auditing]" -ForegroundColor Yellow
    $auditConfig = Get-OrganizationConfig | Select-Object -ExpandProperty AuditDisabled
    if ($auditConfig -eq $true) {
        Write-Host "[CRITICAL] Mailbox auditing is DISABLED at organization level!" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Category = "MailboxAudit"
            Setting = "Organization Auditing"
            Value = "Disabled"
            RiskLevel = "Critical"
            Issues = "Mailbox auditing disabled - compliance risk"
        }
    }
    else {
        Write-Host "[OK] Mailbox auditing enabled" -ForegroundColor Green
        $results += [PSCustomObject]@{
            Category = "MailboxAudit"
            Setting = "Organization Auditing"
            Value = "Enabled"
            RiskLevel = "Low"
            Issues = ""
        }
    }
    
    Write-Host "`n[External Forwarding Rules]" -ForegroundColor Yellow
    $forwardingRules = Get-Mailbox -ResultSize Unlimited | Where-Object { 
        $_.ForwardingAddress -ne $null -or $_.ForwardingSmtpAddress -ne $null 
    } | Select-Object UserPrincipalName, ForwardingAddress, ForwardingSmtpAddress, DeliverToMailboxAndForward
    
    if ($forwardingRules) {
        foreach ($rule in $forwardingRules) {
            $isExternal = $false
            if ($rule.ForwardingSmtpAddress -and $rule.ForwardingSmtpAddress -notmatch "@$((Get-AcceptedDomain).DomainName)") {
                $isExternal = $true
            }
            
            $results += [PSCustomObject]@{
                Category = "Forwarding"
                Setting = "Mailbox Forwarding"
                Value = "$($rule.UserPrincipalName) -> $($rule.ForwardingSmtpAddress)"
                RiskLevel = if ($isExternal) { "High" } else { "Medium" }
                Issues = if ($isExternal) { "External forwarding detected" } else { "Internal forwarding" }
            }
            
            if ($isExternal) {
                Write-Host "[HIGH] $($rule.UserPrincipalName) forwards externally to $($rule.ForwardingSmtpAddress)" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "[OK] No forwarding rules found" -ForegroundColor Green
    }
    
    Write-Host "`n[Inbox Rules with External Forwarding]" -ForegroundColor Yellow
    $inboxRules = Get-Mailbox -ResultSize Unlimited | ForEach-Object {
        Get-InboxRule -Mailbox $_.UserPrincipalName -ErrorAction SilentlyContinue | 
        Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo }
    }
    
    foreach ($rule in $inboxRules) {
        $hasExternal = @($rule.ForwardTo, $rule.ForwardAsAttachmentTo, $rule.RedirectTo) | Where-Object { $_ -match "SMTP:" }
        
        if ($hasExternal) {
            Write-Host "[HIGH] Inbox rule '$($rule.Name)' on $($rule.MailboxOwnerId) forwards externally" -ForegroundColor Red
            $results += [PSCustomObject]@{
                Category = "InboxRule"
                Setting = "External Forwarding Rule"
                Value = "$($rule.MailboxOwnerId) - $($rule.Name)"
                RiskLevel = "High"
                Issues = "Rule forwards to: $($hasExternal -join ', ')"
            }
        }
    }
    
    Write-Host "`n[Delegates & Full Access]" -ForegroundColor Yellow
    $delegates = Get-Mailbox -ResultSize Unlimited | Get-MailboxPermission | Where-Object { 
        $_.AccessRights -contains "FullAccess" -and $_.User -notlike "NT AUTHORITY\SELF" -and $_.User -notlike "S-1-5-*"
    }
    
    foreach ($delegate in $delegates) {
        $results += [PSCustomObject]@{
            Category = "Delegation"
            Setting = "Full Access Permission"
            Value = "$($delegate.Identity) <- $($delegate.User)"
            RiskLevel = "Medium"
            Issues = "Full mailbox access granted"
        }
        Write-Host "[MEDIUM] $($delegate.User) has Full Access to $($delegate.Identity)" -ForegroundColor DarkYellow
    }
    
    Write-Host "`n[Transport Rules]" -ForegroundColor Yellow
    $transportRules = Get-TransportRule | Where-Object { 
        $_.Mode -eq "Enforce" -and (
            $_.DeleteMessage -or 
            $_.RedirectMessageTo -or 
            $_.BlindCopyTo
        )
    }
    
    foreach ($tRule in $transportRules) {
        $results += [PSCustomObject]@{
            Category = "TransportRule"
            Setting = "Active Transport Rule"
            Value = $tRule.Name
            RiskLevel = "Low"
            Issues = "Rule active with redirect/delete actions"
        }
        Write-Host "[INFO] Transport Rule: $($tRule.Name)" -ForegroundColor Gray
    }
    
    Write-Host "`n[Anti-Phishing & DKIM]" -ForegroundColor Yellow
    $antiPhishPolicy = Get-AntiPhishPolicy | Where-Object { $_.Identity -eq "Office365 AntiPhish Default" -or $_.IsDefault -eq $true }
    
    if ($antiPhishPolicy) {
        if ($antiPhishPolicy.EnableFirstContactSafetyTips -eq $true) {
            Write-Host "[OK] First contact safety tips enabled" -ForegroundColor Green
        }
        else {
            Write-Host "[MEDIUM] First contact safety tips not enabled" -ForegroundColor Yellow
        }
    }
    
    $dkimConfig = Get-DkimSigningConfig | Where-Object { $_.Enabled -eq $true }
    Write-Host "[INFO] DKIM enabled for $($dkimConfig.Count) domains" -ForegroundColor Cyan
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "  External Forwards: $(($results | Where-Object { $_.Category -eq 'Forwarding' -and $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor Red
    Write-Host "  Suspicious Inbox Rules: $(($results | Where-Object { $_.Category -eq 'InboxRule' }).Count)" -ForegroundColor Red
    Write-Host "  Delegates: $(($results | Where-Object { $_.Category -eq 'Delegation' }).Count)" -ForegroundColor Yellow
    Write-Host "  Critical Issues: $(($results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count)" -ForegroundColor Red
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "ExchangeOnline_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "ExchangeOnline_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n--- Exchange Online Audit Complete ---" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
    Stop-Transcript
}

return $results
