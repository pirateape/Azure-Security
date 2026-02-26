[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/M365",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-SharePoint_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- SharePoint Online Security Audit ---" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Online.SharePoint.PowerShell)) {
        Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser -Force
    }
    
    $tenant = Get-SPOTenant
    $results = @()
    
    Write-Host "`n[Tenant Sharing Settings]" -ForegroundColor Yellow
    
    $sharingCapabilities = @{
        "Disabled" = "No external sharing"
        "ExternalUserSharingOnly" = "Authenticated external users only"
        "ExternalUserAndGuestSharing" = "Anyone links (anonymous access)"
    }
    
    $sharingCapability = $sharingCapabilities[$tenant.SharingCapability.ToString()]
    Write-Host "Sharing Capability: $sharingCapability" -ForegroundColor Cyan
    
    $riskLevel = switch ($tenant.SharingCapability.ToString()) {
        "ExternalUserAndGuestSharing" { "High" }
        "ExternalUserSharingOnly" { "Medium" }
        default { "Low" }
    }
    
    $results += [PSCustomObject]@{
        Category = "TenantSharing"
        Setting = "Sharing Capability"
        Value = $tenant.SharingCapability.ToString()
        RiskLevel = $riskLevel
        Issues = $sharingCapability
    }
    
    if ($tenant.SharingCapability.ToString() -eq "ExternalUserAndGuestSharing") {
        Write-Host "[HIGH] Anonymous 'Anyone' links are enabled!" -ForegroundColor Red
    }
    
    Write-Host "`n[Default Link Settings]" -ForegroundColor Yellow
    
    $defaultLinkType = $tenant.DefaultSharingLinkType
    Write-Host "Default Sharing Link: $defaultLinkType" -ForegroundColor Cyan
    
    $riskLevel = if ($defaultLinkType -eq "AnonymousAccess") { "High" }
                 elseif ($defaultLinkType -eq "Internal") { "Low" }
                 else { "Medium" }
    
    $results += [PSCustomObject]@{
        Category = "LinkSettings"
        Setting = "Default Sharing Link Type"
        Value = $defaultLinkType.ToString()
        RiskLevel = $riskLevel
        Issues = ""
    }
    
    if ($tenant.DefaultLinkPermission -eq "Edit") {
        Write-Host "[MEDIUM] Default link permission is 'Edit'" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            Category = "LinkSettings"
            Setting = "Default Link Permission"
            Value = "Edit"
            RiskLevel = "Medium"
            Issues = "Default permission allows editing"
        }
    }
    
    Write-Host "`n[Link Expiration Settings]" -ForegroundColor Yellow
    
    if ($tenant.ExternalUserExpireInDays -gt 0) {
        Write-Host "[OK] External user expiration: $($tenant.ExternalUserExpireInDays) days" -ForegroundColor Green
        $results += [PSCustomObject]@{
            Category = "Expiration"
            Setting = "External User Expiration"
            Value = "$($tenant.ExternalUserExpireInDays) days"
            RiskLevel = "Low"
            Issues = ""
        }
    }
    else {
        Write-Host "[HIGH] External user expiration not configured!" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Category = "Expiration"
            Setting = "External User Expiration"
            Value = "Not Configured"
            RiskLevel = "High"
            Issues = "External users never expire"
        }
    }
    
    if ($tenant.ExpireVersionsAfterDays -gt 0) {
        Write-Host "[OK] Version expiration: $($tenant.ExpireVersionsAfterDays) days" -ForegroundColor Green
    }
    
    Write-Host "`n[Access Control Settings]" -ForegroundColor Yellow
    
    if ($tenant.ConditionalAccessPolicy -eq "AllowLimitedAccess") {
        Write-Host "[OK] Conditional access policy: Limited access" -ForegroundColor Green
        $results += [PSCustomObject]@{
            Category = "AccessControl"
            Setting = "Conditional Access"
            Value = "AllowLimitedAccess"
            RiskLevel = "Low"
            Issues = ""
        }
    }
    
    if ($tenant.DisallowInfectedFileDownload -eq $true) {
        Write-Host "[OK] Infected file download blocked" -ForegroundColor Green
    }
    else {
        Write-Host "[MEDIUM] Infected files can be downloaded" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            Category = "AccessControl"
            Setting = "Infected File Download"
            Value = "Allowed"
            RiskLevel = "Medium"
            Issues = "Users can download infected files"
        }
    }
    
    Write-Host "`n[Site Collection Audit]" -ForegroundColor Yellow
    $sites = Get-SPOSite -Limit All | Where-Object { $_.Url -notlike "*-my.sharepoint.com*" }
    
    $publicSites = @()
    $externalSharingSites = @()
    
    foreach ($site in $sites) {
        if ($site.SharingCapability -eq "ExternalUserAndGuestSharing") {
            $publicSites += $site
        }
        if ($site.SharingCapability -ne "Disabled") {
            $externalSharingSites += $site
        }
    }
    
    Write-Host "Total Sites: $($sites.Count)" -ForegroundColor Cyan
    Write-Host "Sites with Anonymous Sharing: $($publicSites.Count)" -ForegroundColor $(if ($publicSites.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "Sites with External Sharing: $($externalSharingSites.Count)" -ForegroundColor Yellow
    
    foreach ($site in $publicSites | Select-Object -First 20) {
        $results += [PSCustomObject]@{
            Category = "SiteSettings"
            Setting = "Anonymous Sharing Site"
            Value = $site.Url
            RiskLevel = "High"
            Issues = "Anyone links enabled"
        }
    }
    
    Write-Host "`n[Admin Audit Log]" -ForegroundColor Yellow
    $auditLogEnabled = $tenant.AuditDisabled
    
    if ($auditLogEnabled -eq $true) {
        Write-Host "[CRITICAL] Audit logging is DISABLED!" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Category = "Audit"
            Setting = "Audit Logging"
            Value = "Disabled"
            RiskLevel = "Critical"
            Issues = "SharePoint audit logs disabled"
        }
    }
    else {
        Write-Host "[OK] Audit logging enabled" -ForegroundColor Green
    }
    
    Write-Host "`n[Legacy Authentication]" -ForegroundColor Yellow
    if ($tenant.LegacyAuthProtocolsEnabled -eq $true) {
        Write-Host "[HIGH] Legacy authentication protocols enabled!" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Category = "Authentication"
            Setting = "Legacy Authentication"
            Value = "Enabled"
            RiskLevel = "High"
            Issues = "Legacy auth (NTLM, Basic) allowed"
        }
    }
    else {
        Write-Host "[OK] Legacy authentication disabled" -ForegroundColor Green
    }
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "  Total Sites: $($sites.Count)"
    Write-Host "  Critical Issues: $(($results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count)" -ForegroundColor Red
    Write-Host "  High Risk: $(($results | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor Red
    Write-Host "  Medium Risk: $(($results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count)" -ForegroundColor Yellow
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "SharePoint_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "SharePoint_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n--- SharePoint Audit Complete ---" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Disconnect-SPOService -ErrorAction SilentlyContinue
    Stop-Transcript
}

return $results
