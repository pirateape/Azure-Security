[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-AzureADConnect_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Azure AD Connect Health Audit ===" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "Organization.Read.All", "Directory.Read.All", "AuditLog.Read.All" -NoWelcome
    
    $results = @()
    
    # Get organization info
    Write-Host "`n[Directory Synchronization Status]" -ForegroundColor Yellow
    $org = Get-MgOrganization -Property "id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesSyncLastSyncDate"
    
    $results += [PSCustomObject]@{
        CheckType = "DirectorySync"
        Setting = "Sync Enabled"
        Value = $org.OnPremisesSyncEnabled
        RiskLevel = "Info"
        Details = ""
    }
    
    if ($org.OnPremisesSyncEnabled -eq $true) {
        Write-Host "[INFO] Azure AD Connect is enabled" -ForegroundColor Cyan
        
        $lastSync = $org.OnPremisesLastSyncDateTime
        if ($lastSync) {
            $minutesSinceSync = [math]::Floor(((Get-Date) - [datetime]$lastSync).TotalMinutes)
            Write-Host "  Last Sync: $lastSync ($minutesSinceSync minutes ago)" -ForegroundColor $(if ($minutesSinceSync -lt 30) { "Green" } elseif ($minutesSinceSync -lt 120) { "Yellow" } else { "Red" })
            
            $results += [PSCustomObject]@{
                CheckType = "LastSync"
                Setting = "Minutes Since Last Sync"
                Value = $minutesSinceSync
                RiskLevel = if ($minutesSinceSync -gt 180) { "Critical" } elseif ($minutesSinceSync -gt 60) { "High" } elseif ($minutesSinceSync -gt 30) { "Medium" } else { "Low" }
                Details = "Last sync at $lastSync"
            }
            
            if ($minutesSinceSync -gt 180) {
                Write-Host "  [CRITICAL] Sync is more than 3 hours old!" -ForegroundColor Red
            }
            elseif ($minutesSinceSync -gt 60) {
                Write-Host "  [WARNING] Sync is more than 1 hour old" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "  [WARNING] Last sync time not available" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[INFO] Azure AD Connect is not enabled (cloud-only environment)" -ForegroundColor Cyan
    }
    
    # Check sync errors
    Write-Host "`n[Sync Errors Analysis]" -ForegroundColor Yellow
    try {
        # Get synchronization errors from audit logs
        $syncErrors = Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Sync Audit Event'" -Top 50 | Where-Object { $_.Result -eq "failure" }
        
        if ($syncErrors) {
            Write-Host "[WARNING] Found $($syncErrors.Count) sync errors in recent audit logs" -ForegroundColor Yellow
            $results += [PSCustomObject]@{
                CheckType = "SyncErrors"
                Setting = "Recent Sync Errors"
                Value = $syncErrors.Count
                RiskLevel = "High"
                Details = "Recent sync failures detected"
            }
        }
        else {
            Write-Host "[OK] No recent sync errors found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[INFO] Unable to retrieve sync error details" -ForegroundColor Gray
    }
    
    # Check hybrid join status
    Write-Host "`n[Hybrid Azure AD Join Status]" -ForegroundColor Yellow
    $devices = Get-MgDevice -All -Property "id,displayName,deviceId,operatingSystem,operatingSystemVersion,trustType,approximateLastSignInDateTime,isCompliant,isManaged"
    
    $hybridJoined = $devices | Where-Object { $_.TrustType -eq "ServerAd" }
    $azureAdJoined = $devices | Where-Object { $_.TrustType -eq "AzureAd" }
    $registered = $devices | Where-Object { $_.TrustType -eq "Workplace" }
    
    Write-Host "  Hybrid Joined: $($hybridJoined.Count)" -ForegroundColor Cyan
    Write-Host "  Azure AD Joined: $($azureAdJoined.Count)" -ForegroundColor Cyan
    Write-Host "  Workplace Joined: $($registered.Count)" -ForegroundColor Cyan
    Write-Host "  Total Devices: $($devices.Count)" -ForegroundColor Cyan
    
    $results += [PSCustomObject]@{
        CheckType = "HybridJoin"
        Setting = "Hybrid Joined Devices"
        Value = $hybridJoined.Count
        RiskLevel = "Info"
        Details = ""
    }
    
    $results += [PSCustomObject]@{
        CheckType = "AzureADJoin"
        Setting = "Azure AD Joined Devices"
        Value = $azureAdJoined.Count
        RiskLevel = "Info"
        Details = ""
    }
    
    # Check for stale hybrid devices
    $staleThreshold = (Get-Date).AddDays(-90)
    $staleDevices = $hybridJoined | Where-Object { $_.ApproximateLastSignInDateTime -lt $staleThreshold }
    
    if ($staleDevices.Count -gt 0) {
        Write-Host "`n[WARNING] Found $($staleDevices.Count) stale hybrid joined devices (no sign-in for 90+ days)" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            CheckType = "StaleHybridDevices"
            Setting = "Stale Hybrid Devices"
            Value = $staleDevices.Count
            RiskLevel = "Medium"
            Details = "Devices not signed in for 90+ days"
        }
    }
    
    # Check sync configuration
    Write-Host "`n[Sync Configuration]" -ForegroundColor Yellow
    try {
        $syncFeatures = Get-MgDirectoryOnPremiseSynchronization -ErrorAction SilentlyContinue
        
        if ($syncFeatures) {
            Write-Host "  Password Hash Sync: $($syncFeatures.Features.PasswordHashSync)" -ForegroundColor $(if ($syncFeatures.Features.PasswordHashSync -eq "Enabled") { "Green" } else { "Yellow" })
            Write-Host "  Seamless SSO: $($syncFeatures.Features.SeamlessSingleSignOn)" -ForegroundColor $(if ($syncFeatures.Features.SeamlessSingleSignOn -eq "Enabled") { "Green" } else { "Gray" })
            Write-Host "  Password Writeback: $($syncFeatures.Features.PasswordWriteback)" -ForegroundColor $(if ($syncFeatures.Features.PasswordWriteback -eq "Enabled") { "Green" } else { "Gray" })
            Write-Host "  Device Writeback: $($syncFeatures.Features.DeviceWriteback)" -ForegroundColor $(if ($syncFeatures.Features.DeviceWriteback -eq "Enabled") { "Green" } else { "Gray" })
            
            $results += [PSCustomObject]@{
                CheckType = "PasswordHashSync"
                Setting = "Password Hash Sync"
                Value = $syncFeatures.Features.PasswordHashSync
                RiskLevel = if ($syncFeatures.Features.PasswordHashSync -ne "Enabled") { "Medium" } else { "Low" }
                Details = ""
            }
            
            $results += [PSCustomObject]@{
                CheckType = "PasswordWriteback"
                Setting = "Password Writeback"
                Value = $syncFeatures.Features.PasswordWriteback
                RiskLevel = "Info"
                Details = ""
            }
        }
    }
    catch {
        Write-Host "  [INFO] Unable to retrieve sync features configuration" -ForegroundColor Gray
    }
    
    # Check for PHS issues
    Write-Host "`n[Password Hash Sync Health]" -ForegroundColor Yellow
    $recentPasswordChanges = Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Change user password'" -Top 10
    
    if ($recentPasswordChanges) {
        Write-Host "  [OK] Recent password changes detected in audit logs" -ForegroundColor Green
        Write-Host "  Recent changes: $($recentPasswordChanges.Count) in last period" -ForegroundColor Gray
    }
    
    # Summary
    Write-Host "`n=== Azure AD Connect Summary ===" -ForegroundColor Cyan
    Write-Host "Sync Enabled: $($org.OnPremisesSyncEnabled)" -ForegroundColor Cyan
    Write-Host "Hybrid Devices: $($hybridJoined.Count)" -ForegroundColor Cyan
    Write-Host "Azure AD Devices: $($azureAdJoined.Count)" -ForegroundColor Cyan
    Write-Host "Stale Devices: $($staleDevices.Count)" -ForegroundColor $(if ($staleDevices.Count -gt 0) { "Yellow" } else { "Green" })
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "AzureADConnect_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "AzureADConnect_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Azure AD Connect Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
