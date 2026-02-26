[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/M365",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-Purview_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- Microsoft Purview Compliance Audit ---" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Install-Module ExchangeOnlineManagement -Scope CurrentUser -Force
    }
    
    Connect-ExchangeOnline -ShowBanner:$false
    
    $results = @()
    
    Write-Host "`n[Data Loss Prevention (DLP) Policies]" -ForegroundColor Yellow
    $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction SilentlyContinue
    
    if ($dlpPolicies) {
        Write-Host "DLP Policies Found: $($dlpPolicies.Count)" -ForegroundColor Cyan
        
        foreach ($policy in $dlpPolicies) {
            $enabled = $policy.Enabled
            $mode = $policy.Mode
            
            $riskLevel = if ($mode -eq "Enable") { "Low" }
                         elseif ($mode -eq "TestWithNotifications") { "Medium" }
                         else { "Medium" }
            
            $results += [PSCustomObject]@{
                Category = "DLP"
                Setting = $policy.Name
                Value = $mode
                RiskLevel = $riskLevel
                Issues = if ($mode -ne "Enable") { "Policy not in enforcement mode" } else { "" }
            }
            
            Write-Host "  [$mode] $($policy.Name)" -ForegroundColor $(if ($mode -eq "Enable") { "Green" } else { "Yellow" })
        }
    }
    else {
        Write-Host "[HIGH] No DLP policies configured!" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Category = "DLP"
            Setting = "DLP Policies"
            Value = "None"
            RiskLevel = "High"
            Issues = "No DLP policies configured"
        }
    }
    
    Write-Host "`n[Sensitivity Labels]" -ForegroundColor Yellow
    $labels = Get-Label -ErrorAction SilentlyContinue
    
    if ($labels) {
        Write-Host "Sensitivity Labels Found: $($labels.Count)" -ForegroundColor Cyan
        
        $encryptionLabels = $labels | Where-Object { $_.EncryptionEnabled -eq $true }
        Write-Host "Labels with Encryption: $($encryptionLabels.Count)" -ForegroundColor Green
        
        if ($encryptionLabels.Count -eq 0) {
            $results += [PSCustomObject]@{
                Category = "SensitivityLabels"
                Setting = "Encryption Labels"
                Value = "0"
                RiskLevel = "Medium"
                Issues = "No sensitivity labels with encryption"
            }
        }
        
        $publishedLabels = Get-LabelPolicy -ErrorAction SilentlyContinue
        if ($publishedLabels) {
            Write-Host "Published Label Policies: $($publishedLabels.Count)" -ForegroundColor Green
        }
    }
    else {
        Write-Host "[HIGH] No sensitivity labels configured!" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Category = "SensitivityLabels"
            Setting = "Labels"
            Value = "None"
            RiskLevel = "High"
            Issues = "No sensitivity labels configured"
        }
    }
    
    Write-Host "`n[Retention Policies]" -ForegroundColor Yellow
    $retentionPolicies = Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue
    
    if ($retentionPolicies) {
        Write-Host "Retention Policies Found: $($retentionPolicies.Count)" -ForegroundColor Cyan
        
        foreach ($policy in $retentionPolicies) {
            $results += [PSCustomObject]@{
                Category = "Retention"
                Setting = $policy.Name
                Value = $policy.Enabled
                RiskLevel = "Low"
                Issues = ""
            }
        }
    }
    else {
        Write-Host "[MEDIUM] No retention policies configured" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            Category = "Retention"
            Setting = "Retention Policies"
            Value = "None"
            RiskLevel = "Medium"
            Issues = "No retention policies - potential compliance gap"
        }
    }
    
    Write-Host "`n[Information Barriers]" -ForegroundColor Yellow
    $ibPolicies = Get-InformationBarrierPolicy -ErrorAction SilentlyContinue
    
    if ($ibPolicies) {
        $activePolicies = $ibPolicies | Where-Object { $_.State -eq "Active" }
        Write-Host "Information Barrier Policies: $($ibPolicies.Count) (Active: $($activePolicies.Count))" -ForegroundColor Cyan
        
        if ($activePolicies.Count -gt 0) {
            Write-Host "[OK] Information barriers are active" -ForegroundColor Green
        }
    }
    else {
        Write-Host "[INFO] No information barrier policies configured" -ForegroundColor Gray
    }
    
    Write-Host "`n[Insider Risk Management]" -ForegroundColor Yellow
    try {
        $irmPolicies = Get-InsiderRiskPolicy -ErrorAction SilentlyContinue
        if ($irmPolicies) {
            Write-Host "Insider Risk Policies: $($irmPolicies.Count)" -ForegroundColor Cyan
        }
        else {
            Write-Host "[INFO] No insider risk policies configured" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "[INFO] Insider Risk Management not available or not licensed" -ForegroundColor Gray
    }
    
    Write-Host "`n[eDiscovery Settings]" -ForegroundColor Yellow
    $eDiscoveryCases = Get-ComplianceCase -CaseType eDiscovery -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Active" }
    
    if ($eDiscoveryCases) {
        Write-Host "Active eDiscovery Cases: $($eDiscoveryCases.Count)" -ForegroundColor Cyan
    }
    else {
        Write-Host "No active eDiscovery cases" -ForegroundColor Gray
    }
    
    Write-Host "`n[Audit Log Search]" -ForegroundColor Yellow
    $auditConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
    
    if ($auditConfig) {
        if ($auditConfig.UnifiedAuditLogIngestionEnabled -eq $true) {
            Write-Host "[OK] Unified Audit Log enabled" -ForegroundColor Green
            $results += [PSCustomObject]@{
                Category = "Audit"
                Setting = "Unified Audit Log"
                Value = "Enabled"
                RiskLevel = "Low"
                Issues = ""
            }
        }
        else {
            Write-Host "[CRITICAL] Unified Audit Log is DISABLED!" -ForegroundColor Red
            $results += [PSCustomObject]@{
                Category = "Audit"
                Setting = "Unified Audit Log"
                Value = "Disabled"
                RiskLevel = "Critical"
                Issues = "Audit log search disabled - major compliance risk"
            }
        }
    }
    
    Write-Host "`n[Customer Lockbox]" -ForegroundColor Yellow
    $lockboxConfig = Get-CustomerLockboxEnabled -ErrorAction SilentlyContinue
    
    if ($lockboxConfig) {
        Write-Host "[OK] Customer Lockbox: $lockboxConfig" -ForegroundColor Green
    }
    else {
        Write-Host "[INFO] Customer Lockbox status unavailable" -ForegroundColor Gray
    }
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "  Critical Issues: $(($results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count)" -ForegroundColor Red
    Write-Host "  High Risk: $(($results | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor Red
    Write-Host "  Medium Risk: $(($results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count)" -ForegroundColor Yellow
    Write-Host "  DLP Policies: $(($results | Where-Object { $_.Category -eq 'DLP' }).Count)" -ForegroundColor Cyan
    Write-Host "  Sensitivity Labels: $(($results | Where-Object { $_.Category -eq 'SensitivityLabels' }).Count)" -ForegroundColor Cyan
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "Purview_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "Purview_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n--- Purview Compliance Audit Complete ---" -ForegroundColor Cyan
    
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
