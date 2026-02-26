[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/SecurityOperations",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [switch]$CheckConfigurationOnly
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-DefenderStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Microsoft Defender XDR Status Audit ===" -ForegroundColor Cyan
    
    # Connect to Azure
    $connected = $false
    try {
        $context = Get-AzContext
        if ($context) { $connected = $true }
    }
    catch { $connected = $false }
    
    if (-not $connected) {
        try {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            Write-Host "[OK] Connected using Managed Identity" -ForegroundColor Green
        }
        catch {
            Connect-AzAccount | Out-Null
            Write-Host "[OK] Connected using interactive login" -ForegroundColor Green
        }
    }
    
    $results = @()
    $subscriptionId = (Get-AzContext).Subscription.Id
    
    Write-Host "`n[Defender for Cloud Status]" -ForegroundColor Yellow
    
    # Check Defender for Cloud pricing tier
    try {
        $defenderSettings = Get-AzSecurityPricing -ErrorAction Stop
        
        foreach ($setting in $defenderSettings) {
            $isEnabled = $setting.PricingTier -eq "Standard"
            $resourceType = $setting.Name
            
            $result = [PSCustomObject]@{
                CheckType = "DefenderForCloud"
                ResourceType = $resourceType
                PricingTier = $setting.PricingTier
                Enabled = $isEnabled
                FreeTrialRemaining = $setting.FreeTrialRemainingTime
                RiskLevel = if (-not $isEnabled) { "High" } else { "Low" }
                Recommendation = if (-not $isEnabled) { "Enable Defender for $resourceType" } else { "" }
            }
            
            $results += $result
            
            if ($isEnabled) {
                Write-Host "  [OK] Defender for $resourceType : ENABLED" -ForegroundColor Green
            }
            else {
                Write-Host "  [WARNING] Defender for $resourceType : $($setting.PricingTier)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Warning "[WARNING] Could not retrieve Defender for Cloud settings: $($_.Exception.Message)"
    }
    
    # Check security contacts
    Write-Host "`n[Security Contacts]" -ForegroundColor Yellow
    try {
        $securityContacts = Get-AzSecurityContact -ErrorAction Stop
        
        if ($securityContacts.Count -eq 0) {
            Write-Host "  [CRITICAL] No security contacts configured!" -ForegroundColor Red
            $results += [PSCustomObject]@{
                CheckType = "SecurityContacts"
                Setting = "Contacts"
                Value = "None"
                RiskLevel = "Critical"
                Recommendation = "Configure at least one security contact for alerts"
            }
        }
        else {
            Write-Host "  [OK] $($securityContacts.Count) security contact(s) configured" -ForegroundColor Green
            foreach ($contact in $securityContacts) {
                Write-Host "    - $($contact.Email) (Alerts: $($contact.AlertNotifications))" -ForegroundColor Gray
            }
        }
    }
    catch {
        Write-Warning "[WARNING] Could not retrieve security contacts: $($_.Exception.Message)"
    }
    
    # Check auto-provisioning
    Write-Host "`n[Auto-Provisioning Status]" -ForegroundColor Yellow
    try {
        $autoProvisioning = Get-AzSecurityAutoProvisioningSetting -ErrorAction Stop
        
        if ($autoProvisioning.AutoProvision -eq "On") {
            Write-Host "  [OK] Auto-provisioning is enabled" -ForegroundColor Green
        }
        else {
            Write-Host "  [WARNING] Auto-provisioning is $($autoProvisioning.AutoProvision)" -ForegroundColor Yellow
            $results += [PSCustomObject]@{
                CheckType = "AutoProvisioning"
                Setting = "Auto-Provision"
                Value = $autoProvisioning.AutoProvision
                RiskLevel = "Medium"
                Recommendation = "Enable auto-provisioning for continuous monitoring"
            }
        }
    }
    catch {
        Write-Warning "[WARNING] Could not retrieve auto-provisioning settings"
    }
    
    # Check Secure Score
    Write-Host "`n[Secure Score]" -ForegroundColor Yellow
    try {
        $secureScores = Get-AzSecureScore -ErrorAction Stop | Select-Object -First 1
        
        if ($secureScores) {
            $percentage = [math]::Round(($secureScores.CurrentScore / $secureScores.MaxScore) * 100, 1)
            Write-Host "  Current Secure Score: $($secureScores.CurrentScore) / $($secureScores.MaxScore) ($percentage%)" -ForegroundColor $(if ($percentage -ge 70) { "Green" } elseif ($percentage -ge 50) { "Yellow" } else { "Red" })
            
            $results += [PSCustomObject]@{
                CheckType = "SecureScore"
                Setting = "Current Score"
                Value = "$percentage%"
                RiskLevel = if ($percentage -lt 50) { "High" } elseif ($percentage -lt 70) { "Medium" } else { "Low" }
                Recommendation = if ($percentage -lt 70) { "Review Secure Score recommendations" } else { "" }
            }
        }
    }
    catch {
        Write-Warning "[WARNING] Could not retrieve Secure Score"
    }
    
    # Check security recommendations
    Write-Host "`n[Security Recommendations Summary]" -ForegroundColor Yellow
    try {
        $recommendations = Get-AzSecurityRecommendation -ErrorAction Stop
        
        $criticalRecs = $recommendations | Where-Object { $_.Severity -eq "High" -or $_.Severity -eq "Critical" }
        $mediumRecs = $recommendations | Where-Object { $_.Severity -eq "Medium" }
        $lowRecs = $recommendations | Where-Object { $_.Severity -eq "Low" }
        
        Write-Host "  Critical/High: $($criticalRecs.Count)" -ForegroundColor $(if ($criticalRecs.Count -gt 0) { "Red" } else { "Green" })
        Write-Host "  Medium: $($mediumRecs.Count)" -ForegroundColor Yellow
        Write-Host "  Low: $($lowRecs.Count)" -ForegroundColor Gray
        
        if ($criticalRecs.Count -gt 0 -and -not $CheckConfigurationOnly) {
            Write-Host "`n  Top 10 Critical Recommendations:" -ForegroundColor Red
            $criticalRecs | Select-Object -First 10 | ForEach-Object {
                Write-Host "    - [$($_.Severity)] $($_.DisplayName)" -ForegroundColor Red
            }
        }
        
        $results += [PSCustomObject]@{
            CheckType = "Recommendations"
            Setting = "Open Recommendations"
            Value = "$($recommendations.Count) total (Critical: $($criticalRecs.Count))"
            RiskLevel = if ($criticalRecs.Count -gt 10) { "High" } elseif ($criticalRecs.Count -gt 0) { "Medium" } else { "Low" }
            Recommendation = "Remediate Critical and High recommendations"
        }
    }
    catch {
        Write-Warning "[WARNING] Could not retrieve recommendations"
    }
    
    # Check for active alerts
    Write-Host "`n[Active Security Alerts]" -ForegroundColor Yellow
    try {
        $alerts = Get-AzSecurityAlert -ErrorAction Stop
        $activeAlerts = $alerts | Where-Object { $_.State -eq "Active" }
        
        Write-Host "  Total Alerts: $($alerts.Count)" -ForegroundColor Cyan
        Write-Host "  Active Alerts: $($activeAlerts.Count)" -ForegroundColor $(if ($activeAlerts.Count -gt 0) { "Red" } else { "Green" })
        
        if ($activeAlerts.Count -gt 0) {
            $highSeverity = $activeAlerts | Where-Object { $_.Severity -in @("High", "Critical") }
            Write-Host "  High/Critical Active: $($highSeverity.Count)" -ForegroundColor Red
            
            if (-not $CheckConfigurationOnly) {
                Write-Host "`n  Active High/Critical Alerts:" -ForegroundColor Red
                $highSeverity | Select-Object -First 10 | ForEach-Object {
                    Write-Host "    - [$($_.Severity)] $($_.AlertDisplayName)" -ForegroundColor Red
                }
            }
        }
    }
    catch {
        Write-Warning "[WARNING] Could not retrieve security alerts"
    }
    
    # Check JIT access status
    Write-Host "`n[Just-In-Time (JIT) Access]" -ForegroundColor Yellow
    try {
        $jitPolicies = Get-AzJitNetworkAccessPolicy -ErrorAction SilentlyContinue
        
        if ($jitPolicies) {
            Write-Host "  [OK] JIT policies configured: $($jitPolicies.Count)" -ForegroundColor Green
        }
        else {
            Write-Host "  [INFO] No JIT policies configured" -ForegroundColor Gray
            $results += [PSCustomObject]@{
                CheckType = "JITAccess"
                Setting = "JIT Policies"
                Value = "None"
                RiskLevel = "Medium"
                Recommendation = "Configure JIT access for VMs with management ports"
            }
        }
    }
    catch {
        Write-Host "  [INFO] JIT access check skipped" -ForegroundColor Gray
    }
    
    # Summary
    Write-Host "`n=== Defender Status Summary ===" -ForegroundColor Cyan
    $enabledDefenders = ($results | Where-Object { $_.CheckType -eq "DefenderForCloud" -and $_.Enabled -eq $true }).Count
    $totalDefenders = ($results | Where-Object { $_.CheckType -eq "DefenderForCloud" }).Count
    Write-Host "Defender Plans Enabled: $enabledDefenders / $totalDefenders" -ForegroundColor Cyan
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "DefenderStatus_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "DefenderStatus_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Defender Status Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
