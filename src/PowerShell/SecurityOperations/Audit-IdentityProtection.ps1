[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/SecurityOperations",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [switch]$ShowTopFindings
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-IdentityProtection_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Identity Protection Risk Detection Audit ===" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "IdentityRiskEvent.Read.All", "IdentityRiskyUser.Read.All", "IdentityRiskyServicePrincipal.Read.All", "User.Read.All", "AuditLog.Read.All" -NoWelcome
    
    $results = @()
    
    # Check 1: Risky Users
    Write-Host "`n[Risky Users Analysis]" -ForegroundColor Yellow
    try {
        $riskyUsers = Get-MgIdentityProtectionRiskyUser -All -ErrorAction Stop
        
        $atRiskUsers = $riskyUsers | Where-Object { $_.RiskState -eq "atRisk" }
        $confirmedCompromised = $riskyUsers | Where-Object { $_.RiskState -eq "confirmedCompromised" }
        $remediatedUsers = $riskyUsers | Where-Object { $_.RiskState -eq "remediated" }
        $dismissedUsers = $riskyUsers | Where-Object { $_.RiskState -eq "dismissed" }
        
        Write-Host "  Total Risky Users: $($riskyUsers.Count)" -ForegroundColor Cyan
        Write-Host "  Currently At Risk: $($atRiskUsers.Count)" -ForegroundColor $(if ($atRiskUsers.Count -gt 0) { "Red" } else { "Green" })
        Write-Host "  Confirmed Compromised: $($confirmedCompromised.Count)" -ForegroundColor $(if ($confirmedCompromised.Count -gt 0) { "Red" } else { "Green" })
        Write-Host "  Remediated: $($remediatedUsers.Count)" -ForegroundColor Green
        Write-Host "  Dismissed: $($dismissedUsers.Count)" -ForegroundColor Gray
        
        $results += [PSCustomObject]@{
            CheckType = "RiskyUsers"
            Setting = "Users At Risk"
            Value = $atRiskUsers.Count
            RiskLevel = if ($atRiskUsers.Count -gt 5) { "High" } elseif ($atRiskUsers.Count -gt 0) { "Medium" } else { "Low" }
            Recommendation = if ($atRiskUsers.Count -gt 0) { "Investigate and remediate risky users" } else { "" }
        }
        
        if ($atRiskUsers.Count -gt 0) {
            Write-Host "`n  Top At-Risk Users:" -ForegroundColor Red
            $atRiskUsers | Select-Object -First 10 | ForEach-Object {
                $riskDetail = $_.RiskDetail
                $riskLevel = $_.RiskLevel
                Write-Host "    - $($_.UserDisplayName) (Risk: $riskLevel, Detail: $riskDetail)" -ForegroundColor Red
            }
        }
    }
    catch {
        Write-Warning "[WARNING] Could not retrieve risky users: $($_.Exception.Message)"
    }
    
    # Check 2: Risk Detections
    Write-Host "`n[Risk Detections]" -ForegroundColor Yellow
    try {
        # Get risk detections from audit logs
        $riskDetections = Get-MgAuditLogSignIn -Filter "riskLevelDuringSignIn eq 'high' or riskLevelDuringSignIn eq 'medium'" -Top 100 -ErrorAction SilentlyContinue
        
        if ($riskDetections) {
            $highRisk = $riskDetections | Where-Object { $_.RiskLevelDuringSignIn -eq "high" }
            $mediumRisk = $riskDetections | Where-Object { $_.RiskLevelDuringSignIn -eq "medium" }
            
            Write-Host "  High Risk Sign-ins (24h): $($highRisk.Count)" -ForegroundColor $(if ($highRisk.Count -gt 0) { "Red" } else { "Green" })
            Write-Host "  Medium Risk Sign-ins (24h): $($mediumRisk.Count)" -ForegroundColor $(if ($mediumRisk.Count -gt 0) { "Yellow" } else { "Green" })
            
            if ($highRisk.Count -gt 0 -and $ShowTopFindings) {
                Write-Host "`n  High Risk Sign-ins:" -ForegroundColor Red
                $highRisk | Select-Object -First 5 | ForEach-Object {
                    Write-Host "    - $($_.UserPrincipalName) from $($_.IPAddress) [$($_.RiskEventTypes)]" -ForegroundColor Red
                }
            }
        }
    }
    catch {
        Write-Warning "[WARNING] Could not retrieve risk detections"
    }
    
    # Check 3: Anonymous IP Sign-ins
    Write-Host "`n[Anonymous IP Usage]" -ForegroundColor Yellow
    try {
        $anonymousSignIns = Get-MgAuditLogSignIn -Filter "riskEventTypes/any(t: t eq 'anonymousIPAddress')" -Top 50 -ErrorAction SilentlyContinue
        
        if ($anonymousSignIns) {
            $uniqueUsers = $anonymousSignIns | Select-Object -ExpandProperty UserPrincipalName -Unique
            Write-Host "  [WARNING] Found $($anonymousSignIns.Count) sign-ins from anonymous IPs!" -ForegroundColor Red
            Write-Host "  Affected Users: $($uniqueUsers.Count)" -ForegroundColor Red
            
            $results += [PSCustomObject]@{
                CheckType = "AnonymousIPs"
                Setting = "Anonymous IP Sign-ins"
                Value = $anonymousSignIns.Count
                RiskLevel = "High"
                Recommendation = "Review and block if unauthorized; consider blocking anonymous IPs via CA"
            }
        }
        else {
            Write-Host "  [OK] No anonymous IP sign-ins detected" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [INFO] Anonymous IP check skipped" -ForegroundColor Gray
    }
    
    # Check 4: Impossible Travel
    Write-Host "`n[Impossible Travel]" -ForegroundColor Yellow
    try {
        $impossibleTravel = Get-MgAuditLogSignIn -Filter "riskEventTypes/any(t: t eq 'impossibleTravel')" -Top 50 -ErrorAction SilentlyContinue
        
        if ($impossibleTravel) {
            Write-Host "  [WARNING] Found $($impossibleTravel.Count) impossible travel events!" -ForegroundColor Red
            
            $results += [PSCustomObject]@{
                CheckType = "ImpossibleTravel"
                Setting = "Impossible Travel Events"
                Value = $impossibleTravel.Count
                RiskLevel = "High"
                Recommendation = "Investigate immediately - may indicate compromised credentials"
            }
        }
        else {
            Write-Host "  [OK] No impossible travel events detected" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [INFO] Impossible travel check skipped" -ForegroundColor Gray
    }
    
    # Check 5: Leaked Credentials
    Write-Host "`n[Leaked Credentials]" -ForegroundColor Yellow
    try {
        $leakedCreds = Get-MgAuditLogSignIn -Filter "riskEventTypes/any(t: t eq 'leakedCredentials')" -Top 50 -ErrorAction SilentlyContinue
        
        if ($leakedCreds) {
            $affectedUsers = $leakedCreds | Select-Object -ExpandProperty UserPrincipalName -Unique
            Write-Host "  [CRITICAL] Found $($leakedCreds.Count) leaked credential events!" -ForegroundColor Red
            Write-Host "  Affected Users: $($affectedUsers.Count)" -ForegroundColor Red
            
            $results += [PSCustomObject]@{
                CheckType = "LeakedCredentials"
                Setting = "Leaked Credentials Detected"
                Value = $leakedCreds.Count
                RiskLevel = "Critical"
                Recommendation = "Force password reset for affected users immediately"
            }
        }
        else {
            Write-Host "  [OK] No leaked credentials detected" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [INFO] Leaked credentials check skipped" -ForegroundColor Gray
    }
    
    # Check 6: Risky Service Principals
    Write-Host "`n[Risky Service Principals]" -ForegroundColor Yellow
    try {
        $riskySPs = Get-MgIdentityProtectionRiskyServicePrincipal -All -ErrorAction SilentlyContinue
        
        if ($riskySPs) {
            $atRiskSPs = $riskySPs | Where-Object { $_.RiskState -eq "atRisk" }
            Write-Host "  Total Risky Service Principals: $($riskySPs.Count)" -ForegroundColor Cyan
            Write-Host "  At Risk: $($atRiskSPs.Count)" -ForegroundColor $(if ($atRiskSPs.Count -gt 0) { "Red" } else { "Green" })
            
            if ($atRiskSPs.Count -gt 0) {
                $results += [PSCustomObject]@{
                    CheckType = "RiskyServicePrincipals"
                    Setting = "Service Principals At Risk"
                    Value = $atRiskSPs.Count
                    RiskLevel = "High"
                    Recommendation = "Investigate risky service principals and rotate credentials"
                }
            }
        }
    }
    catch {
        Write-Host "  [INFO] Service Principal risk check skipped" -ForegroundColor Gray
    }
    
    # Check 7: Password Spray Detection
    Write-Host "`n[Password Spray Detection]" -ForegroundColor Yellow
    try {
        $passwordSpray = Get-MgAuditLogSignIn -Filter "riskEventTypes/any(t: t eq 'passwordSpray')" -Top 50 -ErrorAction SilentlyContinue
        
        if ($passwordSpray) {
            Write-Host "  [CRITICAL] Password spray attack detected! ($($passwordSpray.Count) events)" -ForegroundColor Red
            
            $results += [PSCustomObject]@{
                CheckType = "PasswordSpray"
                Setting = "Password Spray Events"
                Value = $passwordSpray.Count
                RiskLevel = "Critical"
                Recommendation = "Implement account lockout and consider IP blocking"
            }
        }
        else {
            Write-Host "  [OK] No password spray events detected" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [INFO] Password spray check skipped" -ForegroundColor Gray
    }
    
    # Check 8: Malware Linked IP
    Write-Host "`n[Malware-Linked IP Addresses]" -ForegroundColor Yellow
    try {
        $malwareIPs = Get-MgAuditLogSignIn -Filter "riskEventTypes/any(t: t eq 'malwareLinkedIP')" -Top 50 -ErrorAction SilentlyContinue
        
        if ($malwareIPs) {
            Write-Host "  [CRITICAL] Sign-ins from malware-linked IPs detected! ($($malwareIPs.Count) events)" -ForegroundColor Red
            
            $results += [PSCustomObject]@{
                CheckType = "MalwareIPs"
                Setting = "Malware-Linked IP Sign-ins"
                Value = $malwareIPs.Count
                RiskLevel = "Critical"
                Recommendation = "Block IPs and investigate compromised devices"
            }
        }
        else {
            Write-Host "  [OK] No malware-linked IP sign-ins" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [INFO] Malware IP check skipped" -ForegroundColor Gray
    }
    
    # Summary
    Write-Host "`n=== Identity Protection Summary ===" -ForegroundColor Cyan
    $criticalCount = ($results | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $highCount = ($results | Where-Object { $_.RiskLevel -eq "High" }).Count
    
    Write-Host "Critical Findings: $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) { "Red" } else { "Green" })
    Write-Host "High Findings: $highCount" -ForegroundColor $(if ($highCount -gt 0) { "Red" } else { "Green" })
    
    if ($criticalCount -gt 0) {
        Write-Host "`n[IMMEDIATE ACTION REQUIRED]" -ForegroundColor Red
        Write-Host "Critical identity risks detected - investigate immediately!" -ForegroundColor Red
    }
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "IdentityProtection_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "IdentityProtection_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Identity Protection Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
