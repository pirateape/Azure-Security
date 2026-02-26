[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/EntraID",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-RiskyUsers_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Entra ID Risky Users Audit ===" -ForegroundColor Cyan
    Write-Host "Note: This requires the Microsoft.Graph module and appropriate API permissions (e.g., IdentityRiskyUser.Read.All)" -ForegroundColor Yellow
    
    # Check if Microsoft.Graph is installed/imported
    if (-not (Get-Module -Name Microsoft.Graph.Identity.SignIns -ListAvailable)) {
        Write-Host "The Microsoft.Graph module is not installed. Please run: Install-Module Microsoft.Graph" -ForegroundColor Red
        return
    }

    # Connect to Graph (Uses current session or prompts)
    try {
        Connect-MgGraph -Scopes "IdentityRiskyUser.Read.All", "User.Read.All" -ErrorAction Stop | Out-Null
        Write-Host "[OK] Connected to Microsoft Graph" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERROR] Failed to connect to Microsoft Graph. Exception: $_" -ForegroundColor Red
        throw
    }
    
    $results = @()
    
    Write-Host "`n[Fetching Risky Users]" -ForegroundColor Yellow
    # Fetch active risky users (RiskState == 'atRisk')
    $riskyUsers = Get-MgRiskyUser -Filter "riskState eq 'atRisk'" -All
    
    if (-not $riskyUsers) {
        Write-Host "  No users currently marked at risk." -ForegroundColor Green
    }
    else {
        Write-Host "  At-Risk Users Found: $($riskyUsers.Count)" -ForegroundColor Red
        
        foreach ($user in $riskyUsers) {
            Write-Host "`n  User UPN: $($user.UserPrincipalName)" -ForegroundColor Cyan
            Write-Host "    Risk Level: $($user.RiskLevel)" -ForegroundColor $(if ($user.RiskLevel -eq 'high') { 'Red' } else { 'Yellow' })
            Write-Host "    Risk Detail: $($user.RiskDetail)" -ForegroundColor Gray
            Write-Host "    Risk Last Updated: $($user.RiskLastUpdatedDateTime)" -ForegroundColor Gray
            
            $results += [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                RiskLevel         = $user.RiskLevel
                RiskState         = $user.RiskState
                RiskDetail        = $user.RiskDetail
                RiskLastUpdated   = $user.RiskLastUpdatedDateTime
            }
        }
    }
    
    # Summary
    Write-Host "`n=== Entra ID Risky Users Summary ===" -ForegroundColor Cyan
    $highRiskCount = ($results | Where-Object { $_.RiskLevel -eq "high" }).Count
    $mediumRiskCount = ($results | Where-Object { $_.RiskLevel -eq "medium" -or $_.RiskLevel -eq "low" }).Count
    
    Write-Host "Total Risky Users: $(if ($results) { $results.Count } else { 0 })" -ForegroundColor $(if ($results.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "High Risk: $highRiskCount" -ForegroundColor $(if ($highRiskCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium/Low Risk: $mediumRiskCount" -ForegroundColor $(if ($mediumRiskCount -gt 0) { "Yellow" } else { "Green" })
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Investigate high-risk users immediately via the Azure Portal (Security -> Risky users)." -ForegroundColor Gray
    Write-Host "  2. Ensure Conditional Access policies enforce MFA or password resets for high-risk sign-ins." -ForegroundColor Gray
    Write-Host "  3. Dismiss risk events manually if deemed a false positive." -ForegroundColor Gray
    Write-Host "  4. Consider configuring Identity Protection to block or require secure password changes for High risk." -ForegroundColor Gray
    
    # Export
    if ($results.Count -gt 0) {
        if ($ExportCSV) {
            $csvPath = Join-Path $OutputPath "RiskyUsers-Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $results | Export-Csv -Path $csvPath -NoTypeInformation
            Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
        }
        
        if ($ExportJSON) {
            $jsonPath = Join-Path $OutputPath "RiskyUsers-Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
            Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
        }
    }
    
    Write-Host "`n=== Auditing Complete ===" -ForegroundColor Cyan
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
