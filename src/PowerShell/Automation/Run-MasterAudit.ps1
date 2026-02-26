[CmdletBinding()]
param(
    [string]$OutputPath = "",
    [switch]$RunAllIdentity,
    [switch]$RunAllM365,
    [switch]$RunAllAzure,
    [switch]$RunAll,
    [switch]$GenerateReport
)

$ErrorActionPreference = "Stop"

# Resolve repo root relative to this script's location
# Script location: <repo>/src/PowerShell/Automation/Run-MasterAudit.ps1
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../../..")).Path
$OutputPath = if ($OutputPath -ne "") { $OutputPath } else { Join-Path $repoRoot "Reports" }

$startTime = Get-Date
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "       COMPREHENSIVE SECURITY AUDIT - AZ-WALL                   " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Started at: $($startTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Gray
Write-Host ""

# Create master output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$summary = @{
    StartTime        = $startTime
    ScriptsRun       = @()
    TotalFindings    = 0
    CriticalFindings = 0
    HighFindings     = 0
    MediumFindings   = 0
    LowFindings      = 0
}

function Invoke-AuditScript {
    param(
        [string]$ScriptPath,
        [string]$Category,
        [hashtable]$Params = @{}
    )
    
    $scriptName = Split-Path $ScriptPath -Leaf
    Write-Host "`n[$Category] Running: $scriptName" -ForegroundColor Yellow
    Write-Host "---------------------------------------------------" -ForegroundColor Gray
    
    try {
        $outputDir = Join-Path $OutputPath $Category
        
        $scriptParams = @{
            OutputPath = $outputDir
            ExportCSV  = $true
            ExportJSON = $true
        }
        
        # Merge additional params
        foreach ($key in $Params.Keys) {
            $scriptParams[$key] = $Params[$key]
        }
        
        # Build parameter string
        $paramString = ($scriptParams.GetEnumerator() | ForEach-Object { 
                if ($_.Value -is [switch] -and $_.Value) {
                    "-$($_.Key)"
                }
                elseif ($_.Value -isnot [switch]) {
                    "-$($_.Key) `"$($_.Value)`""
                }
            }) -join " "
        
        Write-Verbose "Parameters: $paramString"
        
        # Run the script
        $results = & $ScriptPath @scriptParams
        
        $summary.ScriptsRun += [PSCustomObject]@{
            Script     = $scriptName
            Category   = $Category
            Status     = "Success"
            OutputPath = $outputDir
        }
        
        Write-Host "[SUCCESS] $scriptName completed" -ForegroundColor Green
        return $results
    }
    catch {
        $summary.ScriptsRun += [PSCustomObject]@{
            Script   = $scriptName
            Category = $Category
            Status   = "Failed"
            Error    = $_.Exception.Message
        }
        
        Write-Host "[FAILED] $scriptName - $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# IDENTITY AUDITS
if ($RunAllIdentity -or $RunAll) {
    Write-Host "`n### RUNNING IDENTITY SECURITY AUDITS ###" -ForegroundColor Cyan
    
    $identityScripts = @(
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-CA-Logic.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-MFA-Registration.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-PIM-Config.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-AppRegistrations.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-ServicePrincipals.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-B2B-Guests.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-AccessReviews.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-PasswordPolicy.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-DeviceCompliance.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-AzureADConnect.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Audit-CA-Exclusions.ps1"; Category = "Identity" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Identity_Audit/Config-SmartLockout-BP.ps1"; Category = "Identity" }
    )
    
    foreach ($script in $identityScripts) {
        if (Test-Path $script.Path) {
            Invoke-AuditScript -ScriptPath $script.Path -Category $script.Category
        }
        else {
            Write-Warning "Script not found: $($script.Path)"
        }
    }
}

# M365 AUDITS
if ($RunAllM365 -or $RunAll) {
    Write-Host "`n### RUNNING M365 SECURITY AUDITS ###" -ForegroundColor Cyan
    
    $m365Scripts = @(
        @{ Path = Join-Path $repoRoot "src/PowerShell/M365_Audit/Audit-ExchangeOnline.ps1"; Category = "M365" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/M365_Audit/Audit-Teams.ps1"; Category = "M365" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/M365_Audit/Audit-SharePoint.ps1"; Category = "M365" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/M365_Audit/Audit-Purview.ps1"; Category = "M365" }
    )
    
    foreach ($script in $m365Scripts) {
        if (Test-Path $script.Path) {
            Invoke-AuditScript -ScriptPath $script.Path -Category $script.Category
        }
        else {
            Write-Warning "Script not found: $($script.Path)"
        }
    }
}

# AZURE INFRASTRUCTURE AUDITS
if ($RunAllAzure -or $RunAll) {
    Write-Host "`n### RUNNING AZURE INFRASTRUCTURE AUDITS ###" -ForegroundColor Cyan
    
    $azureScripts = @(
        @{ Path = Join-Path $repoRoot "src/PowerShell/Network_Audit/Audit-NetworkSecurity.ps1"; Category = "Azure" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Data_Audit/Audit-PublicResources.ps1"; Category = "Azure" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Governance/Get-SecureScore-Report.ps1"; Category = "Azure" },
        @{ Path = Join-Path $repoRoot "src/PowerShell/Azure/Audit-CognitiveServices.ps1"; Category = "Azure" }
    )
    
    foreach ($script in $azureScripts) {
        if (Test-Path $script.Path) {
            Invoke-AuditScript -ScriptPath $script.Path -Category $script.Category
        }
        else {
            Write-Warning "Script not found: $($script.Path)"
        }
    }
}

# Generate Master Report
if ($GenerateReport -or $RunAll -or $RunAllIdentity -or $RunAllM365 -or $RunAllAzure) {
    Write-Host "`n### GENERATING MASTER REPORT ###" -ForegroundColor Cyan
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    $masterReport = [PSCustomObject]@{
        AuditSummary      = @{
            StartTime         = $startTime.ToString("yyyy-MM-dd HH:mm:ss")
            EndTime           = $endTime.ToString("yyyy-MM-dd HH:mm:ss")
            Duration          = "$([math]::Round($duration.TotalMinutes, 1)) minutes"
            TotalScriptsRun   = $summary.ScriptsRun.Count
            SuccessfulScripts = ($summary.ScriptsRun | Where-Object { $_.Status -eq "Success" }).Count
            FailedScripts     = ($summary.ScriptsRun | Where-Object { $_.Status -eq "Failed" }).Count
        }
        ScriptsExecuted   = $summary.ScriptsRun
        OutputDirectories = @{
            Identity = Join-Path $OutputPath "Identity"
            M365     = Join-Path $OutputPath "M365"
            Azure    = Join-Path $OutputPath "Azure"
        }
        Recommendations   = @(
            "Review all Critical and High findings immediately"
            "Prioritize MFA enforcement gaps"
            "Address any open management ports (RDP/SSH)"
            "Review and remediate Conditional Access policy gaps"
            "Ensure break-glass accounts are properly configured"
            "Validate guest/external user access regularly"
            "Monitor for stale accounts and devices"
            "Review app registration credential expiration"
        )
    }
    
    # Save master report
    $masterReportPath = Join-Path $OutputPath "MASTER_AUDIT_REPORT.json"
    $masterReport | ConvertTo-Json -Depth 10 | Out-File $masterReportPath
    Write-Host "[EXPORT] Master report saved to: $masterReportPath" -ForegroundColor Green
    
    # Generate HTML report
    $htmlReport = @"
<!DOCTYPE html>
<html>
<head>
    <title>AZ-WALL Security Audit Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .header { background: #0078d4; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .script-list { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
        .success { color: green; }
        .failed { color: red; }
        .info { background: #e3f2fd; padding: 15px; border-left: 4px solid #2196F3; margin: 10px 0; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f5f5f5; }
        .recommendations { background: #fff3e0; padding: 20px; border-radius: 5px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>AZ-WALL Security Audit Report</h1>
        <p>Generated: $($endTime.ToString('yyyy-MM-dd HH:mm:ss'))</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p><strong>Audit Duration:</strong> $([math]::Round($duration.TotalMinutes, 1)) minutes</p>
        <p><strong>Scripts Executed:</strong> $($masterReport.AuditSummary.TotalScriptsRun)</p>
        <p><strong>Successful:</strong> <span class="success">$($masterReport.AuditSummary.SuccessfulScripts)</span></p>
        <p><strong>Failed:</strong> <span class="failed">$($masterReport.AuditSummary.FailedScripts)</span></p>
    </div>
    
    <div class="script-list">
        <h2>Executed Scripts</h2>
        <table>
            <tr>
                <th>Script</th>
                <th>Category</th>
                <th>Status</th>
            </tr>
"@
    
    foreach ($script in $summary.ScriptsRun) {
        $statusClass = if ($script.Status -eq "Success") { "success" } else { "failed" }
        $htmlReport += @"
            <tr>
                <td>$($script.Script)</td>
                <td>$($script.Category)</td>
                <td class="$statusClass">$($script.Status)</td>
            </tr>
"@
    }
    
    $htmlReport += @"
        </table>
    </div>
    
    <div class="recommendations">
        <h2>Key Recommendations</h2>
        <ul>
"@
    
    foreach ($rec in $masterReport.Recommendations) {
        $htmlReport += "            <li>$rec</li>`n"
    }
    
    $htmlReport += @"
        </ul>
    </div>
    
    <div class="info">
        <p><strong>Note:</strong> Detailed findings are available in individual script output files (CSV/JSON) in the output directories.</p>
    </div>
</body>
</html>
"@
    
    $htmlPath = Join-Path $OutputPath "MASTER_AUDIT_REPORT.html"
    $htmlReport | Out-File $htmlPath
    Write-Host "[EXPORT] HTML report saved to: $htmlPath" -ForegroundColor Green
}

# Final Summary
Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "                    AUDIT COMPLETE                              " -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Total Scripts Run: $($summary.ScriptsRun.Count)" -ForegroundColor White
Write-Host "Successful: $(($summary.ScriptsRun | Where-Object { $_.Status -eq 'Success' }).Count)" -ForegroundColor Green
Write-Host "Failed: $(($summary.ScriptsRun | Where-Object { $_.Status -eq 'Failed' }).Count)" -ForegroundColor Red
Write-Host "Duration: $([math]::Round($duration.TotalMinutes, 1)) minutes" -ForegroundColor White
Write-Host "Output Directory: $OutputPath" -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan
