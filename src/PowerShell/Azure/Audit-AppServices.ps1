[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-AppServices_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== App Services Security Audit ===" -ForegroundColor Cyan
    
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
    
    Write-Host "`n[App Services Inventory]" -ForegroundColor Yellow
    $webApps = Get-AzWebApp
    Write-Host "  Web Apps Found: $($webApps.Count)" -ForegroundColor Cyan
    
    foreach ($app in $webApps) {
        Write-Host "`n  App: $($app.Name)" -ForegroundColor Cyan
        
        $httpsOnly = $app.HttpsOnly
        Write-Host "    HTTPS Only: $(if ($httpsOnly) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($httpsOnly) { 'Green' } else { 'Red' })
        
        $minTls = $app.SiteConfig.MinTlsVersion
        $tlsOk = ($minTls -eq '1.2' -or $minTls -eq '1.3')
        Write-Host "    Min TLS Version: $minTls" -ForegroundColor $(if ($tlsOk) { 'Green' } else { 'Red' })
        
        $ftpsState = $app.SiteConfig.FtpsState
        $ftpsOk = ($ftpsState -eq 'FtpsOnly' -or $ftpsState -eq 'Disabled')
        Write-Host "    FTPS State: $ftpsState" -ForegroundColor $(if ($ftpsOk) { 'Green' } else { 'Yellow' })
        
        $vnetIntegration = $app.VirtualNetworkSubnetId
        Write-Host "    VNet Integration: $(if ($vnetIntegration) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($vnetIntegration) { 'Green' } else { 'Yellow' })
        
        $issues = @()
        if (-not $httpsOnly) { $issues += "HTTPS Only is disabled" }
        if (-not $tlsOk) { $issues += "Min TLS version is less than 1.2" }
        if (-not $ftpsOk) { $issues += "FTP is enabled (should be FTPS only or Disabled)" }
        
        $results += [PSCustomObject]@{
            CheckType       = "AppServiceConfig"
            AppName         = $app.Name
            ResourceGroup   = $app.ResourceGroup
            Location        = $app.Location
            HttpsOnly       = $httpsOnly
            MinTlsVersion   = $minTls
            FtpsState       = $ftpsState
            VNetIntegration = [bool]$vnetIntegration
            RiskLevel       = if (-not $httpsOnly -or -not $tlsOk) { 'High' } elseif (-not $ftpsOk) { 'Medium' } else { 'Low' }
            Issues          = $issues -join "; "
        }
    }
    
    # Summary
    Write-Host "`n=== App Services Security Summary ===" -ForegroundColor Cyan
    $highRiskApps = ($results | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumRiskApps = ($results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    
    Write-Host "Total App Services: $($webApps.Count)" -ForegroundColor Cyan
    Write-Host "High Risk (HTTPS/TLS): $highRiskApps" -ForegroundColor $(if ($highRiskApps -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Risk (FTP): $mediumRiskApps" -ForegroundColor $(if ($mediumRiskApps -gt 0) { "Yellow" } else { "Green" })
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Enforce HTTPS only on all App Services." -ForegroundColor Gray
    Write-Host "  2. Upgrade minimum TLS version to 1.2 or 1.3." -ForegroundColor Gray
    Write-Host "  3. Disable FTP deployments, require FTPS." -ForegroundColor Gray
    Write-Host "  4. Consider VNet integration to secure outbound traffic." -ForegroundColor Gray
    
    # Export
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "AppServices-Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "AppServices-Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== App Services Audit Complete ===" -ForegroundColor Cyan
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
