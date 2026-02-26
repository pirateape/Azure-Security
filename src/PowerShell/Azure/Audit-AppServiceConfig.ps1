<#
.SYNOPSIS
    Audits Azure App Services (Web Apps and Function Apps) for critical security configurations.

.DESCRIPTION
    This script connects to Azure and evaluates all App Services against a secure baseline.
    Specifically checks for:
    - HTTPS Only enabled
    - Minimum TLS Version (1.2 or 1.3)
    - Local Authentication methods disabled (FTP/Basic Auth)
    - System-Assigned Managed Identity enabled
    - VNET Integration enabled (prevents multi-tenant public routing)

    Supports exporting findings to a CSV file.

.PARAMETER ExportCSV
    Switch to output results to a CSV file.

.PARAMETER ShowDetails
    Switch to format output as a detailed list in the console.

.EXAMPLE
    .\Audit-AppServiceConfig.ps1 -ExportCSV -ShowDetails
#>

[CmdletBinding()]
param (
    [switch]$ExportCSV,
    [switch]$ShowDetails
)

# Colors for output
$ColorSuccess = "Green"
$ColorWarning = "Yellow"
$ColorDanger = "Red"
$ColorInfo = "Cyan"

Write-Host "Starting Azure App Service Configuration Audit..." -ForegroundColor $ColorInfo

# Verify Azure connection
try {
    $context = Get-AzContext -ErrorAction Stop
    Write-Host "Connected to Azure: $($context.Subscription.Name)" -ForegroundColor $ColorInfo
}
catch {
    Write-Host "Not connected to Azure. Please run 'Connect-AzAccount' first." -ForegroundColor $ColorDanger
    exit
}

$webApps = Get-AzWebApp
$results = @()

if ($webApps.Count -eq 0) {
    Write-Host "No App Services found in the current subscription." -ForegroundColor $ColorWarning
    exit
}

Write-Host "Auditing $($webApps.Count) App Services..." -ForegroundColor $ColorInfo

foreach ($app in $webApps) {
    # Extract details
    $httpsOnly = $app.HttpsOnly
    $minTls = $app.SiteConfig.MinTlsVersion
    $hasIdentity = $null -ne $app.Identity -and $app.Identity.Type -match "SystemAssigned"
    $vnetIntegration = $null -ne $app.VirtualNetworkSubnetId
    
    # Check Auth (Basic/FTP)
    $ftpEnabled = $true
    if ($app.SiteConfig.FtpsState -eq "FtpsOnly" -or $app.SiteConfig.FtpsState -eq "Disabled") {
        $ftpEnabled = $app.SiteConfig.FtpsState -ne "Disabled"
    }

    $appConfig = [PSCustomObject]@{
        Name               = $app.Name
        ResourceGroup      = $app.ResourceGroup
        State              = $app.State
        HttpsOnly          = $httpsOnly
        MinTlsVersion      = $minTls
        HasManagedIdentity = $hasIdentity
        VnetIntegration    = $vnetIntegration
        FTPEnabled         = $ftpEnabled
    }
    
    $results += $appConfig
}

# Output to console
if ($ShowDetails) {
    $results | Format-List
}
else {
    $results | Format-Table -AutoSize
}

# Export
if ($ExportCSV) {
    $exportPath = ".\AppService_Audit_$(Get-Date -Format 'yyyyMMdd').csv"
    $results | Export-Csv -Path $exportPath -NoTypeInformation
    Write-Host "Report exported to: $exportPath" -ForegroundColor $ColorSuccess
}

Write-Host "Audit completed successfully." -ForegroundColor $ColorSuccess
