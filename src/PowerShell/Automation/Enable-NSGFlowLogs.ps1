<#
.SYNOPSIS
    Enable NSG Flow Logs v2 for all Network Security Groups
    
.DESCRIPTION
    This script enables NSG Flow Logs (Version 2) for all NSGs in the subscription
    and configures them to send to both a Storage Account and Log Analytics workspace.
    
    Requires: Az.Network, Az.OperationalInsights modules
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$StorageAccountId,
    
    [Parameter(Mandatory=$true)]
    [string]$LogAnalyticsWorkspaceId,
    
    [string]$NetworkWatcherRG = "NetworkWatcherRG",
    
    [string]$Location,
    
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# Connect to Azure
$connected = $false
try {
    $context = Get-AzContext
    if ($context) {
        $connected = $true
        Write-Host "Already connected to Azure" -ForegroundColor Green
    }
}
catch {
    $connected = $false
}

if (-not $connected) {
    Write-Host "Connecting to Azure..." -ForegroundColor Cyan
    try {
        Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        Write-Host "Connected using Managed Identity" -ForegroundColor Green
    }
    catch {
        Write-Host "Managed identity failed, trying interactive login..." -ForegroundColor Yellow
        Connect-AzAccount | Out-Null
    }
}

# Verify storage account and workspace exist
Write-Host "`nVerifying resources..." -ForegroundColor Cyan
try {
    $storageAccount = Get-AzStorageAccount -ResourceId $StorageAccountId -ErrorAction Stop
    Write-Host "[OK] Storage Account verified: $($storageAccount.StorageAccountName)" -ForegroundColor Green
}
catch {
    Write-Error "Storage Account not found: $StorageAccountId"
    throw
}

try {
    $workspace = Get-AzOperationalInsightsWorkspace -ResourceId $LogAnalyticsWorkspaceId -ErrorAction Stop
    Write-Host "[OK] Log Analytics Workspace verified: $($workspace.Name)" -ForegroundColor Green
}
catch {
    Write-Error "Log Analytics Workspace not found: $LogAnalyticsWorkspaceId"
    throw
}

# Get or create Network Watcher
$location = if ($Location) { $Location } else { (Get-AzContext).Subscription.HomeTenantId }
$subscriptionId = (Get-AzContext).Subscription.Id

Write-Host "`nChecking Network Watcher in region: $location" -ForegroundColor Cyan

try {
    $networkWatcher = Get-AzNetworkWatcher -Name "NetworkWatcher_$location" -ResourceGroupName $NetworkWatcherRG -ErrorAction Stop
    Write-Host "[OK] Network Watcher found: $($networkWatcher.Name)" -ForegroundColor Green
}
catch {
    Write-Host "Creating Network Watcher..." -ForegroundColor Yellow
    
    # Create resource group if it doesn't exist
    $rg = Get-AzResourceGroup -Name $NetworkWatcherRG -ErrorAction SilentlyContinue
    if (-not $rg) {
        New-AzResourceGroup -Name $NetworkWatcherRG -Location $location | Out-Null
        Write-Host "Created resource group: $NetworkWatcherRG" -ForegroundColor Green
    }
    
    $networkWatcher = New-AzNetworkWatcher `
        -Name "NetworkWatcher_$location" `
        -ResourceGroupName $NetworkWatcherRG `
        -Location $location
    
    Write-Host "[OK] Network Watcher created: $($networkWatcher.Name)" -ForegroundColor Green
}

# Get all NSGs
Write-Host "`nRetrieving Network Security Groups..." -ForegroundColor Cyan
$nsgs = Get-AzNetworkSecurityGroup

Write-Host "Found $($nsgs.Count) NSGs" -ForegroundColor Cyan

$enabledCount = 0
$skippedCount = 0
$errorCount = 0

foreach ($nsg in $nsgs) {
    $flowLogName = "FlowLog-$($nsg.Name)"
    
    Write-Host "`nProcessing NSG: $($nsg.Name) in $($nsg.ResourceGroupName)" -ForegroundColor Cyan
    
    # Check if flow log already exists
    $existingFlowLog = Get-AzNetworkWatcherFlowLog `
        -NetworkWatcher $networkWatcher `
        -Name $flowLogName `
        -ErrorAction SilentlyContinue
    
    if ($existingFlowLog -and -not $Force) {
        Write-Host "  [SKIP] Flow log already exists. Use -Force to update." -ForegroundColor Yellow
        $skippedCount++
        continue
    }
    
    try {
        $flowLogParams = @{
            NetworkWatcher = $networkWatcher
            Name = $flowLogName
            TargetResourceId = $nsg.Id
            StorageId = $StorageAccountId
            Enabled = $true
            FormatType = "JSON"
            FormatVersion = 2
        }
        
        if ($existingFlowLog) {
            # Update existing
            Set-AzNetworkWatcherFlowLog @flowLogParams -Force | Out-Null
            Write-Host "  [UPDATED] Flow log updated" -ForegroundColor Green
        }
        else {
            # Create new
            $flowLog = Set-AzNetworkWatcherFlowLog @flowLogParams
            
            # Configure Traffic Analytics
            Set-AzNetworkWatcherFlowLog `
                -NetworkWatcher $networkWatcher `
                -Name $flowLogName `
                -TargetResourceId $nsg.Id `
                -StorageId $StorageAccountId `
                -Enabled $true `
                -FormatType "JSON" `
                -FormatVersion 2 `
                -EnableTrafficAnalytics `
                -WorkspaceResourceId $LogAnalyticsWorkspaceId `
                -TrafficAnalyticsInterval 60 | Out-Null
            
            Write-Host "  [CREATED] Flow log enabled with Traffic Analytics" -ForegroundColor Green
        }
        
        $enabledCount++
    }
    catch {
        Write-Host "  [ERROR] Failed to enable flow log: $($_.Exception.Message)" -ForegroundColor Red
        $errorCount++
    }
}

Write-Host "`n--- NSG Flow Logs Summary ---" -ForegroundColor Cyan
Write-Host "  Total NSGs: $($nsgs.Count)"
Write-Host "  Enabled/Updated: $enabledCount" -ForegroundColor Green
Write-Host "  Skipped: $skippedCount" -ForegroundColor Yellow
Write-Host "  Errors: $errorCount" -ForegroundColor Red

if ($errorCount -gt 0) {
    Write-Host "`nNote: Some errors may be due to NSGs in different regions." -ForegroundColor Yellow
    Write-Host "Create Network Watchers in each region where NSGs exist." -ForegroundColor Gray
}
