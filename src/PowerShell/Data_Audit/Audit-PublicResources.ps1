# Audit Publicly Accessible Data Resources
# Checks Storage Accounts and Key Vaults for public network access (Firewall Rules).
# Goal: Ensure critical data services are restricted to VNETs or specific IPs.
# Enhanced version with error handling, exports, and logging.

[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Data",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [switch]$AutoRemediate
)

$ErrorActionPreference = "Stop"

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$transcriptPath = Join-Path $OutputPath "Audit-PublicResources_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- Auditing Data Service Public Access ---" -ForegroundColor Cyan
    
    # Connect to Azure with fallback
    $connected = $false
    try {
        $context = Get-AzContext
        if ($context) {
            $connected = $true
            Write-Host "[OK] Already connected to Azure" -ForegroundColor Green
        }
    }
    catch {
        $connected = $false
    }
    
    if (-not $connected) {
        Write-Host "[INFO] Attempting to connect with Managed Identity..." -ForegroundColor Cyan
        try {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            Write-Host "[OK] Connected using Managed Identity" -ForegroundColor Green
        }
        catch {
            Write-Host "[INFO] Managed Identity failed, attempting interactive login..." -ForegroundColor Yellow
            try {
                Connect-AzAccount -ErrorAction Stop | Out-Null
                Write-Host "[OK] Connected using interactive login" -ForegroundColor Green
            }
            catch {
                Write-Error "Failed to connect to Azure: $($_.Exception.Message)"
                throw
            }
        }
    }
    
    $results = @()
    
    Write-Host "`n[1. Key Vaults]" -ForegroundColor Yellow
    
    try {
        $kvs = Get-AzKeyVault -ErrorAction Stop
        Write-Host "Found $($kvs.Count) Key Vaults" -ForegroundColor Cyan
        
        foreach ($kv in $kvs) {
            try {
                $rules = Get-AzKeyVaultNetworkRuleSet -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName -ErrorAction Stop
                
                $isPublic = $rules.DefaultAction -eq "Allow"
                $riskLevel = if ($isPublic) { "Critical" } else { "Low" }
                
                $result = [PSCustomObject]@{
                    ResourceType = "KeyVault"
                    Name = $kv.VaultName
                    ResourceGroup = $kv.ResourceGroupName
                    Location = $kv.Location
                    DefaultAction = $rules.DefaultAction
                    IsPublic = $isPublic
                    IPRulesCount = $rules.IpAddressRanges.Count
                    VnetRulesCount = $rules.VirtualNetworkResourceIds.Count
                    RiskLevel = $riskLevel
                    Issue = if ($isPublic) { "Key Vault allows ALL public networks" } else { ""
                    }
                }
                
                $results += $result
                
                if ($isPublic) {
                    Write-Host "[CRITICAL] Key Vault '$($kv.VaultName)' allows ALL public networks." -ForegroundColor Red
                    
                    if ($AutoRemediate) {
                        Write-Host "  [AUTO-REMEDIATE] Disabling public access..." -ForegroundColor Yellow
                        try {
                            Update-AzKeyVaultNetworkRuleSet `
                                -VaultName $kv.VaultName `
                                -ResourceGroupName $kv.ResourceGroupName `
                                -DefaultAction Deny -ErrorAction Stop | Out-Null
                            Write-Host "  [FIXED] Public access disabled for $($kv.VaultName)" -ForegroundColor Green
                            $result.Issue = "Fixed - public access disabled"
                            $result.RiskLevel = "Low"
                            $result.IsPublic = $false
                        }
                        catch {
                            Write-Warning "  [FAILED] Could not disable public access: $($_.Exception.Message)"
                        }
                    }
                }
                else {
                    Write-Host "[OK] Key Vault '$($kv.VaultName)' restricts access (Default: Deny)." -ForegroundColor Green
                }
            }
            catch {
                Write-Warning "[WARNING] Could not retrieve network rules for Key Vault '$($kv.VaultName)': $($_.Exception.Message)"
                $results += [PSCustomObject]@{
                    ResourceType = "KeyVault"
                    Name = $kv.VaultName
                    ResourceGroup = $kv.ResourceGroupName
                    Location = $kv.Location
                    DefaultAction = "Unknown"
                    IsPublic = $null
                    IPRulesCount = 0
                    VnetRulesCount = 0
                    RiskLevel = "Unknown"
                    Issue = "Failed to retrieve network rules: $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-Warning "[WARNING] Could not retrieve Key Vaults: $($_.Exception.Message)"
    }
    
    Write-Host "`n[2. Storage Accounts]" -ForegroundColor Yellow
    
    try {
        $storageAccounts = Get-AzStorageAccount -ErrorAction Stop
        Write-Host "Found $($storageAccounts.Count) Storage Accounts" -ForegroundColor Cyan
        
        foreach ($sa in $storageAccounts) {
            $isPublic = $sa.NetworkRuleSet.DefaultAction -eq "Allow"
            $blobPublicAccess = $sa.AllowBlobPublicAccess
            $riskLevel = if ($isPublic -and $blobPublicAccess) { "Critical" } elseif ($isPublic -or $blobPublicAccess) { "High" } else { "Low" }
            
            $result = [PSCustomObject]@{
                ResourceType = "StorageAccount"
                Name = $sa.StorageAccountName
                ResourceGroup = $sa.ResourceGroupName
                Location = $sa.Location
                DefaultAction = $sa.NetworkRuleSet.DefaultAction
                BlobPublicAccess = $sa.AllowBlobPublicAccess
                IsPublic = $isPublic
                BlobPublicEnabled = $blobPublicAccess
                IPRulesCount = $sa.NetworkRuleSet.IpRules.Count
                VnetRulesCount = $sa.NetworkRuleSet.VirtualNetworkRules.Count
                RiskLevel = $riskLevel
                Issue = if ($isPublic) { "Storage Account allows ALL public networks" } elseif ($blobPublicAccess) { "Blob public access enabled" } else { "" }
            }
            
            $results += $result
            
            if ($isPublic) {
                Write-Host "[CRITICAL] Storage Account '$($sa.StorageAccountName)' allows ALL public networks." -ForegroundColor Red
            }
            elseif ($blobPublicAccess) {
                Write-Host "[HIGH] Storage Account '$($sa.StorageAccountName)' has blob public access enabled." -ForegroundColor Yellow
            }
            else {
                Write-Host "[OK] Storage Account '$($sa.StorageAccountName)' restricts access." -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Warning "[WARNING] Could not retrieve Storage Accounts: $($_.Exception.Message)"
    }
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    $kvPublic = ($results | Where-Object { $_.ResourceType -eq "KeyVault" -and $_.IsPublic -eq $true }).Count
    $kvTotal = ($results | Where-Object { $_.ResourceType -eq "KeyVault" }).Count
    $saPublic = ($results | Where-Object { $_.ResourceType -eq "StorageAccount" -and $_.IsPublic -eq $true }).Count
    $saTotal = ($results | Where-Object { $_.ResourceType -eq "StorageAccount" }).Count
    $critical = ($results | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $high = ($results | Where-Object { $_.RiskLevel -eq "High" }).Count
    
    Write-Host "  Key Vaults: $kvTotal total, $kvPublic public" -ForegroundColor $(if ($kvPublic -gt 0) { "Red" } else { "Green" })
    Write-Host "  Storage Accounts: $saTotal total, $saPublic public" -ForegroundColor $(if ($saPublic -gt 0) { "Red" } else { "Green" })
    Write-Host "  Critical Issues: $critical" -ForegroundColor $(if ($critical -gt 0) { "Red" } else { "Green" })
    Write-Host "  High Issues: $high" -ForegroundColor $(if ($high -gt 0) { "Yellow" } else { "Green" })
    
    # Export results
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "PublicResources_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        try {
            $results | Export-Csv -Path $csvPath -NoTypeInformation -ErrorAction Stop
            Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "[WARNING] Failed to export CSV: $($_.Exception.Message)"
        }
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "PublicResources_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        try {
            $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath -ErrorAction Stop
            Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
        }
        catch {
            Write-Warning "[WARNING] Failed to export JSON: $($_.Exception.Message)"
        }
    }
    
    Write-Host "`n--- Audit Complete ---" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    throw
}
finally {
    Stop-Transcript
}

return $results
