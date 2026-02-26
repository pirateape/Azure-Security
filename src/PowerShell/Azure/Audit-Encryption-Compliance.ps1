[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-Encryption-Compliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Azure Encryption at Rest & in Transit Audit ===" -ForegroundColor Cyan
    
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
    
    Write-Host "`n[Storage Account Encryption]" -ForegroundColor Yellow
    $storageAccounts = Get-AzStorageAccount
    
    foreach ($sa in $storageAccounts) {
        $issues = @()
        
        # Check HTTPS only
        if (-not $sa.EnableHttpsTrafficOnly) {
            $issues += "HTTPS not enforced"
        }
        
        # Check TLS version
        if ($sa.MinimumTlsVersion -lt 'TLS1_2') {
            $issues += "TLS version below 1.2 ($($sa.MinimumTlsVersion))"
        }
        
        # Check encryption (should be Microsoft.Storage by default)
        $encryption = $sa.Encryption
        $encryptionType = $encryption.KeySource
        
        if ($encryptionType -eq 'Microsoft.Storage') {
            # Platform-managed key - OK but not best
        }
        elseif ($encryptionType -eq 'Microsoft.Keyvault') {
            # Customer-managed key - Best practice
        }
        
        $result = [PSCustomObject]@{
            ResourceType = "StorageAccount"
            ResourceName = $sa.StorageAccountName
            ResourceGroup = $sa.ResourceGroupName
            HttpsOnly = $sa.EnableHttpsTrafficOnly
            MinTLS = $sa.MinimumTlsVersion
            EncryptionType = $encryptionType
            InfrastructureEncryption = $encryption.RequireInfrastructureEncryption
            RiskLevel = if (-not $sa.EnableHttpsTrafficOnly -or $sa.MinimumTlsVersion -lt 'TLS1_2') { 'High' } elseif ($encryptionType -eq 'Microsoft.Storage') { 'Medium' } else { 'Low' }
            Issues = $issues -join "; "
        }
        
        $results += $result
        
        if ($issues.Count -gt 0) {
            Write-Host "  [WARNING] $($sa.StorageAccountName): $($issues -join ', ')" -ForegroundColor $(if ($result.RiskLevel -eq 'High') { 'Red' } else { 'Yellow' })
        }
    }
    
    $httpsOnlyCount = ($results | Where-Object { $_.ResourceType -eq 'StorageAccount' -and $_.HttpsOnly -eq $true }).Count
    $tls12Count = ($results | Where-Object { $_.ResourceType -eq 'StorageAccount' -and $_.MinTLS -ge 'TLS1_2' }).Count
    Write-Host "  Storage Accounts with HTTPS Only: $httpsOnlyCount/$($storageAccounts.Count)" -ForegroundColor $(if ($httpsOnlyCount -eq $storageAccounts.Count) { 'Green' } else { 'Yellow' })
    Write-Host "  Storage Accounts with TLS 1.2+: $tls12Count/$($storageAccounts.Count)" -ForegroundColor $(if ($tls12Count -eq $storageAccounts.Count) { 'Green' } else { 'Yellow' })
    
    # Check SQL Database TDE
    Write-Host "`n[SQL Database TDE Status]" -ForegroundColor Yellow
    $sqlServers = Get-AzSqlServer
    
    foreach ($server in $sqlServers) {
        $databases = Get-AzSqlDatabase -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName | Where-Object { $_.DatabaseName -ne 'master' }
        
        foreach ($db in $databases) {
            $tde = Get-AzSqlDatabaseTransparentDataEncryption -ServerName $server.ServerName -DatabaseName $db.DatabaseName -ResourceGroupName $server.ResourceGroupName
            
            $results += [PSCustomObject]@{
                ResourceType = "SQLDatabase"
                ResourceName = "$($server.ServerName)/$($db.DatabaseName)"
                ResourceGroup = $server.ResourceGroupName
                TDEState = $tde.State
                EncryptionType = "Transparent Data Encryption"
                RiskLevel = if ($tde.State -ne 'Enabled') { 'Critical' } else { 'Low' }
                Issues = if ($tde.State -ne 'Enabled') { "TDE not enabled" } else { "" }
            }
            
            if ($tde.State -ne 'Enabled') {
                Write-Host "  [CRITICAL] TDE disabled on: $($server.ServerName)/$($db.DatabaseName)" -ForegroundColor Red
            }
        }
    }
    
    # Check VM Disk Encryption
    Write-Host "`n[VM Disk Encryption]" -ForegroundColor Yellow
    $vms = Get-AzVM | Select-Object -First 20
    
    foreach ($vm in $vms) {
        $encryptionStatus = Get-AzVMDiskEncryptionStatus -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction SilentlyContinue
        
        if ($encryptionStatus) {
            $osEncrypted = $encryptionStatus.OsVolumeEncrypted -eq 'Encrypted'
            $dataEncrypted = $encryptionStatus.DataVolumesEncrypted -eq 'Encrypted'
            
            $results += [PSCustomObject]@{
                ResourceType = "VirtualMachine"
                ResourceName = $vm.Name
                ResourceGroup = $vm.ResourceGroupName
                OSEncrypted = $osEncrypted
                DataEncrypted = $dataEncrypted
                EncryptionType = "Azure Disk Encryption"
                RiskLevel = if (-not $osEncrypted) { 'High' } elseif (-not $dataEncrypted) { 'Medium' } else { 'Low' }
                Issues = if (-not $osEncrypted) { "OS disk not encrypted" } elseif (-not $dataEncrypted) { "Data disks not encrypted" } else { "" }
            }
            
            if (-not $osEncrypted) {
                Write-Host "  [WARNING] VM '$($vm.Name)' - OS disk NOT encrypted" -ForegroundColor Red
            }
        }
        else {
            Write-Host "  [INFO] VM '$($vm.Name)' - Encryption status unavailable" -ForegroundColor Gray
        }
    }
    
    # Check App Service HTTPS and TLS
    Write-Host "`n[App Service Encryption]" -ForegroundColor Yellow
    $webApps = Get-AzWebApp | Select-Object -First 20
    
    foreach ($app in $webApps) {
        $config = Get-AzWebApp -Name $app.Name -ResourceGroupName $app.ResourceGroupName
        
        $httpsOnly = $config.HttpsOnly
        $minTlsVersion = $config.SiteConfig.MinTlsVersion
        
        $issues = @()
        if (-not $httpsOnly) { $issues += "HTTPS not enforced" }
        if ($minTlsVersion -lt '1.2') { $issues += "TLS version below 1.2" }
        
        $results += [PSCustomObject]@{
            ResourceType = "WebApp"
            ResourceName = $app.Name
            ResourceGroup = $app.ResourceGroupName
            HttpsOnly = $httpsOnly
            MinTLS = $minTlsVersion
            EncryptionType = "TLS in Transit"
            RiskLevel = if (-not $httpsOnly) { 'High' } elseif ($minTlsVersion -lt '1.2') { 'Medium' } else { 'Low' }
            Issues = $issues -join "; "
        }
        
        if ($issues.Count -gt 0) {
            Write-Host "  [WARNING] App '$($app.Name)': $($issues -join ', ')" -ForegroundColor $(if (-not $httpsOnly) { 'Red' } else { 'Yellow' })
        }
    }
    
    # Check Cosmos DB Encryption
    Write-Host "`n[Cosmos DB Encryption]" -ForegroundColor Yellow
    $cosmosAccounts = Get-AzCosmosDBAccount | Select-Object -First 10
    
    foreach ($account in $cosmosAccounts) {
        # Cosmos DB is always encrypted at rest with Microsoft-managed keys by default
        # Check for customer-managed keys
        $hasCMK = ($null -ne $account.KeyVaultKeyUri)
        
        $results += [PSCustomObject]@{
            ResourceType = "CosmosDB"
            ResourceName = $account.Name
            ResourceGroup = $account.ResourceGroupName
            EncryptionAtRest = $true  # Always enabled
            CustomerManagedKey = $hasCMK
            EncryptionType = if ($hasCMK) { "Customer-Managed Key" } else { "Microsoft-Managed Key" }
            RiskLevel = 'Low'  # Encryption always enabled
            Issues = ""
        }
        
        Write-Host "  $($account.Name): $(if ($hasCMK) { 'Customer-managed key' } else { 'Microsoft-managed key' })" -ForegroundColor $(if ($hasCMK) { 'Green' } else { 'Gray' })
    }
    
    # Check Redis Cache Encryption
    Write-Host "`n[Redis Cache Encryption]" -ForegroundColor Yellow
    $redisCaches = Get-AzRedisCache | Select-Object -First 10
    
    foreach ($redis in $redisCaches) {
        $sslEnabled = $redis.EnableNonSslPort -eq $false
        $minTls = $redis.MinimumTlsVersion
        
        $results += [PSCustomObject]@{
            ResourceType = "RedisCache"
            ResourceName = $redis.Name
            ResourceGroup = $redis.ResourceGroupName
            SSLOnly = $sslEnabled
            MinTLS = $minTls
            EncryptionType = "TLS in Transit"
            RiskLevel = if (-not $sslEnabled) { 'High' } else { 'Low' }
            Issues = if (-not $sslEnabled) { "Non-SSL port enabled" } else { "" }
        }
        
        if (-not $sslEnabled) {
            Write-Host "  [WARNING] Redis '$($redis.Name)' - Non-SSL port enabled!" -ForegroundColor Red
        }
    }
    
    # Check for resources without encryption (potential gaps)
    Write-Host "`n[Resources Without Encryption Verification]" -ForegroundColor Yellow
    Write-Host "  Note: Some resources may not support native encryption verification via PowerShell" -ForegroundColor Gray
    
    # Summary
    Write-Host "`n=== Encryption Compliance Summary ===" -ForegroundColor Cyan
    $critical = ($results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count
    $high = ($results | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $medium = ($results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    
    Write-Host "Critical Issues: $critical" -ForegroundColor $(if ($critical -gt 0) { "Red" } else { "Green" })
    Write-Host "High Issues: $high" -ForegroundColor $(if ($high -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Issues: $medium" -ForegroundColor $(if ($medium -gt 0) { "Yellow" } else { "Green" })
    
    # Statistics by resource type
    Write-Host "`n[Encryption Statistics]" -ForegroundColor Yellow
    $storageIssues = ($results | Where-Object { $_.ResourceType -eq 'StorageAccount' -and $_.RiskLevel -in @('High', 'Medium') }).Count
    $sqlIssues = ($results | Where-Object { $_.ResourceType -eq 'SQLDatabase' -and $_.RiskLevel -eq 'Critical' }).Count
    $vmIssues = ($results | Where-Object { $_.ResourceType -eq 'VirtualMachine' -and $_.RiskLevel -eq 'High' }).Count
    $appIssues = ($results | Where-Object { $_.ResourceType -eq 'WebApp' -and $_.RiskLevel -eq 'High' }).Count
    
    Write-Host "  Storage Accounts with Issues: $storageIssues" -ForegroundColor $(if ($storageIssues -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  SQL Databases without TDE: $sqlIssues" -ForegroundColor $(if ($sqlIssues -gt 0) { "Red" } else { "Green" })
    Write-Host "  VMs without Disk Encryption: $vmIssues" -ForegroundColor $(if ($vmIssues -gt 0) { "Red" } else { "Green" })
    Write-Host "  Web Apps without HTTPS: $appIssues" -ForegroundColor $(if ($appIssues -gt 0) { "Red" } else { "Green" })
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Enable HTTPS-only on all storage accounts" -ForegroundColor Gray
    Write-Host "  2. Enforce TLS 1.2+ on all services" -ForegroundColor Gray
    Write-Host "  3. Enable TDE on all SQL databases" -ForegroundColor Gray
    Write-Host "  4. Implement Azure Disk Encryption on all VMs" -ForegroundColor Gray
    Write-Host "  5. Enforce HTTPS-only on all web apps" -ForegroundColor Gray
    Write-Host "  6. Use customer-managed keys (CMK) for sensitive data" -ForegroundColor Gray
    Write-Host "  7. Enable SSL-only on Redis caches" -ForegroundColor Gray
    Write-Host "  8. Enable infrastructure encryption where available" -ForegroundColor Gray
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "Encryption-Compliance_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "Encryption-Compliance_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Encryption Compliance Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
