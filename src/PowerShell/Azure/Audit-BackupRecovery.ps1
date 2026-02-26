[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-BackupRecovery_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Backup & Disaster Recovery Security Audit ===" -ForegroundColor Cyan
    
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
    
    Write-Host "`n[Recovery Services Vaults]" -ForegroundColor Yellow
    
    $vaults = Get-AzRecoveryServicesVault
    Write-Host "  Recovery Services Vaults: $($vaults.Count)" -ForegroundColor Cyan
    
    foreach ($vault in $vaults) {
        Write-Host "`n  Vault: $($vault.Name)" -ForegroundColor Cyan
        
        # Set vault context
        Set-AzRecoveryServicesVaultContext -Vault $vault
        
        # Check soft delete status
        $softDelete = Get-AzRecoveryServicesVaultProperty -Vault $vault | Select-Object -ExpandProperty SoftDeleteFeatureState
        Write-Host "    Soft Delete: $softDelete" -ForegroundColor $(if ($softDelete -eq "Enabled") { "Green" } else { "Red" })
        
        $results += [PSCustomObject]@{
            CheckType = "BackupVault"
            VaultName = $vault.Name
            ResourceGroup = $vault.ResourceGroupName
            Location = $vault.Location
            SoftDelete = $softDelete
            RiskLevel = if ($softDelete -ne "Enabled") { "High" } else { "Low" }
            Issue = if ($softDelete -ne "Enabled") { "Soft delete not enabled - backups can be permanently deleted" } else { "" }
        }
        
        # Check backup policies
        $backupPolicies = Get-AzRecoveryServicesBackupProtectionPolicy
        Write-Host "    Backup Policies: $($backupPolicies.Count)" -ForegroundColor Gray
        
        foreach ($policy in $backupPolicies) {
            Write-Host "      - $($policy.Name) (Schedule: $($policy.SchedulePolicy.ScheduleRunFrequency))" -ForegroundColor Gray
        }
        
        # Check backup items
        $backupItems = Get-AzRecoveryServicesBackupItem -BackupManagementType AzureVM -WorkloadType AzureVM
        Write-Host "    Protected VMs: $($backupItems.Count)" -ForegroundColor $(if ($backupItems.Count -gt 0) { "Green" } else { "Yellow" })
        
        # Check for backup failures
        $failedBackups = $backupItems | Where-Object { $_.ProtectionState -eq "ProtectionStopped" -or $_.LastBackupStatus -eq "Failed" }
        if ($failedBackups) {
            Write-Host "    [WARNING] Failed/Stopped backups: $($failedBackups.Count)" -ForegroundColor Red
            
            $results += [PSCustomObject]@{
                CheckType = "BackupFailures"
                VaultName = $vault.Name
                ResourceGroup = $vault.ResourceGroupName
                FailedCount = $failedBackups.Count
                RiskLevel = "High"
                Issue = "Backup failures detected - data may not be protected"
            }
        }
        
        # Check for unprotected VMs
        $allVMs = Get-AzVM
        $protectedVMIds = $backupItems | Select-Object -ExpandProperty SourceResourceId
        $unprotectedVMs = $allVMs | Where-Object { $_.Id -notin $protectedVMIds }
        
        if ($unprotectedVMs.Count -gt 0) {
            Write-Host "    [WARNING] Unprotected VMs: $($unprotectedVMs.Count)" -ForegroundColor Yellow
            
            $results += [PSCustomObject]@{
                CheckType = "UnprotectedVMs"
                VaultName = $vault.Name
                ResourceGroup = $vault.ResourceGroupName
                UnprotectedCount = $unprotectedVMs.Count
                RiskLevel = "Medium"
                Issue = "VMs without backup protection"
            }
        }
    }
    
    # Check Site Recovery (DR)
    Write-Host "`n[Site Recovery Configuration]" -ForegroundColor Yellow
    try {
        $fabricServers = Get-AzRecoveryServicesAsrFabric
        
        if ($fabricServers) {
            Write-Host "  ASR Fabrics Configured: $($fabricServers.Count)" -ForegroundColor Green
        }
        else {
            Write-Host "  [INFO] No Site Recovery fabrics configured" -ForegroundColor Gray
            Write-Host "  Consider configuring ASR for business-critical workloads" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  [INFO] Site Recovery check skipped" -ForegroundColor Gray
    }
    
    # Check Storage Account Backup (Blob versioning)
    Write-Host "`n[Storage Account Backup Features]" -ForegroundColor Yellow
    $storageAccounts = Get-AzStorageAccount
    
    foreach ($sa in $storageAccounts | Select-Object -First 20) {
        $blobVersioning = $sa.AllowBlobVersioning
        $softDelete = $sa.EnableBlobDeleteRetention
        $deleteRetentionDays = $sa.BlobDeleteRetentionPolicy.Days
        
        $issues = @()
        $riskLevel = "Low"
        
        if (-not $blobVersioning) {
            $issues += "Blob versioning not enabled"
            $riskLevel = "Medium"
        }
        
        if (-not $softDelete) {
            $issues += "Soft delete not enabled"
            if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
        }
        elseif ($deleteRetentionDays -lt 7) {
            $issues += "Short soft delete retention ($deleteRetentionDays days)"
        }
        
        if ($issues.Count -gt 0) {
            $results += [PSCustomObject]@{
                CheckType = "StorageBackup"
                StorageAccount = $sa.StorageAccountName
                ResourceGroup = $sa.ResourceGroupName
                BlobVersioning = $blobVersioning
                SoftDelete = $softDelete
                DeleteRetentionDays = $deleteRetentionDays
                RiskLevel = $riskLevel
                Issue = $issues -join "; "
            }
            
            if ($ShowDetails) {
                Write-Host "  [$riskLevel] $($sa.StorageAccountName): $($issues -join ', ')" -ForegroundColor $(if ($riskLevel -eq "Medium") { "Yellow" } else { "Gray" })
            }
        }
    }
    
    # Check for vault network restrictions
    Write-Host "`n[Backup Vault Network Security]" -ForegroundColor Yellow
    foreach ($vault in $vaults) {
        $vaultResource = Get-AzResource -ResourceId $vault.Id
        $privateEndpoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $vault.Id -ErrorAction SilentlyContinue
        
        if ($privateEndpoints) {
            Write-Host "  [OK] Vault '$($vault.Name)' has private endpoints" -ForegroundColor Green
        }
        else {
            Write-Host "  [INFO] Vault '$($vault.Name)' - no private endpoints (public access)" -ForegroundColor Gray
        }
    }
    
    # Check backup alerts
    Write-Host "`n[Backup Alerts]" -ForegroundColor Yellow
    try {
        foreach ($vault in $vaults) {
            Set-AzRecoveryServicesVaultContext -Vault $vault
            $jobs = Get-AzRecoveryServicesBackupJob -From (Get-Date).AddDays(-7).ToUniversalTime()
            $failedJobs = $jobs | Where-Object { $_.Status -eq "Failed" }
            
            if ($failedJobs) {
                Write-Host "  [WARNING] Vault '$($vault.Name)': $($failedJobs.Count) failed jobs in last 7 days" -ForegroundColor Red
            }
            else {
                Write-Host "  [OK] Vault '$($vault.Name)': No failed jobs in last 7 days" -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Host "  [INFO] Backup job history check skipped" -ForegroundColor Gray
    }
    
    # Summary
    Write-Host "`n=== Backup & DR Summary ===" -ForegroundColor Cyan
    $highRisk = ($results | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumRisk = ($results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    
    Write-Host "Recovery Vaults: $($vaults.Count)" -ForegroundColor Cyan
    Write-Host "High Risk: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Risk: $mediumRisk" -ForegroundColor $(if ($mediumRisk -gt 0) { "Yellow" } else { "Green" })
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Enable soft delete on all recovery services vaults" -ForegroundColor Gray
    Write-Host "  2. Ensure all critical VMs have backup protection" -ForegroundColor Gray
    Write-Host "  3. Enable blob versioning on storage accounts" -ForegroundColor Gray
    Write-Host "  4. Configure Site Recovery for critical workloads" -ForegroundColor Gray
    Write-Host "  5. Regularly test backup restore procedures" -ForegroundColor Gray
    Write-Host "  6. Consider private endpoints for backup vaults" -ForegroundColor Gray
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "BackupRecovery_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "BackupRecovery_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Backup & DR Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
