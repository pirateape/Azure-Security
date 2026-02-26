[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [switch]$CheckKeyRotation
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-KeyVault-Security_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Key Vault & Secrets Security Audit ===" -ForegroundColor Cyan
    
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
    
    Write-Host "`n[Key Vault Inventory]" -ForegroundColor Yellow
    $keyVaults = Get-AzKeyVault
    Write-Host "  Key Vaults Found: $($keyVaults.Count)" -ForegroundColor Cyan
    
    foreach ($kv in $keyVaults) {
        Write-Host "`n  Vault: $($kv.VaultName)" -ForegroundColor Cyan
        
        # Check soft delete
        $softDelete = $kv.EnableSoftDelete
        Write-Host "    Soft Delete: $(if ($softDelete) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($softDelete) { 'Green' } else { 'Red' })
        
        # Check purge protection
        $purgeProtection = $kv.EnablePurgeProtection
        Write-Host "    Purge Protection: $(if ($purgeProtection) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($purgeProtection) { 'Green' } else { 'Yellow' })
        
        # Check network rules
        $networkRules = Get-AzKeyVaultNetworkRuleSet -VaultName $kv.VaultName -ResourceGroupName $kv.ResourceGroupName
        $defaultAction = $networkRules.DefaultAction
        Write-Host "    Network Access: $defaultAction" -ForegroundColor $(if ($defaultAction -eq 'Deny') { 'Green' } else { 'Red' })
        
        # Check private endpoints
        $privateEndpoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $kv.ResourceId -ErrorAction SilentlyContinue
        Write-Host "    Private Endpoints: $(if ($privateEndpoints) { $privateEndpoints.Count } else { 'None' })" -ForegroundColor $(if ($privateEndpoints) { 'Green' } else { 'Yellow' })
        
        # Check RBAC vs Access Policies
        $rbacEnabled = $kv.EnableRbacAuthorization
        Write-Host "    RBAC Authorization: $(if ($rbacEnabled) { 'ENABLED' } else { 'Access Policies' })" -ForegroundColor $(if ($rbacEnabled) { 'Green' } else { 'Gray' })
        
        $results += [PSCustomObject]@{
            CheckType = "KeyVaultConfig"
            VaultName = $kv.VaultName
            ResourceGroup = $kv.ResourceGroupName
            Location = $kv.Location
            SoftDelete = $softDelete
            PurgeProtection = $purgeProtection
            NetworkAccess = $defaultAction
            PrivateEndpoints = ($privateEndpoints.Count -gt 0)
            RBACEnabled = $rbacEnabled
            RiskLevel = if (-not $softDelete -or -not $purgeProtection -or $defaultAction -eq 'Allow') { 'High' } else { 'Low' }
            Issues = @() | ForEach-Object { 
                if (-not $softDelete) { $_ += "Soft delete disabled" }
                if (-not $purgeProtection) { $_ += "Purge protection disabled" }
                if ($defaultAction -eq 'Allow') { $_ += "Public network access allowed" }
                if (-not $privateEndpoints) { $_ += "No private endpoints" }
                $_ -join "; "
            }
        }
        
        # Check secrets
        Write-Host "    [Checking Secrets...]" -ForegroundColor Gray
        $secrets = Get-AzKeyVaultSecret -VaultName $kv.VaultName -ErrorAction SilentlyContinue
        
        if ($secrets) {
            Write-Host "      Secrets: $($secrets.Count)" -ForegroundColor Gray
            
            $oldSecrets = 0
            $expiredSecrets = 0
            $noExpiration = 0
            
            foreach ($secret in $secrets | Select-Object -First 50) {
                $secretDetail = Get-AzKeyVaultSecret -VaultName $kv.VaultName -Name $secret.Name
                
                if ($secretDetail.Enabled -eq $false) {
                    continue
                }
                
                $created = $secretDetail.Created
                $expires = $secretDetail.Expires
                $age = (Get-Date) - $created
                
                if ($age.Days -gt 365) {
                    $oldSecrets++
                }
                
                if ($expires -and $expires -lt (Get-Date)) {
                    $expiredSecrets++
                }
                elseif (-not $expires) {
                    $noExpiration++
                }
            }
            
            if ($oldSecrets -gt 0) {
                Write-Host "      [WARNING] $oldSecrets secrets older than 365 days" -ForegroundColor Yellow
            }
            if ($expiredSecrets -gt 0) {
                Write-Host "      [WARNING] $expiredSecrets expired secrets" -ForegroundColor Red
            }
            if ($noExpiration -gt 0) {
                Write-Host "      [WARNING] $noExpiration secrets without expiration date" -ForegroundColor Yellow
            }
            
            $results += [PSCustomObject]@{
                CheckType = "KeyVaultSecrets"
                VaultName = $kv.VaultName
                TotalSecrets = $secrets.Count
                OldSecrets = $oldSecrets
                ExpiredSecrets = $expiredSecrets
                NoExpiration = $noExpiration
                RiskLevel = if ($expiredSecrets -gt 0 -or $noExpiration -gt 5) { 'Medium' } else { 'Low' }
                Issues = "Secret hygiene issues detected"
            }
        }
        
        # Check certificates
        Write-Host "    [Checking Certificates...]" -ForegroundColor Gray
        $certs = Get-AzKeyVaultCertificate -VaultName $kv.VaultName -ErrorAction SilentlyContinue
        
        if ($certs) {
            Write-Host "      Certificates: $($certs.Count)" -ForegroundColor Gray
            
            $expiringCerts = 0
            $expiredCerts = 0
            
            foreach ($cert in $certs) {
                $certDetail = Get-AzKeyVaultCertificate -VaultName $kv.VaultName -Name $cert.Name
                $expiry = $certDetail.Expires
                $daysUntilExpiry = ($expiry - (Get-Date)).Days
                
                if ($daysUntilExpiry -lt 0) {
                    $expiredCerts++
                }
                elseif ($daysUntilExpiry -lt 30) {
                    $expiringCerts++
                }
            }
            
            if ($expiringCerts -gt 0) {
                Write-Host "      [WARNING] $expiringCerts certificates expiring within 30 days" -ForegroundColor Yellow
            }
            if ($expiredCerts -gt 0) {
                Write-Host "      [CRITICAL] $expiredCerts expired certificates!" -ForegroundColor Red
            }
            
            $results += [PSCustomObject]@{
                CheckType = "KeyVaultCertificates"
                VaultName = $kv.VaultName
                TotalCertificates = $certs.Count
                Expiring30Days = $expiringCerts
                Expired = $expiredCerts
                RiskLevel = if ($expiredCerts -gt 0) { 'High' } elseif ($expiringCerts -gt 0) { 'Medium' } else { 'Low' }
                Issues = if ($expiredCerts -gt 0) { "Expired certificates present" } elseif ($expiringCerts -gt 0) { "Certificates expiring soon" } else { "" }
            }
        }
        
        # Check keys
        if ($CheckKeyRotation) {
            Write-Host "    [Checking Keys...]" -ForegroundColor Gray
            $keys = Get-AzKeyVaultKey -VaultName $kv.VaultName -ErrorAction SilentlyContinue
            
            if ($keys) {
                Write-Host "      Keys: $($keys.Count)" -ForegroundColor Gray
                
                $oldKeys = 0
                foreach ($key in $keys) {
                    $keyDetail = Get-AzKeyVaultKey -VaultName $kv.VaultName -Name $key.Name
                    $created = $keyDetail.Created
                    $age = (Get-Date) - $created
                    
                    if ($age.Days -gt 365) {
                        $oldKeys++
                    }
                }
                
                if ($oldKeys -gt 0) {
                    Write-Host "      [WARNING] $oldKeys keys older than 365 days - consider rotation" -ForegroundColor Yellow
                }
            }
        }
        
        # Check diagnostic settings
        Write-Host "    [Checking Diagnostic Settings...]" -ForegroundColor Gray
        $diagSettings = Get-AzDiagnosticSetting -ResourceId $kv.ResourceId -ErrorAction SilentlyContinue
        
        if (-not $diagSettings) {
            Write-Host "      [WARNING] No diagnostic settings configured!" -ForegroundColor Yellow
            $results += [PSCustomObject]@{
                CheckType = "KeyVaultDiagnostics"
                VaultName = $kv.VaultName
                DiagnosticsEnabled = $false
                RiskLevel = 'Medium'
                Issues = "Diagnostic logging not enabled"
            }
        }
        else {
            Write-Host "      [OK] Diagnostic settings configured" -ForegroundColor Green
        }
    }
    
    # Summary
    Write-Host "`n=== Key Vault Security Summary ===" -ForegroundColor Cyan
    $highRiskVaults = ($results | Where-Object { $_.CheckType -eq "KeyVaultConfig" -and $_.RiskLevel -eq "High" }).Count
    $mediumRiskVaults = ($results | Where-Object { $_.CheckType -eq "KeyVaultConfig" -and $_.RiskLevel -eq "Medium" }).Count
    $expiredCerts = ($results | Where-Object { $_.CheckType -eq "KeyVaultCertificates" }).Expired | Measure-Object -Sum | Select-Object -ExpandProperty Sum
    
    Write-Host "Total Key Vaults: $($keyVaults.Count)" -ForegroundColor Cyan
    Write-Host "High Risk: $highRiskVaults" -ForegroundColor $(if ($highRiskVaults -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Risk: $mediumRiskVaults" -ForegroundColor $(if ($mediumRiskVaults -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Expired Certificates: $expiredCerts" -ForegroundColor $(if ($expiredCerts -gt 0) { "Red" } else { "Green" })
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Enable soft delete and purge protection on all vaults" -ForegroundColor Gray
    Write-Host "  2. Disable public network access, use private endpoints" -ForegroundColor Gray
    Write-Host "  3. Migrate from access policies to RBAC authorization" -ForegroundColor Gray
    Write-Host "  4. Enable diagnostic logging for all vaults" -ForegroundColor Gray
    Write-Host "  5. Set expiration dates on all secrets" -ForegroundColor Gray
    Write-Host "  6. Implement certificate rotation before expiry" -ForegroundColor Gray
    Write-Host "  7. Rotate keys older than 365 days" -ForegroundColor Gray
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "KeyVault-Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "KeyVault-Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Key Vault Security Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
