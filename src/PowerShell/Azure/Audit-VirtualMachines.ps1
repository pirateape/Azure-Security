[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-VirtualMachines_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Virtual Machines Security Audit ===" -ForegroundColor Cyan
    
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
    
    Write-Host "`n[Virtual Machines Inventory]" -ForegroundColor Yellow
    $vms = Get-AzVM
    Write-Host "  VMs Found: $($vms.Count)" -ForegroundColor Cyan
    
    foreach ($vm in $vms) {
        Write-Host "`n  VM: $($vm.Name)" -ForegroundColor Cyan
        
        $managedDisk = [bool]$vm.StorageProfile.OsDisk.ManagedDisk
        Write-Host "    Managed Disk: $(if ($managedDisk) { 'YES' } else { 'NO (Unmanaged)' })" -ForegroundColor $(if ($managedDisk) { 'Green' } else { 'Red' })
        
        $diskEncryption = [bool]$vm.StorageProfile.OsDisk.EncryptionSettings
        Write-Host "    OS Disk Encryption: $(if ($diskEncryption) { 'ENABLED' } else { 'DISABLED/Not configured via ADE' })" -ForegroundColor $(if ($diskEncryption) { 'Green' } else { 'Red' })
        
        # Determine endpoint protection by checking extensions
        $extensions = Get-AzVMExtension -ResourceGroupName $vm.ResourceGroupName -VMName $vm.Name -ErrorAction SilentlyContinue
        $epActive = $false
        foreach ($ext in $extensions) {
            if ($ext.Publisher -match "Microsoft.Azure.Security" -or $ext.ExtensionType -match "IaaSAntimalware|EndpointProtection") {
                $epActive = $true
                break
            }
        }
        Write-Host "    Endpoint Protection (Extension): $(if ($epActive) { 'DETECTED' } else { 'NOT DETECTED' })" -ForegroundColor $(if ($epActive) { 'Green' } else { 'Yellow' })
        
        $issues = @()
        if (-not $managedDisk) { $issues += "Uses unmanaged disk" }
        if (-not $diskEncryption) { $issues += "OS disk encryption not enabled via ADE" }
        if (-not $epActive) { $issues += "No recognized endpoint protection extension" }
        
        $results += [PSCustomObject]@{
            CheckType                   = "VirtualMachineConfig"
            VMName                      = $vm.Name
            ResourceGroup               = $vm.ResourceGroupName
            Location                    = $vm.Location
            ManagedDisk                 = $managedDisk
            DiskEncrypted               = $diskEncryption
            EndpointProtectionExtension = $epActive
            RiskLevel                   = if (-not $managedDisk -or -not $diskEncryption) { 'High' } elseif (-not $epActive) { 'Medium' } else { 'Low' }
            Issues                      = $issues -join "; "
        }
    }
    
    # Summary
    Write-Host "`n=== Virtual Machines Security Summary ===" -ForegroundColor Cyan
    $highRiskVMs = ($results | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumRiskVMs = ($results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    
    Write-Host "Total Virtual Machines: $($vms.Count)" -ForegroundColor Cyan
    Write-Host "High Risk (Unmanaged Disks/No Encryption): $highRiskVMs" -ForegroundColor $(if ($highRiskVMs -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Risk (No EP Extension): $mediumRiskVMs" -ForegroundColor $(if ($mediumRiskVMs -gt 0) { "Yellow" } else { "Green" })
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Migrate all VMs with unmanaged disks to Managed Disks." -ForegroundColor Gray
    Write-Host "  2. Enable Azure Disk Encryption (ADE) or Customer-Managed Keys (CMK) for OS and Data disks." -ForegroundColor Gray
    Write-Host "  3. Deploy Endpoint Protection extensions (Microsoft Defender or third-party) to all VMs." -ForegroundColor Gray
    
    # Export
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "VirtualMachines-Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "VirtualMachines-Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Virtual Machines Audit Complete ===" -ForegroundColor Cyan
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
