[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [int]$StaleDeviceDays = 90
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-DeviceCompliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Device Compliance & Management Audit ===" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "Device.Read.All", "DeviceManagementManagedDevices.Read.All", "DeviceManagementConfiguration.Read.All" -NoWelcome
    
    $results = @()
    
    # Get all devices
    Write-Host "`n[Device Inventory]" -ForegroundColor Yellow
    $devices = Get-MgDevice -All -Property "id,deviceId,displayName,operatingSystem,operatingSystemVersion,trustType,registrationDateTime,approximateLastSignInDateTime,accountEnabled,isManaged,isCompliant,mdmAppId"
    
    Write-Host "Total Devices: $($devices.Count)" -ForegroundColor Cyan
    
    # Categorize devices
    $managedDevices = $devices | Where-Object { $_.IsManaged -eq $true }
    $compliantDevices = $devices | Where-Object { $_.IsCompliant -eq $true }
    $unmanagedDevices = $devices | Where-Object { $_.IsManaged -eq $false -or $_.IsManaged -eq $null }
    $nonCompliantDevices = $devices | Where-Object { $_.IsCompliant -eq $false -or $_.IsCompliant -eq $null }
    $disabledDevices = $devices | Where-Object { $_.AccountEnabled -eq $false }
    
    # By OS
    $windowsDevices = $devices | Where-Object { $_.OperatingSystem -eq "Windows" }
    $iosDevices = $devices | Where-Object { $_.OperatingSystem -eq "iOS" }
    $androidDevices = $devices | Where-Object { $_.OperatingSystem -eq "Android" }
    $macOSDevices = $devices | Where-Object { $_.OperatingSystem -eq "macOS" }
    
    Write-Host "`nDevice Breakdown:" -ForegroundColor Yellow
    Write-Host "  Managed: $($managedDevices.Count)" -ForegroundColor Green
    Write-Host "  Compliant: $($compliantDevices.Count)" -ForegroundColor Green
    Write-Host "  Unmanaged: $($unmanagedDevices.Count)" -ForegroundColor $(if ($unmanagedDevices.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Non-Compliant: $($nonCompliantDevices.Count)" -ForegroundColor $(if ($nonCompliantDevices.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  Disabled: $($disabledDevices.Count)" -ForegroundColor Gray
    Write-Host "`nBy Operating System:" -ForegroundColor Yellow
    Write-Host "  Windows: $($windowsDevices.Count)" -ForegroundColor Cyan
    Write-Host "  iOS: $($iosDevices.Count)" -ForegroundColor Cyan
    Write-Host "  Android: $($androidDevices.Count)" -ForegroundColor Cyan
    Write-Host "  macOS: $($macOSDevices.Count)" -ForegroundColor Cyan
    
    # Check for stale devices
    Write-Host "`n[Stale Device Analysis]" -ForegroundColor Yellow
    $staleThreshold = (Get-Date).AddDays(-$StaleDeviceDays)
    $staleDevices = $devices | Where-Object { 
        $_.ApproximateLastSignInDateTime -lt $staleThreshold -and 
        $_.AccountEnabled -eq $true 
    }
    
    if ($staleDevices.Count -gt 0) {
        Write-Host "[WARNING] Found $($staleDevices.Count) stale devices (no sign-in for $StaleDeviceDays+ days)" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            CheckType = "StaleDevices"
            Setting = "Stale Devices (90+ days)"
            Value = $staleDevices.Count
            RiskLevel = "Medium"
            Details = "Devices not signed in for $StaleDeviceDays+ days"
        }
    }
    else {
        Write-Host "[OK] No stale devices found" -ForegroundColor Green
    }
    
    # Analyze individual devices
    Write-Host "`n[Device Details Analysis]" -ForegroundColor Yellow
    foreach ($device in $devices | Select-Object -First 100) {
        $issues = @()
        $riskLevel = "Low"
        
        # Check management status
        if (-not $device.IsManaged) {
            $issues += "Not managed by MDM"
            $riskLevel = "Medium"
        }
        
        # Check compliance
        if (-not $device.IsCompliant -and $device.IsManaged) {
            $issues += "Not compliant"
            $riskLevel = "High"
        }
        
        # Check OS version (Windows)
        if ($device.OperatingSystem -eq "Windows" -and $device.OperatingSystemVersion) {
            $osVersion = [version]$device.OperatingSystemVersion
            if ($osVersion.Major -lt 10) {
                $issues += "Outdated Windows version"
                $riskLevel = "High"
            }
            elseif ($osVersion.Build -lt 19041) { # Windows 10 2004
                $issues += "Windows version needs update"
                if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
            }
        }
        
        # Check last sign-in
        if ($device.ApproximateLastSignInDateTime) {
            $daysSinceSignIn = [math]::Floor(((Get-Date) - [datetime]$device.ApproximateLastSignInDateTime).TotalDays)
            if ($daysSinceSignIn -gt 180) {
                $issues += "No sign-in for 180+ days"
                if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
            }
        }
        
        # Check if disabled
        if (-not $device.AccountEnabled) {
            $issues += "Account disabled"
            $riskLevel = "Low"
        }
        
        $result = [PSCustomObject]@{
            DeviceName = $device.DisplayName
            DeviceId = $device.DeviceId
            OperatingSystem = $device.OperatingSystem
            OSVersion = $device.OperatingSystemVersion
            TrustType = $device.TrustType
            IsManaged = $device.IsManaged
            IsCompliant = $device.IsCompliant
            IsEnabled = $device.AccountEnabled
            LastSignInDateTime = $device.ApproximateLastSignInDateTime
            DaysSinceSignIn = if ($device.ApproximateLastSignInDateTime) { [math]::Floor(((Get-Date) - [datetime]$device.ApproximateLastSignInDateTime).TotalDays) } else { $null }
            RiskLevel = $riskLevel
            Issues = ($issues -join "; ")
        }
        
        $results += $result
    }
    
    # Check compliance policies
    Write-Host "`n[Compliance Policies]" -ForegroundColor Yellow
    try {
        $compliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy -ErrorAction SilentlyContinue
        
        if ($compliancePolicies) {
            Write-Host "  Compliance Policies: $($compliancePolicies.Count)" -ForegroundColor Cyan
            
            foreach ($policy in $compliancePolicies) {
                Write-Host "    - $($policy.DisplayName) (State: $($policy.State))" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "  [WARNING] No compliance policies found" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [INFO] Unable to retrieve compliance policies (may require Intune permissions)" -ForegroundColor Gray
    }
    
    # Check configuration profiles
    Write-Host "`n[Configuration Profiles]" -ForegroundColor Yellow
    try {
        $configProfiles = Get-MgDeviceManagementDeviceConfiguration -ErrorAction SilentlyContinue
        
        if ($configProfiles) {
            Write-Host "  Configuration Profiles: $($configProfiles.Count)" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Host "  [INFO] Unable to retrieve configuration profiles" -ForegroundColor Gray
    }
    
    # Risk summary
    $highRiskDevices = $results | Where-Object { $_.RiskLevel -eq "High" }
    $mediumRiskDevices = $results | Where-Object { $_.RiskLevel -eq "Medium" }
    
    Write-Host "`n[Risk Summary]" -ForegroundColor Yellow
    Write-Host "  High Risk Devices: $($highRiskDevices.Count)" -ForegroundColor $(if ($highRiskDevices.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  Medium Risk Devices: $($mediumRiskDevices.Count)" -ForegroundColor $(if ($mediumRiskDevices.Count -gt 0) { "Yellow" } else { "Green" })
    
    if ($highRiskDevices.Count -gt 0) {
        Write-Host "`nHigh Risk Devices:" -ForegroundColor Red
        $highRiskDevices | Select-Object -First 10 | ForEach-Object {
            Write-Host "  - $($_.DeviceName) [$($_.OperatingSystem)] - $($_.Issues)" -ForegroundColor Red
        }
    }
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "DeviceCompliance_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "DeviceCompliance_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Device Compliance Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
