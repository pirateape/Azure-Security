[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [int]$RetentionDays = 90
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-ActivityLogs_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Azure Activity Log & Diagnostic Settings Audit ===" -ForegroundColor Cyan
    
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
    $subscriptionName = (Get-AzContext).Subscription.Name
    
    Write-Host "`n[Subscription: $subscriptionName]" -ForegroundColor Yellow
    Write-Host "  Subscription ID: $subscriptionId" -ForegroundColor Gray
    
    # Check Activity Log Profile
    Write-Host "`n[Activity Log Profile]" -ForegroundColor Yellow
    $logProfiles = Get-AzLogProfile -ErrorAction SilentlyContinue
    
    if (-not $logProfiles) {
        Write-Host "  [WARNING] No activity log profiles configured!" -ForegroundColor Red
        Write-Host "  Activity logs will only be retained for 90 days in Azure Monitor!" -ForegroundColor Red
        
        $results += [PSCustomObject]@{
            CheckType = "ActivityLogProfile"
            Setting = "Log Profile"
            Value = "Not Configured"
            RiskLevel = "High"
            Recommendation = "Create log profile to export activity logs to storage account or Event Hub"
        }
    }
    else {
        foreach ($profile in $logProfiles) {
            Write-Host "  Log Profile: $($profile.Name)" -ForegroundColor Cyan
            Write-Host "    Storage Account: $($profile.StorageAccountId)" -ForegroundColor $(if ($profile.StorageAccountId) { 'Green' } else { 'Yellow' })
            Write-Host "    Service Bus Rule: $($profile.ServiceBusRuleId)" -ForegroundColor $(if ($profile.ServiceBusRuleId) { 'Green' } else { 'Gray' })
            Write-Host "    Locations: $($profile.Locations -join ', ')" -ForegroundColor Gray
            Write-Host "    Categories: $($profile.Categories -join ', ')" -ForegroundColor Gray
            Write-Host "    Retention (Days): $($profile.RetentionPolicy.Enabled) - $($profile.RetentionPolicy.Days)" -ForegroundColor $(if ($profile.RetentionPolicy.Enabled -and $profile.RetentionPolicy.Days -ge $RetentionDays) { 'Green' } else { 'Yellow' })
            
            $results += [PSCustomObject]@{
                CheckType = "ActivityLogProfile"
                ProfileName = $profile.Name
                StorageAccountConfigured = ($null -ne $profile.StorageAccountId)
                ServiceBusConfigured = ($null -ne $profile.ServiceBusRuleId)
                RetentionEnabled = $profile.RetentionPolicy.Enabled
                RetentionDays = $profile.RetentionPolicy.Days
                RiskLevel = if (-not $profile.StorageAccountId -and -not $profile.ServiceBusRuleId) { 'High' } elseif (-not $profile.RetentionPolicy.Enabled -or $profile.RetentionPolicy.Days -lt $RetentionDays) { 'Medium' } else { 'Low' }
                Issues = if (-not $profile.StorageAccountId -and -not $profile.ServiceBusRuleId) { "No long-term retention configured" } elseif (-not $profile.RetentionPolicy.Enabled) { "Retention not enabled" } elseif ($profile.RetentionPolicy.Days -lt $RetentionDays) { "Retention period less than $RetentionDays days" } else { "" }
            }
        }
    }
    
    # Check Diagnostic Settings at Subscription Level
    Write-Host "`n[Subscription Diagnostic Settings]" -ForegroundColor Yellow
    $subscriptionPath = "/subscriptions/$subscriptionId"
    $diagSettings = Get-AzDiagnosticSetting -ResourceId $subscriptionPath -ErrorAction SilentlyContinue
    
    if (-not $diagSettings) {
        Write-Host "  [WARNING] No diagnostic settings at subscription level!" -ForegroundColor Yellow
        Write-Host "  Administrative, Security, and Alert events may not be captured!" -ForegroundColor Yellow
        
        $results += [PSCustomObject]@{
            CheckType = "SubscriptionDiagnostics"
            Setting = "Diagnostic Settings"
            Value = "Not Configured"
            RiskLevel = "Medium"
            Recommendation = "Configure diagnostic settings to capture Administrative, Security, and Alert logs"
        }
    }
    else {
        foreach ($setting in $diagSettings) {
            Write-Host "  Diagnostic Setting: $($setting.Name)" -ForegroundColor Cyan
            Write-Host "    Log Analytics Workspace: $($setting.WorkspaceId)" -ForegroundColor $(if ($setting.WorkspaceId) { 'Green' } else { 'Gray' })
            Write-Host "    Storage Account: $($setting.StorageAccountId)" -ForegroundColor $(if ($setting.StorageAccountId) { 'Green' } else { 'Gray' })
            Write-Host "    Event Hub: $($setting.EventHubAuthorizationRuleId)" -ForegroundColor $(if ($setting.EventHubAuthorizationRuleId) { 'Green' } else { 'Gray' })
            
            $enabledLogs = $setting.Log | Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty Category
            Write-Host "    Enabled Logs: $($enabledLogs -join ', ')" -ForegroundColor $(if ($enabledLogs.Count -ge 3) { 'Green' } else { 'Yellow' })
        }
    }
    
    # Check recent activity log events
    Write-Host "`n[Recent Activity Log Events (Last 24h)]" -ForegroundColor Yellow
    $startTime = (Get-Date).AddHours(-24)
    $endTime = Get-Date
    
    try {
        $activityLogs = Get-AzLog -StartTime $startTime -EndTime $endTime -MaxRecord 1000 -WarningAction SilentlyContinue
        
        if ($activityLogs) {
            Write-Host "  Total Events: $($activityLogs.Count)" -ForegroundColor Cyan
            
            # Analyze by category
            $writeOperations = $activityLogs | Where-Object { $_.OperationName.Value -like '*write*' -or $_.OperationName.Value -like '*create*' -or $_.OperationName.Value -like '*delete*' }
            $failedOperations = $activityLogs | Where-Object { $_.Status.Value -eq 'Failed' }
            
            Write-Host "  Write/Create/Delete Operations: $($writeOperations.Count)" -ForegroundColor Yellow
            Write-Host "  Failed Operations: $($failedOperations.Count)" -ForegroundColor $(if ($failedOperations.Count -gt 0) { 'Yellow' } else { 'Green' })
            
            # Check for suspicious patterns
            $roleAssignments = $activityLogs | Where-Object { $_.OperationName.Value -like '*roleAssignments*' }
            $policyChanges = $activityLogs | Where-Object { $_.OperationName.Value -like '*policy*' }
            $nsgChanges = $activityLogs | Where-Object { $_.OperationName.Value -like '*networkSecurityGroups*' }
            
            Write-Host "  Role Assignments Modified: $($roleAssignments.Count)" -ForegroundColor $(if ($roleAssignments.Count -gt 0) { 'Yellow' } else { 'Gray' })
            Write-Host "  Policy Changes: $($policyChanges.Count)" -ForegroundColor $(if ($policyChanges.Count -gt 0) { 'Yellow' } else { 'Gray' })
            Write-Host "  NSG Changes: $($nsgChanges.Count)" -ForegroundColor $(if ($nsgChanges.Count -gt 0) { 'Yellow' } else { 'Gray' })
            
            # Check for after-hours activity
            $afterHours = $activityLogs | Where-Object { 
                $eventTime = [DateTime]$_.EventTimestamp
                $hour = $eventTime.Hour
                $hour -lt 6 -or $hour -gt 22
            }
            
            if ($afterHours.Count -gt 10) {
                Write-Host "  [WARNING] After-hours activity detected: $($afterHours.Count) events" -ForegroundColor Yellow
                
                $results += [PSCustomObject]@{
                    CheckType = "ActivityLogAnalysis"
                    Setting = "After-Hours Activity"
                    Value = "$($afterHours.Count) events"
                    RiskLevel = "Medium"
                    Recommendation = "Review after-hours administrative activity"
                }
            }
            
            # Failed authentication attempts
            $failedAuth = $activityLogs | Where-Object { $_.OperationName.Value -like '*login*' -and $_.Status.Value -eq 'Failed' }
            if ($failedAuth.Count -gt 20) {
                Write-Host "  [WARNING] High number of failed authentication attempts: $($failedAuth.Count)" -ForegroundColor Red
                
                $results += [PSCustomObject]@{
                    CheckType = "ActivityLogAnalysis"
                    Setting = "Failed Authentications"
                    Value = "$($failedAuth.Count) failures"
                    RiskLevel = "High"
                    Recommendation = "Investigate potential brute force attack"
                }
            }
        }
        else {
            Write-Host "  [WARNING] No activity log events found - check log profile configuration!" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "  [INFO] Could not retrieve activity logs: $($_.Exception.Message)" -ForegroundColor Gray
    }
    
    # Check resource-level diagnostic settings
    Write-Host "`n[Resource Diagnostic Settings Coverage]" -ForegroundColor Yellow
    
    $resourceTypesToCheck = @(
        "Microsoft.Network/networkSecurityGroups",
        "Microsoft.KeyVault/vaults",
        "Microsoft.Storage/storageAccounts",
        "Microsoft.Sql/servers",
        "Microsoft.Compute/virtualMachines"
    )
    
    foreach ($resourceType in $resourceTypesToCheck) {
        $resources = Get-AzResource -ResourceType $resourceType | Select-Object -First 10
        $withDiagnostics = 0
        $withoutDiagnostics = 0
        
        foreach ($resource in $resources) {
            $resourceDiag = Get-AzDiagnosticSetting -ResourceId $resource.ResourceId -ErrorAction SilentlyContinue
            if ($resourceDiag) {
                $withDiagnostics++
            }
            else {
                $withoutDiagnostics++
            }
        }
        
        $coverage = if ($resources.Count -gt 0) { [math]::Round(($withDiagnostics / $resources.Count) * 100, 1) } else { 0 }
        Write-Host "  $($resourceType.Split('/')[-1]): $coverage% have diagnostic settings ($withDiagnostics/$($resources.Count))" -ForegroundColor $(if ($coverage -ge 80) { 'Green' } elseif ($coverage -ge 50) { 'Yellow' } else { 'Red' })
        
        $results += [PSCustomObject]@{
            CheckType = "ResourceDiagnostics"
            ResourceType = $resourceType
            TotalResources = $resources.Count
            WithDiagnostics = $withDiagnostics
            WithoutDiagnostics = $withoutDiagnostics
            Coverage = "$coverage%"
            RiskLevel = if ($coverage -lt 50) { 'High' } elseif ($coverage -lt 80) { 'Medium' } else { 'Low' }
        }
    }
    
    # Summary
    Write-Host "`n=== Activity Logs Audit Summary ===" -ForegroundColor Cyan
    $highRisk = ($results | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $mediumRisk = ($results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    
    Write-Host "High Risk Findings: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Risk Findings: $mediumRisk" -ForegroundColor $(if ($mediumRisk -gt 0) { "Yellow" } else { "Green" })
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Configure activity log profile for long-term retention" -ForegroundColor Gray
    Write-Host "  2. Enable diagnostic settings on all critical resources" -ForegroundColor Gray
    Write-Host "  3. Export logs to Log Analytics workspace for analysis" -ForegroundColor Gray
    Write-Host "  4. Set up alerts on critical events (role changes, policy changes)" -ForegroundColor Gray
    Write-Host "  5. Review failed authentication attempts regularly" -ForegroundColor Gray
    Write-Host "  6. Monitor after-hours administrative activity" -ForegroundColor Gray
    Write-Host "  7. Retain logs for at least $RetentionDays days" -ForegroundColor Gray
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "ActivityLogs_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "ActivityLogs_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Activity Logs Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
