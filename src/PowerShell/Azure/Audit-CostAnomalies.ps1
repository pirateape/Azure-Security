[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [int]$LookbackDays = 7,
    [double]$AnomalyThreshold = 50  # Percentage increase to flag as anomaly
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-CostAnomalies_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Azure Cost Anomaly Detection ===" -ForegroundColor Cyan
    Write-Host "Analyzing cost patterns for potential security compromises (crypto mining, resource abuse)" -ForegroundColor Gray
    
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
    
    Write-Host "`n[Cost Analysis for Last $LookbackDays Days]" -ForegroundColor Yellow
    
    # Get resource usage
    $endDate = Get-Date
    $startDate = $endDate.AddDays(-$LookbackDays)
    
    try {
        # Try to get consumption data
        $usage = Get-AzConsumptionUsageDetail -StartDate $startDate -EndDate $endDate -ErrorAction SilentlyContinue | 
            Group-Object -Property InstanceName, ResourceGroup
        
        if ($usage) {
            Write-Host "  Resources with usage: $($usage.Count)" -ForegroundColor Cyan
            
            # Analyze high-cost resources
            $highCostResources = $usage | ForEach-Object {
                $totalCost = ($_.Group | Measure-Object -Property PretaxCost -Sum).Sum
                [PSCustomObject]@{
                    ResourceName = ($_.Name -split ', ')[0]
                    ResourceGroup = ($_.Name -split ', ')[1]
                    Cost = $totalCost
                    UsageRecords = $_.Count
                }
            } | Sort-Object -Property Cost -Descending | Select-Object -First 20
            
            Write-Host "`n  Top 10 Highest Cost Resources:" -ForegroundColor Yellow
            $highCostResources | Select-Object -First 10 | ForEach-Object {
                Write-Host "    $($_.ResourceName): $([math]::Round($_.Cost, 2)) USD" -ForegroundColor $(if ($_.Cost -gt 1000) { 'Red' } elseif ($_.Cost -gt 500) { 'Yellow' } else { 'Gray' })
            }
            
            # Flag suspicious patterns
            $suspiciousResources = @()
            
            foreach ($resource in $highCostResources) {
                $issues = @()
                $riskLevel = 'Low'
                
                # Very high cost (potential crypto mining)
                if ($resource.Cost -gt 2000) {
                    $issues += "Very high cost - possible crypto mining"
                    $riskLevel = 'High'
                }
                elseif ($resource.Cost -gt 1000) {
                    $issues += "High cost"
                    $riskLevel = 'Medium'
                }
                
                # Check if it's a VM (common target for crypto mining)
                if ($resource.ResourceName -match 'vm|virtual' -and $resource.Cost -gt 500) {
                    $vm = Get-AzVM -ResourceGroupName $resource.ResourceGroup -Name $resource.ResourceName -ErrorAction SilentlyContinue
                    if ($vm) {
                        # Get VM metrics to check CPU utilization
                        $cpuMetrics = Get-AzMetric -ResourceId $vm.Id -MetricName "Percentage CPU" -StartTime $startDate -EndTime $endDate -TimeGrain 01:00:00:00 -ErrorAction SilentlyContinue
                        if ($cpuMetrics) {
                            $avgCpu = ($cpuMetrics.Data | Measure-Object -Property Average -Average).Average
                            if ($avgCpu -gt 80) {
                                $issues += "Sustained high CPU ($([math]::Round($avgCpu, 1))%)"
                                if ($riskLevel -eq 'Low') { $riskLevel = 'Medium' }
                            }
                        }
                    }
                }
                
                if ($issues.Count -gt 0) {
                    $suspiciousResources += [PSCustomObject]@{
                        ResourceName = $resource.ResourceName
                        ResourceGroup = $resource.ResourceGroup
                        Cost = $resource.Cost
                        Issues = $issues -join "; "
                        RiskLevel = $riskLevel
                    }
                }
            }
            
            if ($suspiciousResources.Count -gt 0) {
                Write-Host "`n  [WARNING] Suspicious Cost Patterns Detected:" -ForegroundColor Red
                $suspiciousResources | ForEach-Object {
                    Write-Host "    [$($_.RiskLevel)] $($_.ResourceName): $([math]::Round($_.Cost, 2)) USD - $($_.Issues)" -ForegroundColor $(if ($_.RiskLevel -eq 'High') { 'Red' } else { 'Yellow' })
                }
                
                $results += $suspiciousResources
            }
            else {
                Write-Host "  [OK] No suspicious cost patterns detected" -ForegroundColor Green
            }
        }
        else {
            Write-Host "  [INFO] Cost consumption data not available (requires Cost Management permissions)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  [INFO] Could not retrieve cost data: $($_.Exception.Message)" -ForegroundColor Gray
        Write-Host "  Note: Cost Management permissions required for detailed analysis" -ForegroundColor Gray
    }
    
    # Check for recently created resources (potential shadow IT)
    Write-Host "`n[Recently Created Resources]" -ForegroundColor Yellow
    $resources = Get-AzResource | Where-Object { $_.Tags -ne $null }
    
    $recentResources = $resources | Where-Object { 
        $createdTime = $_.Tags.'createdTime' -as [DateTime]
        if (-not $createdTime) {
            $createdTime = $_.Tags.'CreatedDate' -as [DateTime]
        }
        $createdTime -and $createdTime -gt $startDate
    }
    
    if ($recentResources.Count -gt 0) {
        Write-Host "  Resources created in last $LookbackDays days: $($recentResources.Count)" -ForegroundColor Cyan
        
        # Group by resource group
        $byRG = $recentResources | Group-Object -Property ResourceGroupName
        
        foreach ($rg in $byRG | Sort-Object Count -Descending | Select-Object -First 5) {
            Write-Host "    $($rg.Name): $($rg.Count) resources" -ForegroundColor Gray
        }
        
        # Check for resources in suspicious locations
        $unusualLocations = $recentResources | Where-Object { $_.Location -notin @('eastus', 'eastus2', 'westus2', 'westeurope', 'northeurope') } | Select-Object -First 10
        
        if ($unusualLocations.Count -gt 0) {
            Write-Host "`n  [WARNING] Resources created in unusual regions:" -ForegroundColor Yellow
            $unusualLocations | ForEach-Object {
                Write-Host "    - $($_.Name) in $($_.Location)" -ForegroundColor Yellow
            }
        }
        
        $results += [PSCustomObject]@{
            CheckType = "RecentResources"
            Setting = "Resources Created Last $LookbackDays Days"
            Value = $recentResources.Count
            RiskLevel = if ($recentResources.Count -gt 50) { 'Medium' } else { 'Low' }
            Issues = if ($recentResources.Count -gt 50) { "Unusually high number of resources created" } else { "" }
        }
    }
    else {
        Write-Host "  [INFO] No recently created resources found (or missing tags)" -ForegroundColor Gray
    }
    
    # Check for unattached resources (orphaned costs)
    Write-Host "`n[Unattached Resources (Orphaned Costs)]" -ForegroundColor Yellow
    
    # Unattached disks
    $unattachedDisks = Get-AzDisk | Where-Object { $_.ManagedBy -eq $null }
    if ($unattachedDisks.Count -gt 0) {
        $totalSize = ($unattachedDisks | Measure-Object -Property DiskSizeGB -Sum).Sum
        Write-Host "  [WARNING] Unattached Managed Disks: $($unattachedDisks.Count) ($([math]::Round($totalSize, 0)) GB)" -ForegroundColor Yellow
        
        $results += [PSCustomObject]@{
            CheckType = "UnattachedDisks"
            Setting = "Unattached Managed Disks"
            Count = $unattachedDisks.Count
            TotalSizeGB = $totalSize
            RiskLevel = 'Medium'
            Issues = "Unused disks incurring costs"
        }
    }
    else {
        Write-Host "  [OK] No unattached managed disks" -ForegroundColor Green
    }
    
    # Unattached NICs
    $unattachedNics = Get-AzNetworkInterface | Where-Object { $_.VirtualMachine -eq $null -and $_.PrivateEndpoint -eq $null }
    if ($unattachedNics.Count -gt 0) {
        Write-Host "  [WARNING] Unattached Network Interfaces: $($unattachedNics.Count)" -ForegroundColor Yellow
        
        $results += [PSCustomObject]@{
            CheckType = "UnattachedNICs"
            Setting = "Unattached Network Interfaces"
            Count = $unattachedNics.Count
            RiskLevel = 'Low'
            Issues = "Unused NICs"
        }
    }
    
    # Orphaned Public IPs
    $publicIPs = Get-AzPublicIpAddress | Where-Object { $_.IpConfiguration -eq $null }
    if ($publicIPs.Count -gt 0) {
        Write-Host "  [WARNING] Unattached Public IPs: $($publicIPs.Count)" -ForegroundColor Yellow
        
        $results += [PSCustomObject]@{
            CheckType = "UnattachedPublicIPs"
            Setting = "Unattached Public IP Addresses"
            Count = $publicIPs.Count
            RiskLevel = 'Medium'
            Issues = "Unused public IPs - security risk and cost"
        }
    }
    
    # Check for budget alerts
    Write-Host "`n[Budget Configuration]" -ForegroundColor Yellow
    try {
        $budgets = Get-AzConsumptionBudget -ErrorAction SilentlyContinue
        
        if ($budgets) {
            Write-Host "  Budgets Configured: $($budgets.Count)" -ForegroundColor Green
            
            foreach ($budget in $budgets) {
                Write-Host "    - $($budget.Name): $($budget.Amount) $($budget.Category) ($($budget.TimeGrain))" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "  [WARNING] No budgets configured!" -ForegroundColor Yellow
            Write-Host "  Recommendation: Set up budget alerts to detect unusual spending" -ForegroundColor Gray
            
            $results += [PSCustomObject]@{
                CheckType = "Budgets"
                Setting = "Budget Alerts"
                Value = "Not Configured"
                RiskLevel = 'Medium'
                Issues = "No budget alerts configured"
            }
        }
    }
    catch {
        Write-Host "  [INFO] Budget information not available" -ForegroundColor Gray
    }
    
    # Summary
    Write-Host "`n=== Cost Anomaly Detection Summary ===" -ForegroundColor Cyan
    $highRisk = ($results | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $mediumRisk = ($results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    
    Write-Host "High Risk Anomalies: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Risk Issues: $mediumRisk" -ForegroundColor $(if ($mediumRisk -gt 0) { "Yellow" } else { "Green" })
    
    if ($highRisk -gt 0) {
        Write-Host "`n[SECURITY ALERT]" -ForegroundColor Red
        Write-Host "High-cost anomalies detected - investigate for potential compromise!" -ForegroundColor Red
    }
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Set up budget alerts for anomaly detection" -ForegroundColor Gray
    Write-Host "  2. Monitor resources with sustained high CPU" -ForegroundColor Gray
    Write-Host "  3. Investigate resources created in unusual regions" -ForegroundColor Gray
    Write-Host "  4. Delete unattached resources to reduce costs and attack surface" -ForegroundColor Gray
    Write-Host "  5. Tag all resources with owner and purpose" -ForegroundColor Gray
    Write-Host "  6. Review resources with costs > $1000 for business justification" -ForegroundColor Gray
    Write-Host "  7. Enable Cost Management exports for long-term analysis" -ForegroundColor Gray
    Write-Host "  8. Use Azure Advisor cost recommendations" -ForegroundColor Gray
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "CostAnomalies_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "CostAnomalies_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Cost Anomaly Detection Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
