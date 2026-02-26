[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [switch]$ShowConflictsOnly
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-CA-Conflicts_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Conditional Access Policy Conflict Analyzer ===" -ForegroundColor Cyan
    Write-Host "Analyzing CA policies for conflicts, overlaps, and redundancies...`n" -ForegroundColor Gray
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "Policy.Read.All", "Group.Read.All", "User.Read.All", "Application.Read.All" -NoWelcome
    
    $results = @()
    $conflicts = @()
    $warnings = @()
    
    # Get all CA policies
    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
    $enabledPolicies = $caPolicies | Where-Object { $_.State -eq "enabled" }
    
    Write-Host "Found $($caPolicies.Count) total policies, $($enabledPolicies.Count) enabled" -ForegroundColor Cyan
    
    # Check 1: Duplicate Policies (Same conditions, different actions)
    Write-Host "`n[Check 1] Duplicate Policy Detection..." -ForegroundColor Yellow
    
    for ($i = 0; $i -lt $enabledPolicies.Count; $i++) {
        for ($j = $i + 1; $j -lt $enabledPolicies.Count; $j++) {
            $policy1 = $enabledPolicies[$i]
            $policy2 = $enabledPolicies[$j]
            
            # Check if they have the same users/apps/locations
            $sameUsers = (Compare-Object $policy1.Conditions.Users.IncludeUsers $policy2.Conditions.Users.IncludeUsers).Count -eq 0 -and
                        (Compare-Object $policy1.Conditions.Users.ExcludeUsers $policy2.Conditions.Users.ExcludeUsers).Count -eq 0 -and
                        (Compare-Object $policy1.Conditions.Users.IncludeGroups $policy2.Conditions.Users.IncludeGroups).Count -eq 0 -and
                        (Compare-Object $policy1.Conditions.Users.ExcludeGroups $policy2.Conditions.Users.ExcludeGroups).Count -eq 0
            
            $sameApps = (Compare-Object $policy1.Conditions.Applications.IncludeApplications $policy2.Conditions.Applications.IncludeApplications).Count -eq 0 -and
                       (Compare-Object $policy1.Conditions.Applications.ExcludeApplications $policy2.Conditions.Applications.ExcludeApplications).Count -eq 0
            
            $sameLocations = (Compare-Object $policy1.Conditions.Locations.IncludeLocations $policy2.Conditions.Locations.IncludeLocations).Count -eq 0 -and
                            (Compare-Object $policy1.Conditions.Locations.ExcludeLocations $policy2.Conditions.Locations.ExcludeLocations).Count -eq 0
            
            if ($sameUsers -and $sameApps -and $sameLocations) {
                $conflict = [PSCustomObject]@{
                    Type = "Potential Duplicate"
                    Policy1 = $policy1.DisplayName
                    Policy2 = $policy2.DisplayName
                    SameConditions = "Users, Apps, Locations"
                    Policy1Action = ($policy1.GrantControls.BuiltInControls -join ", ")
                    Policy2Action = ($policy2.GrantControls.BuiltInControls -join ", ")
                    RiskLevel = "Medium"
                    Recommendation = "Review if both policies are necessary; may cause confusion"
                }
                $conflicts += $conflict
                Write-Host "  [WARNING] Potential duplicate policies:" -ForegroundColor Yellow
                Write-Host "    - $($policy1.DisplayName)" -ForegroundColor Gray
                Write-Host "    - $($policy2.DisplayName)" -ForegroundColor Gray
            }
        }
    }
    
    # Check 2: Conflicting Block/Allow
    Write-Host "`n[Check 2] Block vs Allow Conflicts..." -ForegroundColor Yellow
    
    $blockPolicies = $enabledPolicies | Where-Object { $_.GrantControls.BuiltInControls -contains "block" }
    $allowPolicies = $enabledPolicies | Where-Object { $_.GrantControls.BuiltInControls -notcontains "block" }
    
    foreach ($blockPolicy in $blockPolicies) {
        foreach ($allowPolicy in $allowPolicies) {
            # Check for overlap
            $usersOverlap = $false
            $appsOverlap = $false
            
            # Check user overlap
            if ($blockPolicy.Conditions.Users.IncludeUsers -contains "All" -or 
                $allowPolicy.Conditions.Users.IncludeUsers -contains "All") {
                $usersOverlap = $true
            }
            elseif ($blockPolicy.Conditions.Users.IncludeUsers | Where-Object { $allowPolicy.Conditions.Users.IncludeUsers -contains $_ }) {
                $usersOverlap = $true
            }
            
            # Check app overlap
            if ($blockPolicy.Conditions.Applications.IncludeApplications -contains "All" -or 
                $allowPolicy.Conditions.Applications.IncludeApplications -contains "All") {
                $appsOverlap = $true
            }
            elseif ($blockPolicy.Conditions.Applications.IncludeApplications | Where-Object { $allowPolicy.Conditions.Applications.IncludeApplications -contains $_ }) {
                $appsOverlap = $true
            }
            
            if ($usersOverlap -and $appsOverlap) {
                # Check if block has conditions that allow doesn't (e.g., specific locations)
                $blockSpecific = $blockPolicy.Conditions.Locations.IncludeLocations.Count -gt 0 -or
                                $blockPolicy.Conditions.ClientAppTypes.Count -gt 0
                
                if (-not $blockSpecific) {
                    $conflict = [PSCustomObject]@{
                        Type = "Block vs Allow Conflict"
                        Policy1 = $blockPolicy.DisplayName
                        Policy1Type = "Block"
                        Policy2 = $allowPolicy.DisplayName
                        Policy2Type = "Allow"
                        Overlap = "Same users and apps without specific conditions"
                        RiskLevel = "High"
                        Recommendation = "Ensure block policy has more specific conditions (locations, client apps) than allow policy"
                    }
                    $conflicts += $conflict
                    Write-Host "  [CRITICAL] Block vs Allow conflict:" -ForegroundColor Red
                    Write-Host "    Block: $($blockPolicy.DisplayName)" -ForegroundColor Gray
                    Write-Host "    Allow: $($allowPolicy.DisplayName)" -ForegroundColor Gray
                }
            }
        }
    }
    
    # Check 3: Exclusion Gaps
    Write-Host "`n[Check 3] Exclusion Coverage Gaps..." -ForegroundColor Yellow
    
    $policiesWithExclusions = $enabledPolicies | Where-Object { 
        $_.Conditions.Users.ExcludeUsers.Count -gt 0 -or 
        $_.Conditions.Users.ExcludeGroups.Count -gt 0 
    }
    
    foreach ($policy in $policiesWithExclusions) {
        $excludedUsers = $policy.Conditions.Users.ExcludeUsers
        $excludedGroups = $policy.Conditions.Users.ExcludeGroups
        
        if ($excludedUsers.Count -gt 0 -and -not ($excludedUsers -contains "GuestsOrExternalUsers")) {
            $warnings += [PSCustomObject]@{
                Type = "User Exclusion"
                Policy = $policy.DisplayName
                ExcludedCount = $excludedUsers.Count
                RiskLevel = "Medium"
                Recommendation = "Review if exclusions are still necessary; document business justification"
            }
        }
        
        if ($excludedGroups.Count -gt 0) {
            foreach ($groupId in $excludedGroups) {
                try {
                    $group = Get-MgGroup -GroupId $groupId -ErrorAction SilentlyContinue
                    $warnings += [PSCustomObject]@{
                        Type = "Group Exclusion"
                        Policy = $policy.DisplayName
                        GroupName = $group.DisplayName
                        GroupId = $groupId
                        RiskLevel = "Medium"
                        Recommendation = "Ensure excluded group membership is regularly reviewed"
                    }
                }
                catch {
                    $warnings += [PSCustomObject]@{
                        Type = "Group Exclusion (Unresolved)"
                        Policy = $policy.DisplayName
                        GroupName = "Unknown"
                        GroupId = $groupId
                        RiskLevel = "High"
                        Recommendation = "Group no longer exists - remove exclusion"
                    }
                }
            }
        }
    }
    
    # Check 4: Platform-Specific Gaps
    Write-Host "`n[Check 4] Platform Coverage Gaps..." -ForegroundColor Yellow
    
    $policiesWithPlatformConditions = $enabledPolicies | Where-Object { 
        $_.Conditions.Platforms.IncludePlatforms -and 
        $_.Conditions.Platforms.IncludePlatforms.Count -gt 0 
    }
    
    $allPlatformPolicies = $enabledPolicies | Where-Object {
        -not $_.Conditions.Platforms.IncludePlatforms -or
        $_.Conditions.Platforms.IncludePlatforms.Count -eq 0
    }
    
    if ($policiesWithPlatformConditions.Count -gt 0 -and $allPlatformPolicies.Count -gt 0) {
        Write-Host "  [INFO] Mix of platform-specific and all-platform policies found" -ForegroundColor Cyan
        Write-Host "    Platform-specific: $($policiesWithPlatformConditions.Count)" -ForegroundColor Gray
        Write-Host "    All platforms: $($allPlatformPolicies.Count)" -ForegroundColor Gray
    }
    
    # Check 5: Missing Critical App Protection
    Write-Host "`n[Check 5] Critical Application Coverage..." -ForegroundColor Yellow
    
    $criticalApps = @{
        "00000002-0000-0ff1-ce00-000000000000" = "Office 365 Exchange Online"
        "00000003-0000-0000-c000-000000000000" = "Microsoft Graph"
        "00000003-0000-0ff1-ce00-000000000000" = "Office 365 SharePoint Online"
    }
    
    foreach ($appId in $criticalApps.Keys) {
        $appProtection = $enabledPolicies | Where-Object {
            $_.Conditions.Applications.IncludeApplications -contains $appId -or
            $_.Conditions.Applications.IncludeApplications -contains "All"
        }
        
        if ($appProtection.Count -eq 0) {
            $warnings += [PSCustomObject]@{
                Type = "Missing App Protection"
                Application = $criticalApps[$appId]
                AppId = $appId
                RiskLevel = "High"
                Recommendation = "Add CA policy to protect this critical application"
            }
            Write-Host "  [WARNING] No CA policy protects: $($criticalApps[$appId])" -ForegroundColor Yellow
        }
        else {
            Write-Host "  [OK] Protected: $($criticalApps[$appId]) ($($appProtection.Count) policies)" -ForegroundColor Green
        }
    }
    
    # Check 6: Policy Evaluation Order Issues
    Write-Host "`n[Check 6] Policy Priority Analysis..." -ForegroundColor Yellow
    
    $reportOnlyPolicies = $enabledPolicies | Where-Object { $_.State -eq "enabledForReportingButNotEnforced" }
    
    if ($reportOnlyPolicies.Count -gt 0) {
        Write-Host "  [INFO] Report-only policies found ($($reportOnlyPolicies.Count)):" -ForegroundColor Cyan
        $reportOnlyPolicies | ForEach-Object {
            Write-Host "    - $($_.DisplayName)" -ForegroundColor Gray
        }
    }
    
    # Summary
    Write-Host "`n=== CA Conflict Analysis Summary ===" -ForegroundColor Cyan
    Write-Host "Critical Conflicts: $(($conflicts | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor $(if (($conflicts | Where-Object { $_.RiskLevel -eq 'High' }).Count -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Conflicts: $(($conflicts | Where-Object { $_.RiskLevel -eq 'Medium' }).Count)" -ForegroundColor $(if (($conflicts | Where-Object { $_.RiskLevel -eq 'Medium' }).Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Warnings: $($warnings.Count)" -ForegroundColor Yellow
    
    # Build results
    $results = @{
        AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalPolicies = $caPolicies.Count
        EnabledPolicies = $enabledPolicies.Count
        Conflicts = $conflicts
        Warnings = $warnings
    }
    
    # Show detailed conflicts if requested
    if ($ShowConflictsOnly) {
        Write-Host "`n=== Detailed Conflicts ===" -ForegroundColor Cyan
        
        if ($conflicts.Count -gt 0) {
            Write-Host "`nCONFLICTS:" -ForegroundColor Red
            $conflicts | ForEach-Object {
                Write-Host "`n[$($_.Type)]" -ForegroundColor Red
                Write-Host "  Policy 1: $($_.Policy1)" -ForegroundColor Gray
                if ($_.Policy2) { Write-Host "  Policy 2: $($_.Policy2)" -ForegroundColor Gray }
                Write-Host "  Risk: $($_.RiskLevel)" -ForegroundColor $(if ($_.RiskLevel -eq 'High') { "Red" } else { "Yellow" })
                Write-Host "  Recommendation: $($_.Recommendation)" -ForegroundColor Cyan
            }
        }
        
        if ($warnings.Count -gt 0) {
            Write-Host "`nWARNINGS:" -ForegroundColor Yellow
            $warnings | ForEach-Object {
                Write-Host "  [$($_.Type)] $($_.Policy) - $($_.Recommendation)" -ForegroundColor Yellow
            }
        }
    }
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "CA-Conflicts_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $conflicts | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] Conflicts CSV saved to: $csvPath" -ForegroundColor Green
        
        $warningsPath = Join-Path $OutputPath "CA-Warnings_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $warnings | Export-Csv -Path $warningsPath -NoTypeInformation
        Write-Host "[EXPORT] Warnings CSV saved to: $warningsPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "CA-Conflicts_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON report saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== CA Conflict Analysis Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
