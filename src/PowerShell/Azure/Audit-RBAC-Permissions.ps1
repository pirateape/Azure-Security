[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [switch]$ShowDetails
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-RBAC-Permissions_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== RBAC Permissions & Privilege Audit ===" -ForegroundColor Cyan
    
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
    
    Write-Host "`n[Subscription Level Role Assignments]" -ForegroundColor Yellow
    
    # Get all role assignments at subscription level
    $subRoleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$subscriptionId"
    
    $highPrivRoles = @(
        "Owner",
        "Contributor", 
        "User Access Administrator",
        "Security Admin",
        "Key Vault Administrator"
    )
    
    $highPrivAssignments = $subRoleAssignments | Where-Object { $_.RoleDefinitionName -in $highPrivRoles }
    
    Write-Host "  Total Role Assignments: $($subRoleAssignments.Count)" -ForegroundColor Cyan
    Write-Host "  High Privilege Assignments: $($highPrivAssignments.Count)" -ForegroundColor $(if ($highPrivAssignments.Count -gt 10) { "Yellow" } else { "Green" })
    
    # Check for Service Principals with high privileges
    $spnHighPriv = $highPrivAssignments | Where-Object { $_.ObjectType -eq "ServicePrincipal" }
    Write-Host "  Service Principals with High Privileges: $($spnHighPriv.Count)" -ForegroundColor $(if ($spnHighPriv.Count -gt 0) { "Yellow" } else { "Green" })
    
    foreach ($assignment in $highPrivAssignments) {
        $riskLevel = if ($assignment.RoleDefinitionName -eq "Owner") { "High" } else { "Medium" }
        
        if ($assignment.ObjectType -eq "ServicePrincipal") {
            $riskLevel = "High"  # Elevate risk for SPNs
        }
        
        $result = [PSCustomObject]@{
            Scope = "Subscription"
            ScopeName = $subscriptionId
            PrincipalName = $assignment.DisplayName
            PrincipalType = $assignment.ObjectType
            PrincipalId = $assignment.ObjectId
            Role = $assignment.RoleDefinitionName
            RiskLevel = $riskLevel
            Issue = if ($assignment.ObjectType -eq "ServicePrincipal") { "Service Principal with elevated permissions" } else { "" }
        }
        
        $results += $result
        
        if ($ShowDetails) {
            $color = if ($riskLevel -eq "High") { "Red" } elseif ($riskLevel -eq "Medium") { "Yellow" } else { "Green" }
            Write-Host "  [$riskLevel] $($assignment.DisplayName) - $($assignment.RoleDefinitionName)" -ForegroundColor $color
        }
    }
    
    # Check for classic administrators (deprecated)
    Write-Host "`n[Classic Administrators (Deprecated)]" -ForegroundColor Yellow
    try {
        $classicAdmins = Get-AzRoleAssignment -IncludeClassicAdministrators | Where-Object { $_.Scope -eq "/subscriptions/$subscriptionId" -and $_.RoleDefinitionName -like "*Administrator" }
        
        if ($classicAdmins) {
            Write-Host "  [WARNING] Found $($classicAdmins.Count) classic administrator assignments!" -ForegroundColor Red
            Write-Host "  Classic RBAC is deprecated - migrate to Azure RBAC!" -ForegroundColor Red
            
            foreach ($admin in $classicAdmins) {
                $results += [PSCustomObject]@{
                    Scope = "Subscription"
                    ScopeName = $subscriptionId
                    PrincipalName = $admin.DisplayName
                    PrincipalType = $admin.ObjectType
                    PrincipalId = $admin.ObjectId
                    Role = $admin.RoleDefinitionName
                    RiskLevel = "High"
                    Issue = "Classic Administrator - deprecated, should migrate to Azure RBAC"
                }
            }
        }
        else {
            Write-Host "  [OK] No classic administrators found" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [INFO] Classic administrator check skipped" -ForegroundColor Gray
    }
    
    # Check resource group level assignments
    Write-Host "`n[Resource Group Level Assignments]" -ForegroundColor Yellow
    $resourceGroups = Get-AzResourceGroup
    $rgAssignments = @()
    
    foreach ($rg in $resourceGroups) {
        $assignments = Get-AzRoleAssignment -ResourceGroupName $rg.ResourceGroupName
        $rgHighPriv = $assignments | Where-Object { $_.RoleDefinitionName -in $highPrivRoles }
        
        if ($rgHighPriv.Count -gt 0) {
            Write-Host "  Resource Group '$($rg.ResourceGroupName)': $($rgHighPriv.Count) high privilege assignments" -ForegroundColor Yellow
            
            foreach ($assignment in $rgHighPriv) {
                $results += [PSCustomObject]@{
                    Scope = "ResourceGroup"
                    ScopeName = $rg.ResourceGroupName
                    PrincipalName = $assignment.DisplayName
                    PrincipalType = $assignment.ObjectType
                    PrincipalId = $assignment.ObjectId
                    Role = $assignment.RoleDefinitionName
                    RiskLevel = "Medium"
                    Issue = "High privilege at resource group level"
                }
            }
        }
    }
    
    # Check for custom roles
    Write-Host "`n[Custom RBAC Roles]" -ForegroundColor Yellow
    $customRoles = Get-AzRoleDefinition -Custom | Where-Object { $_.AssignableScopes -contains "/subscriptions/$subscriptionId" }
    
    Write-Host "  Custom Roles: $($customRoles.Count)" -ForegroundColor Cyan
    
    foreach ($role in $customRoles) {
        $wildCardActions = $role.Actions | Where-Object { $_ -eq "*" }
        $wildCardDataActions = $role.DataActions | Where-Object { $_ -eq "*" }
        
        if ($wildCardActions -or $wildCardDataActions) {
            Write-Host "  [WARNING] Custom role '$($role.Name)' has wildcard (*) permissions!" -ForegroundColor Red
            
            $results += [PSCustomObject]@{
                Scope = "CustomRole"
                ScopeName = $role.Name
                PrincipalName = "N/A"
                PrincipalType = "RoleDefinition"
                PrincipalId = $role.Id
                Role = "Custom"
                RiskLevel = "High"
                Issue = "Custom role has wildcard (*) permissions - very dangerous"
            }
        }
        else {
            Write-Host "  [INFO] Custom role: $($role.Name)" -ForegroundColor Gray
        }
    }
    
    # Check for orphaned role assignments
    Write-Host "`n[Orphaned Role Assignments Check]" -ForegroundColor Yellow
    $orphanedCount = 0
    
    foreach ($assignment in $subRoleAssignments | Select-Object -First 100) {
        $principal = Get-AzADObject -ObjectId $assignment.ObjectId -ErrorAction SilentlyContinue
        
        if (-not $principal) {
            $orphanedCount++
            if ($orphanedCount -le 5) {
                Write-Host "  [WARNING] Orphaned assignment: $($assignment.DisplayName) ($($assignment.RoleDefinitionName))" -ForegroundColor Yellow
            }
        }
    }
    
    if ($orphanedCount -gt 0) {
        Write-Host "  Total Orphaned Assignments: $orphanedCount" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            Scope = "Subscription"
            ScopeName = $subscriptionId
            PrincipalName = "Multiple Orphaned"
            PrincipalType = "Unknown"
            PrincipalId = "N/A"
            Role = "Various"
            RiskLevel = "Medium"
            Issue = "$orphanedCount orphaned role assignments should be removed"
        }
    }
    else {
        Write-Host "  [OK] No orphaned role assignments found" -ForegroundColor Green
    }
    
    # Check for resource locks
    Write-Host "`n[Resource Locks]" -ForegroundColor Yellow
    $locks = Get-AzResourceLock -Scope "/subscriptions/$subscriptionId"
    
    if ($locks.Count -eq 0) {
        Write-Host "  [WARNING] No resource locks configured!" -ForegroundColor Yellow
        Write-Host "  Consider adding CanNotDelete locks on critical resources" -ForegroundColor Gray
        
        $results += [PSCustomObject]@{
            Scope = "Subscription"
            ScopeName = $subscriptionId
            PrincipalName = "N/A"
            PrincipalType = "N/A"
            PrincipalId = "N/A"
            Role = "Resource Lock"
            RiskLevel = "Medium"
            Issue = "No resource locks configured - resources can be accidentally deleted"
        }
    }
    else {
        Write-Host "  [OK] $($locks.Count) resource lock(s) configured" -ForegroundColor Green
    }
    
    # Check PIM eligibility
    Write-Host "`n[PIM Role Eligibility Check]" -ForegroundColor Yellow
    Write-Host "  Note: PIM requires additional permissions to audit via PowerShell" -ForegroundColor Gray
    Write-Host "  Please verify PIM is configured for privileged roles" -ForegroundColor Gray
    
    # Summary
    Write-Host "`n=== RBAC Audit Summary ===" -ForegroundColor Cyan
    $highRisk = ($results | Where-Object { $_.RiskLevel -eq "High" }).Count
    $mediumRisk = ($results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
    
    Write-Host "High Risk: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Risk: $mediumRisk" -ForegroundColor $(if ($mediumRisk -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Total Assignments Analyzed: $($results.Count)" -ForegroundColor Cyan
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Review all high privilege assignments" -ForegroundColor Gray
    Write-Host "  2. Migrate classic administrators to Azure RBAC" -ForegroundColor Gray
    Write-Host "  3. Remove wildcard (*) permissions from custom roles" -ForegroundColor Gray
    Write-Host "  4. Remove orphaned role assignments" -ForegroundColor Gray
    Write-Host "  5. Implement PIM for privileged roles" -ForegroundColor Gray
    Write-Host "  6. Add CanNotDelete locks on critical resources" -ForegroundColor Gray
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "RBAC-Permissions_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "RBAC-Permissions_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== RBAC Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
