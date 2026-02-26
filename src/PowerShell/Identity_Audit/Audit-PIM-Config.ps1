[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-PIM_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- Entra ID PIM Configuration Audit ---" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "RoleEligibilitySchedule.Read.Directory", "PrivilegedAccess.Read.AzureResources" -NoWelcome
    
    $results = @()
    
    $roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All
    
    $eligibleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty "principal,roleDefinition"
    
    Write-Host "`n[Eligible Role Assignments]" -ForegroundColor Yellow
    
    foreach ($assignment in $eligibleAssignments) {
        $principal = Get-MgDirectoryObject -DirectoryObjectId $assignment.PrincipalId -ErrorAction SilentlyContinue
        $role = $roleDefinitions | Where-Object { $_.Id -eq $assignment.RoleDefinitionId }
        
        $result = [PSCustomObject]@{
            Type = "EligibleAssignment"
            PrincipalId = $assignment.PrincipalId
            PrincipalName = $principal.AdditionalProperties.userPrincipalName
            PrincipalType = $assignment.Principal.AdditionalProperties.'@odata.type' -replace '#microsoft.graph.'
            RoleName = $role.DisplayName
            RoleId = $assignment.RoleDefinitionId
            StartDateTime = $assignment.StartDateTime
            EndDateTime = $assignment.EndDateTime
            MemberType = $assignment.MemberType
            Status = if ($assignment.EndDateTime -and [datetime]$assignment.EndDateTime -lt (Get-Date)) { "Expired" } else { "Active" }
            RiskLevel = if ($role.DisplayName -match "Global Admin|Security Admin|Exchange Admin|SharePoint Admin") { "High" } elseif ($role.DisplayName -match "User Admin|Helpdesk") { "Medium" } else { "Low" }
        }
        
        $results += $result
        
        if ($result.RiskLevel -eq "High") {
            Write-Host "[HIGH RISK] $($result.PrincipalName) - $($result.RoleName)" -ForegroundColor Red
        }
        else {
            Write-Host "[OK] $($result.PrincipalName) - $($result.RoleName)" -ForegroundColor Green
        }
    }
    
    Write-Host "`n[PIM Settings Audit]" -ForegroundColor Yellow
    
    $pimPolicy = Get-MgPolicyRoleManagementPolicyAssignment -UnifiedRoleManagementPolicyAssignmentId "DirectoryRole_d27607e3-48d6-4ca8-89b1-1ff7a4a1f1ff_8" -ExpandProperty "policy" -ErrorAction SilentlyContinue
    
    if ($pimPolicy) {
        Write-Host "  PIM Policy Found: $($pimPolicy.Policy.DisplayName)" -ForegroundColor Green
    }
    else {
        Write-Host "  [WARNING] Unable to retrieve PIM policy details" -ForegroundColor Yellow
    }
    
    Write-Host "`n[Permanent Role Assignments - Non-PIM]" -ForegroundColor Yellow
    
    $allRoleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All
    $permanentAssignments = $allRoleAssignments | Where-Object { 
        $_.RoleDefinitionId -ne (Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq 'Global Administrator'").Id -or
        $_.PrincipalId -notin $eligibleAssignments.PrincipalId
    }
    
    foreach ($perm in $permanentAssignments) {
        $principal = Get-MgDirectoryObject -DirectoryObjectId $perm.PrincipalId -ErrorAction SilentlyContinue
        $role = $roleDefinitions | Where-Object { $_.Id -eq $perm.RoleDefinitionId }
        
        if ($principal -and $role) {
            $result = [PSCustomObject]@{
                Type = "PermanentAssignment"
                PrincipalId = $perm.PrincipalId
                PrincipalName = $principal.AdditionalProperties.userPrincipalName
                PrincipalType = "User"
                RoleName = $role.DisplayName
                RoleId = $perm.RoleDefinitionId
                StartDateTime = $null
                EndDateTime = "Permanent"
                MemberType = "Direct"
                Status = "Permanent"
                RiskLevel = if ($role.DisplayName -match "Global Admin|Security Admin") { "Critical" } elseif ($role.DisplayName -match "User Admin|Helpdesk") { "High" } else { "Medium" }
            }
            
            $results += $result
            
            if ($result.RiskLevel -eq "Critical") {
                Write-Host "[CRITICAL] Permanent: $($result.PrincipalName) - $($result.RoleName)" -ForegroundColor Red
            }
        }
    }
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "  Total Eligible Assignments: $(($results | Where-Object { $_.Type -eq 'EligibleAssignment' }).Count)"
    Write-Host "  Total Permanent Assignments: $(($results | Where-Object { $_.Type -eq 'PermanentAssignment' }).Count)"
    Write-Host "  High/Critical Risk: $(($results | Where-Object { $_.RiskLevel -in @('High', 'Critical') }).Count)"
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "PIM_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "PIM_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n--- PIM Audit Complete ---" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
