<#
.SYNOPSIS
    Azure Automation Runbook: Scheduled Remediation Task
    
.DESCRIPTION
    This runbook checks for non-compliant Azure Policy assignments and triggers
    remediation tasks for DeployIfNotExists and Modify effects.
    
    Requires: Az.Resources module and System Assigned Managed Identity with 
    Policy Contributor role.
#>

[CmdletBinding()]
param(
    [string]$ResourceGroupName = "",
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

# Connect using Managed Identity
try {
    $null = Connect-AzAccount -Identity -ErrorAction Stop
    Write-Output "Connected using Managed Identity"
}
catch {
    Write-Error "Failed to connect using Managed Identity: $($_.Exception.Message)"
    throw
}

# Get all policy assignments with DeployIfNotExists or Modify effects
Write-Output "Checking for non-compliant policy assignments..."

try {
    $assignments = Get-AzPolicyAssignment -Scope "/subscriptions/$((Get-AzContext).Subscription.Id)"
    
    $remediationCount = 0
    
    foreach ($assignment in $assignments) {
        $policyDefinition = Get-AzPolicyDefinition -Id $assignment.PolicyDefinitionId -ErrorAction SilentlyContinue
        
        if ($policyDefinition) {
            $effect = $policyDefinition.Properties.PolicyRule.then.effect
            
            if ($effect -in @("deployIfNotExists", "modify")) {
                # Check compliance state
                $complianceStates = Get-AzPolicyState -PolicyAssignmentName $assignment.Name -Filter "ComplianceState eq 'NonCompliant'"
                
                if ($complianceStates.Count -gt 0) {
                    Write-Output "Found $($complianceStates.Count) non-compliant resources for policy: $($assignment.Name)"
                    
                    if (-not $WhatIf) {
                        # Create remediation task
                        $remediationName = "AutoRemediation-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$($assignment.Name)"
                        
                        try {
                            $remediation = Start-AzPolicyRemediation `
                                -Name $remediationName `
                                -PolicyAssignmentId $assignment.PolicyAssignmentId `
                                -ResourceDiscoveryMode ReEvaluateCompliance `
                                -ErrorAction Stop
                            
                            Write-Output "Created remediation task: $remediationName"
                            $remediationCount++
                        }
                        catch {
                            Write-Warning "Failed to create remediation task for $($assignment.Name): $($_.Exception.Message)"
                        }
                    }
                    else {
                        Write-Output "[WHATIF] Would create remediation task for: $($assignment.Name)"
                    }
                }
            }
        }
    }
    
    Write-Output "Completed. Total remediation tasks created: $remediationCount"
}
catch {
    Write-Error "Error during remediation check: $($_.Exception.Message)"
    throw
}
