<#
.SYNOPSIS
    Azure Automation Runbook: NSG Rule Cleanup
    
.DESCRIPTION
    This runbook identifies and optionally removes overly permissive NSG rules
    that allow inbound traffic from the internet on management ports (RDP/SSH).
    
    Requires: Az.Network module and System Assigned Managed Identity with 
    Network Contributor role.
#>

[CmdletBinding()]
param(
    [switch]$AutoRemove,
    [string[]]$ProtectedNSGs = @()
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

# Risky ports to check
$riskyPorts = @(22, 3389)
$riskyPrefixes = @("*", "Internet", "0.0.0.0/0")

$violationsFound = 0

# Get all NSGs
$nsgs = Get-AzNetworkSecurityGroup

foreach ($nsg in $nsgs) {
    if ($nsg.Name -in $ProtectedNSGs) {
        Write-Output "Skipping protected NSG: $($nsg.Name)"
        continue
    }
    
    $riskyRules = $nsg.SecurityRules | Where-Object {
        $_.Access -eq "Allow" -and
        $_.Direction -eq "Inbound" -and
        $_.SourceAddressPrefix -in $riskyPrefixes -and
        ($_.DestinationPortRange -in $riskyPorts -or 
         ($_.DestinationPortRanges | Where-Object { $_ -in $riskyPorts }).Count -gt 0)
    }
    
    foreach ($rule in $riskyRules) {
        $violationsFound++
        
        $message = @"
CRITICAL: Risky NSG Rule Found!
NSG: $($nsg.Name) in $($nsg.ResourceGroupName)
Rule: $($rule.Name)
Priority: $($rule.Priority)
Port: $($rule.DestinationPortRange -join ', ')
Source: $($rule.SourceAddressPrefix -join ', ')
"@
        
        Write-Output $message
        
        if ($AutoRemove) {
            try {
                Remove-AzNetworkSecurityRuleConfig `
                    -Name $rule.Name `
                    -NetworkSecurityGroup $nsg | Out-Null
                
                $nsg | Set-AzNetworkSecurityGroup | Out-Null
                Write-Output "REMOVED rule: $($rule.Name) from NSG: $($nsg.Name)"
            }
            catch {
                Write-Warning "Failed to remove rule: $($_.Exception.Message)"
            }
        }
    }
}

if ($violationsFound -eq 0) {
    Write-Output "No risky NSG rules found. All clear!"
}
else {
    Write-Output "Total violations found: $violationsFound"
    if (-not $AutoRemove) {
        Write-Output "Use -AutoRemove switch to automatically delete these rules."
    }
}
