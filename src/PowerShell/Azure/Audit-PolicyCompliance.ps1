[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-PolicyCompliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Azure Policy Compliance Audit ===" -ForegroundColor Cyan
    
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
    
    Write-Host "`n[Fetching Policy Compliance States]" -ForegroundColor Yellow
    Write-Host "  Retrieving non-compliant resources (this may take a moment)..." -ForegroundColor Gray
    
    # Fetch latest policy states where compliance state is NonCompliant
    $nonCompliantStates = Get-AzPolicyState -Filter "IsCompliant eq false" -ErrorAction SilentlyContinue
    
    if (-not $nonCompliantStates) {
        Write-Host "  No Non-Compliant resources found or policy states could not be retrieved." -ForegroundColor Green
    }
    else {
        Write-Host "  Non-Compliant Records Found: $($nonCompliantStates.Count)" -ForegroundColor Cyan
         
        # Group by Policy Definition
        $groupedByPolicy = $nonCompliantStates | Group-Object PolicyDefinitionName
         
        foreach ($policyGrp in $groupedByPolicy) {
            # Get policy details to show display name
            $policyDef = Get-AzPolicyDefinition -Name $policyGrp.Name -ErrorAction SilentlyContinue
            $displayName = if ($policyDef) { $policyDef.Properties.DisplayName } else { $policyGrp.Name }
             
            Write-Host "`n  Policy: $displayName" -ForegroundColor Yellow
            Write-Host "    Non-Compliant Resources: $($policyGrp.Count)" -ForegroundColor Red
             
            foreach ($record in $policyGrp.Group) {
                # output limit logic for console
                Write-Host "    - Resource: $($record.ResourceId.Split('/')[-1])" -ForegroundColor Gray
                 
                $results += [PSCustomObject]@{
                    CheckType            = "PolicyNonCompliance"
                    PolicyAssignmentName = $record.PolicyAssignmentName
                    PolicyDefinitionName = $record.PolicyDefinitionName
                    PolicyDisplayName    = $displayName
                    ResourceId           = $record.ResourceId
                    ResourceType         = $record.ResourceType
                    ComplianceState      = $record.ComplianceState
                }
            }
        }
    }
    
    # Summary
    Write-Host "`n=== Policy Compliance Summary ===" -ForegroundColor Cyan
    
    Write-Host "Total Non-Compliant Resources: $(if ($nonCompliantStates) { $nonCompliantStates.Count } else { 0 })" -ForegroundColor $(if ($nonCompliantStates.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "Unique Policies Violated: $(if ($groupedByPolicy) { $groupedByPolicy.Count } else { 0 })" -ForegroundColor Cyan
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Review the generated reports to identify frequently violated policies." -ForegroundColor Gray
    Write-Host "  2. Assign remediation tasks or DeployIfNotExists configurations to automate compliance." -ForegroundColor Gray
    Write-Host "  3. Focus on Microsoft Cloud Security Benchmark initiatives first." -ForegroundColor Gray
    
    # Export
    if ($results.Count -gt 0) {
        if ($ExportCSV) {
            $csvPath = Join-Path $OutputPath "PolicyCompliance-Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $results | Export-Csv -Path $csvPath -NoTypeInformation
            Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
        }
        
        if ($ExportJSON) {
            $jsonPath = Join-Path $OutputPath "PolicyCompliance-Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
            $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
            Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
        }
    }
    
    Write-Host "`n=== Azure Policy Audit Complete ===" -ForegroundColor Cyan
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
