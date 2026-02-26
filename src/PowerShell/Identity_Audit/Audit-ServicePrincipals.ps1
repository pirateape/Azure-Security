[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [int]$CredentialExpiryWarningDays = 30
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-ServicePrincipals_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- Service Principals Security Audit ---" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All" -NoWelcome
    
    $results = @()
    $spns = Get-MgServicePrincipal -All -Property "id,appId,displayName,servicePrincipalType,passwordCredentials,keyCredentials,appRoles,oauth2PermissionScopes,accountEnabled"
    
    Write-Host "`n[Service Principals Analysis]" -ForegroundColor Yellow
    Write-Host "Total Service Principals Found: $($spns.Count)" -ForegroundColor Gray
    
    foreach ($spn in $spns) {
        $issues = @()
        $riskLevel = "Low"
        
        if (-not $spn.AccountEnabled) {
            $issues += "Service principal is disabled"
        }
        
        if ($spn.PasswordCredentials) {
            foreach ($secret in $spn.PasswordCredentials) {
                if ($secret.EndDateTime -and [datetime]$secret.EndDateTime -lt (Get-Date)) {
                    $issues += "Expired password credential: $($secret.DisplayName)"
                    $riskLevel = "Critical"
                }
                elseif ($secret.EndDateTime -and [datetime]$secret.EndDateTime -lt (Get-Date).AddDays($CredentialExpiryWarningDays)) {
                    $issues += "Password expiring soon: $($secret.DisplayName) (Expires: $($secret.EndDateTime))"
                    if ($riskLevel -ne "Critical") { $riskLevel = "High" }
                }
                if (-not $secret.DisplayName) {
                    $issues += "Password credential without description"
                    if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
                }
            }
        }
        
        if ($spn.KeyCredentials) {
            foreach ($cert in $spn.KeyCredentials) {
                if ($cert.EndDateTime -and [datetime]$cert.EndDateTime -lt (Get-Date)) {
                    $issues += "Expired certificate: $($cert.DisplayName)"
                    $riskLevel = "Critical"
                }
                elseif ($cert.EndDateTime -and [datetime]$cert.EndDateTime -lt (Get-Date).AddDays($CredentialExpiryWarningDays)) {
                    $issues += "Certificate expiring soon: $($cert.DisplayName)"
                    if ($riskLevel -ne "Critical") { $riskLevel = "High" }
                }
            }
        }
        
        $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spn.Id -ErrorAction SilentlyContinue
        $highPrivRoles = $appRoleAssignments | Where-Object { 
            $_.AppRoleId -in @(
                "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",
                "7b1f7869-5728-4e1e-8a48-7e2fe0a8d947",
                "6e469ea9-5761-4d15-9d7c-52b2d1c4e1e8"
            )
        }
        
        if ($highPrivRoles) {
            $issues += "Has highly privileged app roles"
            $riskLevel = if ($riskLevel -in @("Low", "Medium")) { "High" } else { $riskLevel }
        }
        
        $delegatedPerms = $spn.Oauth2PermissionScopes
        if ($delegatedPerms -and $delegatedPerms.Count -gt 0) {
            $adminConsentPerms = $delegatedPerms | Where-Object { $_.Type -eq "Admin" }
            if ($adminConsentPerms) {
                $issues += "Exposes admin-consent required permissions"
            }
        }
        
        $result = [PSCustomObject]@{
            DisplayName = $spn.DisplayName
            AppId = $spn.AppId
            ObjectId = $spn.Id
            Type = $spn.ServicePrincipalType
            AccountEnabled = $spn.AccountEnabled
            PasswordCredentialCount = $spn.PasswordCredentials.Count
            KeyCredentialCount = $spn.KeyCredentials.Count
            AppRoleCount = $appRoleAssignments.Count
            HasHighPrivRoles = $highPrivRoles.Count -gt 0
            ExposedPermissionCount = $delegatedPerms.Count
            RiskLevel = $riskLevel
            Issues = $issues -join "; "
        }
        
        $results += $result
        
        if ($riskLevel -eq "Critical") {
            Write-Host "[CRITICAL] $($spn.DisplayName) - $($issues -join ', ')" -ForegroundColor Red
        }
        elseif ($riskLevel -eq "High") {
            Write-Host "[HIGH] $($spn.DisplayName) - $($issues -join ', ')" -ForegroundColor Yellow
        }
        elseif ($issues.Count -gt 0) {
            Write-Host "[MEDIUM] $($spn.DisplayName) - $($issues -join ', ')" -ForegroundColor DarkYellow
        }
    }
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "  Total Service Principals: $($spns.Count)"
    Write-Host "  Critical Risk: $(($results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count)" -ForegroundColor Red
    Write-Host "  High Risk: $(($results | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor Yellow
    Write-Host "  Medium Risk: $(($results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count)" -ForegroundColor DarkYellow
    Write-Host "  Disabled: $(($results | Where-Object { -not $_.AccountEnabled }).Count)" -ForegroundColor Gray
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "ServicePrincipals_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "ServicePrincipals_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n--- Service Principals Audit Complete ---" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
