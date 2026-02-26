[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [int]$SecretExpiryWarningDays = 30
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-AppRegistrations_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- App Registrations Security Audit ---" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All" -NoWelcome
    
    $results = @()
    $apps = Get-MgApplication -All -Property "id,appId,displayName,signInAudience,passwordCredentials,keyCredentials,federatedIdentityCredentials,requiredResourceAccess,createdDateTime,deletedDateTime"
    
    Write-Host "`n[App Registrations Analysis]" -ForegroundColor Yellow
    Write-Host "Total Apps Found: $($apps.Count)" -ForegroundColor Gray
    
    $highRiskPermissions = @(
        "RoleManagement.ReadWrite.Directory",
        "AppRoleAssignment.ReadWrite.All",
        "Application.ReadWrite.All",
        "Directory.ReadWrite.All",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Mail.ReadWrite",
        "Mail.Send",
        "Files.ReadWrite.All",
        "Sites.ReadWrite.All"
    )
    
    foreach ($app in $apps) {
        $issues = @()
        $riskLevel = "Low"
        
        if ($app.PasswordCredentials) {
            foreach ($secret in $app.PasswordCredentials) {
                if ($secret.EndDateTime -and [datetime]$secret.EndDateTime -lt (Get-Date)) {
                    $issues += "Expired secret: $($secret.DisplayName)"
                    $riskLevel = "Critical"
                }
                elseif ($secret.EndDateTime -and [datetime]$secret.EndDateTime -lt (Get-Date).AddDays($SecretExpiryWarningDays)) {
                    $issues += "Secret expiring soon: $($secret.DisplayName) (Expires: $($secret.EndDateTime))"
                    if ($riskLevel -ne "Critical") { $riskLevel = "High" }
                }
                if (-not $secret.DisplayName) {
                    $issues += "Secret without description"
                    if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
                }
            }
        }
        
        if ($app.KeyCredentials) {
            foreach ($cert in $app.KeyCredentials) {
                if ($cert.EndDateTime -and [datetime]$cert.EndDateTime -lt (Get-Date)) {
                    $issues += "Expired certificate: $($cert.DisplayName)"
                    $riskLevel = "Critical"
                }
                elseif ($cert.EndDateTime -and [datetime]$cert.EndDateTime -lt (Get-Date).AddDays($SecretExpiryWarningDays)) {
                    $issues += "Certificate expiring soon: $($cert.DisplayName)"
                    if ($riskLevel -ne "Critical") { $riskLevel = "High" }
                }
            }
        }
        
        $federatedCreds = Get-MgApplicationFederatedIdentityCredential -ApplicationId $app.Id -ErrorAction SilentlyContinue 
        if ($federatedCreds) {
            $issues += "Uses Federated Identity Credentials ($($federatedCreds.Count))"
            if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
            
            foreach ($fic in $federatedCreds) {
                if ($fic.Subject -match "\*") {
                    $issues += "Federated credential has wildcard subject: $($fic.Name)"
                    if ($riskLevel -ne "Critical") { $riskLevel = "High" }
                }
            }
        }
        
        $dangerousPerms = @()
        if ($app.RequiredResourceAccess) {
            foreach ($resource in $app.RequiredResourceAccess) {
                foreach ($perm in $resource.ResourceAccess) {
                    if ($perm.Type -eq "Role") {
                        $dangerousPerms += $perm.Id
                    }
                }
            }
        }
        
        if ($dangerousPerms.Count -gt 0) {
            $issues += "Has $($dangerousPerms.Count) application permissions (high privilege)"
            if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
        }
        
        if ($app.SignInAudience -eq "AzureADMultipleOrgs" -or $app.SignInAudience -eq "AzureADandPersonalMicrosoftAccount") {
            $issues += "Multi-tenant application: $($app.SignInAudience)"
            if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
        }
        
        $age = (Get-Date) - $app.CreatedDateTime
        if ($age.Days -gt 365 -and $app.PasswordCredentials.Count -eq 0 -and $app.KeyCredentials.Count -eq 0) {
            $issues += "Unused app (old, no credentials)"
            if ($riskLevel -eq "Low") { $riskLevel = "Low" }
        }
        
        $result = [PSCustomObject]@{
            AppName                   = $app.DisplayName
            AppId                     = $app.AppId
            ObjectId                  = $app.Id
            SignInAudience            = $app.SignInAudience
            SecretCount               = $app.PasswordCredentials.Count
            CertificateCount          = $app.KeyCredentials.Count
            FederatedCredentialCount  = $federatedCreds.Count
            HasApplicationPermissions = $dangerousPerms.Count -gt 0
            PermissionCount           = $dangerousPerms.Count
            CreatedDate               = $app.CreatedDateTime
            AgeDays                   = [math]::Floor($age.TotalDays)
            RiskLevel                 = $riskLevel
            Issues                    = $issues -join "; "
        }
        
        $results += $result
        
        if ($riskLevel -eq "Critical") {
            Write-Host "[CRITICAL] $($app.DisplayName) - $($issues -join ', ')" -ForegroundColor Red
        }
        elseif ($riskLevel -eq "High") {
            Write-Host "[HIGH] $($app.DisplayName) - $($issues -join ', ')" -ForegroundColor Yellow
        }
        elseif ($issues.Count -gt 0) {
            Write-Host "[MEDIUM] $($app.DisplayName) - $($issues -join ', ')" -ForegroundColor DarkYellow
        }
    }
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "  Total Apps: $($apps.Count)"
    Write-Host "  Critical Risk: $(($results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count)" -ForegroundColor Red
    Write-Host "  High Risk: $(($results | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor Yellow
    Write-Host "  Medium Risk: $(($results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count)" -ForegroundColor DarkYellow
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "AppRegistrations_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "AppRegistrations_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n--- App Registrations Audit Complete ---" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
