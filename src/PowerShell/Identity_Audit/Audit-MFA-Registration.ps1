[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [switch]$IncludeDetails
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-MFA-Registration_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== MFA Registration & Authentication Methods Audit ===" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "User.Read.All", "UserAuthenticationMethod.Read.All", "Policy.Read.All" -NoWelcome
    
    $results = @()
    
    # Get Authentication Methods Policy
    Write-Host "`n[Authentication Methods Policy]" -ForegroundColor Yellow
    $authMethodsPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue
    
    if ($authMethodsPolicy) {
        Write-Host "  Policy State: $($authMethodsPolicy.PolicyMigrationState)" -ForegroundColor Cyan
        
        # Check MFA registration campaign
        $registrationCampaign = $authMethodsPolicy.RegistrationEnforcement.RegistrationCampaign
        if ($registrationCampaign) {
            Write-Host "  Registration Campaign: $($registrationCampaign.State)" -ForegroundColor $(if ($registrationCampaign.State -eq "Enabled") { "Green" } else { "Yellow" })
        }
    }
    
    # Get all users
    Write-Host "`n[Analyzing User MFA Status...]" -ForegroundColor Yellow
    $users = Get-MgUser -All -Property "id,userPrincipalName,displayName,accountEnabled,signInActivity"
    
    $totalUsers = $users.Count
    $enabledUsers = ($users | Where-Object { $_.AccountEnabled }).Count
    $disabledUsers = ($users | Where-Object { -not $_.AccountEnabled }).Count
    
    Write-Host "  Total Users: $totalUsers" -ForegroundColor Cyan
    Write-Host "  Enabled: $enabledUsers" -ForegroundColor Green
    Write-Host "  Disabled: $disabledUsers" -ForegroundColor Gray
    
    $mfaRegistered = 0
    $mfaNotRegistered = 0
    $strongAuthMethods = 0
    $weakAuthMethods = 0
    $noAuthMethods = 0
    
    $counter = 0
    foreach ($user in $users | Where-Object { $_.AccountEnabled }) {
        $counter++
        if ($counter % 100 -eq 0) {
            Write-Host "  Progress: $counter/$enabledUsers users analyzed..." -ForegroundColor Gray
        }
        
        try {
            # Get authentication methods for user
            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
            
            $hasMFA = $false
            $hasStrongAuth = $false
            $authMethodTypes = @()
            
            if ($authMethods) {
                foreach ($method in $authMethods) {
                    $methodType = $method.AdditionalProperties.'@odata.type'
                    $authMethodTypes += $methodType
                    
                    switch -Regex ($methodType) {
                        "microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { 
                            $hasMFA = $true
                            $hasStrongAuth = $true
                        }
                        "microsoft.graph.phoneAuthenticationMethod" {
                            $hasMFA = $true
                        }
                        "microsoft.graph.fido2AuthenticationMethod" {
                            $hasMFA = $true
                            $hasStrongAuth = $true
                        }
                        "microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
                            $hasMFA = $true
                            $hasStrongAuth = $true
                        }
                        "microsoft.graph.softwareOathAuthenticationMethod" {
                            $hasMFA = $true
                            $hasStrongAuth = $true
                        }
                        "microsoft.graph.passwordAuthenticationMethod" {
                            # Just password
                        }
                        "microsoft.graph.emailAuthenticationMethod" {
                            # Email - not strong
                        }
                    }
                }
            }
            
            if ($hasMFA) {
                $mfaRegistered++
                if ($hasStrongAuth) {
                    $strongAuthMethods++
                }
                else {
                    $weakAuthMethods++
                }
            }
            else {
                $mfaNotRegistered++
                if ($authMethodTypes.Count -eq 0 -or ($authMethodTypes.Count -eq 1 -and $authMethodTypes[0] -match "passwordAuthenticationMethod")) {
                    $noAuthMethods++
                }
            }
            
            $lastSignIn = $user.SignInActivity.LastSignInDateTime
            $daysSinceSignIn = if ($lastSignIn) { [math]::Floor(((Get-Date) - [datetime]$lastSignIn).TotalDays) } else { $null }
            
            $result = [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                AccountEnabled = $user.AccountEnabled
                HasMFA = $hasMFA
                HasStrongAuth = $hasStrongAuth
                AuthMethods = ($authMethodTypes -join ";")
                MethodCount = $authMethods.Count
                LastSignInDateTime = $lastSignIn
                DaysSinceSignIn = $daysSinceSignIn
                RiskLevel = if (-not $hasMFA) { "High" } elseif (-not $hasStrongAuth) { "Medium" } else { "Low" }
            }
            
            $results += $result
            
            if ($IncludeDetails) {
                if (-not $hasMFA) {
                    Write-Host "  [HIGH] $($user.UserPrincipalName) - No MFA registered" -ForegroundColor Red
                }
                elseif (-not $hasStrongAuth) {
                    Write-Host "  [MEDIUM] $($user.UserPrincipalName) - Weak MFA (SMS/Voice only)" -ForegroundColor Yellow
                }
            }
        }
        catch {
            Write-Warning "  Could not retrieve auth methods for $($user.UserPrincipalName): $($_.Exception.Message)"
            $results += [PSCustomObject]@{
                UserPrincipalName = $user.UserPrincipalName
                DisplayName = $user.DisplayName
                AccountEnabled = $user.AccountEnabled
                HasMFA = $null
                HasStrongAuth = $null
                AuthMethods = "Error retrieving"
                MethodCount = 0
                LastSignInDateTime = $null
                DaysSinceSignIn = $null
                RiskLevel = "Unknown"
            }
        }
    }
    
    # Summary
    Write-Host "`n=== MFA Registration Summary ===" -ForegroundColor Cyan
    Write-Host "MFA Registered: $mfaRegistered" -ForegroundColor Green
    Write-Host "  - Strong Methods (Authenticator/FIDO2/Windows Hello): $strongAuthMethods" -ForegroundColor Green
    Write-Host "  - Weak Methods (SMS/Voice only): $weakAuthMethods" -ForegroundColor Yellow
    Write-Host "No MFA: $mfaNotRegistered" -ForegroundColor $(if ($mfaNotRegistered -gt 0) { "Red" } else { "Green" })
    Write-Host "  - No Methods Registered: $noAuthMethods" -ForegroundColor Red
    
    $mfaCoverage = if ($enabledUsers -gt 0) { [math]::Round(($mfaRegistered / $enabledUsers) * 100, 1) } else { 0 }
    Write-Host "`nMFA Coverage: $mfaCoverage%" -ForegroundColor $(if ($mfaCoverage -ge 90) { "Green" } elseif ($mfaCoverage -ge 70) { "Yellow" } else { "Red" })
    
    # Findings
    if ($mfaCoverage -lt 100) {
        Write-Host "`n[WARNING] Not all users have MFA registered!" -ForegroundColor Yellow
        
        if ($mfaNotRegistered -gt 0) {
            $noMfaUsers = $results | Where-Object { $_.HasMFA -eq $false -and $_.AccountEnabled -eq $true } | Select-Object -First 10
            Write-Host "`nUsers without MFA (first 10):" -ForegroundColor Yellow
            $noMfaUsers | ForEach-Object { Write-Host "  - $($_.UserPrincipalName)" -ForegroundColor Red }
        }
    }
    
    # Admin check
    Write-Host "`n[Checking Admin MFA Status...]" -ForegroundColor Yellow
    $adminRoleIds = @(
        "62e90394-69f5-4237-9190-012177145e10", # Global Admin
        "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Admin
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", # SharePoint Admin
        "29232cdf-9323-42fd-ade2-1d097af3e4de", # Exchange Admin
        "fe930be7-5e62-47db-91af-98c3a49a38b1"  # User Admin
    )
    
    $adminsWithoutMFA = @()
    foreach ($roleId in $adminRoleIds) {
        try {
            $roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $roleId -ErrorAction SilentlyContinue
            foreach ($member in $roleMembers) {
                $user = $users | Where-Object { $_.Id -eq $member.Id }
                if ($user) {
                    $userResult = $results | Where-Object { $_.UserPrincipalName -eq $user.UserPrincipalName }
                    if ($userResult -and -not $userResult.HasMFA) {
                        $adminsWithoutMFA += $user.UserPrincipalName
                    }
                }
            }
        }
        catch {
            # Role may not exist
        }
    }
    
    if ($adminsWithoutMFA.Count -gt 0) {
        Write-Host "[CRITICAL] Admins without MFA:" -ForegroundColor Red
        $adminsWithoutMFA | Select-Object -Unique | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    }
    else {
        Write-Host "[OK] All admins have MFA registered" -ForegroundColor Green
    }
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "MFA-Registration_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "MFA-Registration_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== MFA Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
