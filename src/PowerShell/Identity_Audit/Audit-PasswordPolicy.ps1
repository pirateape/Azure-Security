[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-PasswordPolicy_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Password Policy & Security Settings Audit ===" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "Policy.Read.All", "Directory.Read.All", "User.Read.All" -NoWelcome
    
    $results = @()
    
    # Get password policies
    Write-Host "`n[Password Policies]" -ForegroundColor Yellow
    
    # Get tenant password policy
    $domain = Get-MgDomain -All | Select-Object -First 1
    $passwordPolicy = $domain.PasswordValidityPeriodInDays
    $passwordNotificationWindow = $domain.PasswordNotificationWindowInDays
    
    Write-Host "  Password Validity Period: $passwordPolicy days" -ForegroundColor $(if ($passwordPolicy -eq "2147483647") { "Green" } else { "Yellow" })
    Write-Host "  Password Notification Window: $passwordNotificationWindow days" -ForegroundColor Cyan
    
    $results += [PSCustomObject]@{
        CheckType = "PasswordValidity"
        Setting = "Password Expiration"
        Value = if ($passwordPolicy -eq "2147483647") { "Never Expires (Recommended)" } else { "$passwordPolicy days" }
        RiskLevel = if ($passwordPolicy -ne "2147483647" -and $passwordPolicy -lt 90) { "Medium" } else { "Low" }
        Recommendation = "Passwords should not expire (NIST guidance)"
    }
    
    # Check if password expiration is enabled (legacy)
    if ($passwordPolicy -ne "2147483647") {
        Write-Host "  [WARNING] Password expiration is enabled - not recommended per NIST" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [OK] Passwords set to never expire (modern approach)" -ForegroundColor Green
    }
    
    # Get authentication methods policy
    Write-Host "`n[Authentication Methods Policy]" -ForegroundColor Yellow
    $authMethodsPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue
    
    if ($authMethodsPolicy) {
        Write-Host "  Policy Migration State: $($authMethodsPolicy.PolicyMigrationState)" -ForegroundColor Cyan
        
        # Check self-service password reset
        $ssprEnabled = $authMethodsPolicy.PolicyMigrationState -eq "MigrationComplete" -or 
                      $authMethodsPolicy.RegistrationEnforcement.RegistrationCampaign.State -eq "Enabled"
        
        if ($ssprEnabled) {
            Write-Host "  [OK] Modern authentication methods policy enabled" -ForegroundColor Green
        }
        else {
            Write-Host "  [WARNING] Legacy authentication methods may be in use" -ForegroundColor Yellow
        }
    }
    
    # Check password protection
    Write-Host "`n[Password Protection Settings]" -ForegroundColor Yellow
    try {
        $directorySettings = Get-MgDirectorySetting | Where-Object { $_.DisplayName -eq "Password Rule Settings" }
        
        if ($directorySettings) {
            $banPassword = ($directorySettings.Values | Where-Object { $_.Name -eq "BannedPasswordList" }).Value
            $enablePasswordProtection = ($directorySettings.Values | Where-Object { $_.Name -eq "EnableBannedPasswordCheck" }).Value
            
            Write-Host "  Password Protection: $enablePasswordProtection" -ForegroundColor $(if ($enablePasswordProtection -eq $true) { "Green" } else { "Yellow" })
            
            $results += [PSCustomObject]@{
                CheckType = "PasswordProtection"
                Setting = "Banned Password Check"
                Value = $enablePasswordProtection
                RiskLevel = if ($enablePasswordProtection -ne $true) { "High" } else { "Low" }
                Recommendation = "Enable banned password protection"
            }
        }
        else {
            Write-Host "  [WARNING] Password protection settings not configured" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [INFO] Unable to retrieve password protection settings" -ForegroundColor Gray
    }
    
    # Check user password policies
    Write-Host "`n[User Password Policies]" -ForegroundColor Yellow
    $users = Get-MgUser -All -Property "id,userPrincipalName,passwordPolicies,passwordProfile"
    
    $passwordNeverExpires = $users | Where-Object { $_.PasswordPolicies -contains "DisablePasswordExpiration" }
    $forceChangePassword = $users | Where-Object { $_.PasswordProfile.ForceChangePasswordNextSignIn -eq $true }
    
    Write-Host "  Users with non-expiring passwords: $($passwordNeverExpires.Count)" -ForegroundColor $(if ($passwordNeverExpires.Count -eq 0) { "Green" } else { "Yellow" })
    Write-Host "  Users requiring password change: $($forceChangePassword.Count)" -ForegroundColor $(if ($forceChangePassword.Count -eq 0) { "Green" } else { "Yellow" })
    
    $results += [PSCustomObject]@{
        CheckType = "PasswordExpiration"
        Setting = "Users with Non-Expiring Passwords"
        Value = $passwordNeverExpires.Count
        RiskLevel = if ($passwordNeverExpires.Count -gt 10) { "Medium" } else { "Low" }
        Recommendation = "Review users with non-expiring passwords"
    }
    
    if ($passwordNeverExpires.Count -gt 0) {
        Write-Host "`n  Users with non-expiring passwords:" -ForegroundColor Yellow
        $passwordNeverExpires | Select-Object -First 10 | ForEach-Object {
            Write-Host "    - $($_.UserPrincipalName)" -ForegroundColor Gray
        }
    }
    
    # Check for weak/reused passwords via sign-in logs (recent failures)
    Write-Host "`n[Recent Password Failures]" -ForegroundColor Yellow
    try {
        $signIns = Get-MgAuditLogSignIn -Top 100 -Filter "status/errorCode eq 50126" -ErrorAction SilentlyContinue
        
        if ($signIns) {
            $failedPasswordAttempts = $signIns | Group-Object UserPrincipalName | Sort-Object Count -Descending | Select-Object -First 10
            
            if ($failedPasswordAttempts.Count -gt 0) {
                Write-Host "  Users with recent password failures:" -ForegroundColor Yellow
                $failedPasswordAttempts | ForEach-Object {
                    Write-Host "    - $($_.Name): $($_.Count) failures" -ForegroundColor Yellow
                }
            }
        }
    }
    catch {
        Write-Host "  [INFO] Unable to retrieve sign-in logs" -ForegroundColor Gray
    }
    
    # Check MFA methods
    Write-Host "`n[MFA Method Analysis]" -ForegroundColor Yellow
    $usersSample = $users | Where-Object { $_.AccountEnabled } | Select-Object -First 50
    
    $smsUsers = 0
    $voiceUsers = 0
    $totpUsers = 0
    $noMFA = 0
    
    foreach ($user in $usersSample) {
        try {
            $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
            
            $hasSMS = $authMethods | Where-Object { $_.AdditionalProperties.'@odata.type' -match "phoneAuthenticationMethod" }
            $hasTOTP = $authMethods | Where-Object { $_.AdditionalProperties.'@odata.type' -match "softwareOathAuthenticationMethod" }
            
            if ($hasSMS) { $smsUsers++ }
            if ($hasTOTP) { $totpUsers++ }
            if (-not $authMethods -or $authMethods.Count -eq 0) { $noMFA++ }
        }
        catch {
            # Ignore errors
        }
    }
    
    if ($usersSample.Count -gt 0) {
        $smsPercentage = [math]::Round(($smsUsers / $usersSample.Count) * 100, 1)
        Write-Host "  SMS-based MFA (sample): $smsUsers/$($usersSample.Count) ($smsPercentage%)" -ForegroundColor $(if ($smsPercentage -gt 50) { "Yellow" } else { "Green" })
        
        $results += [PSCustomObject]@{
            CheckType = "MFAMethods"
            Setting = "SMS-based MFA Users (sample)"
            Value = "$smsPercentage%"
            RiskLevel = if ($smsPercentage -gt 50) { "Medium" } else { "Low" }
            Recommendation = "Encourage stronger MFA methods (Authenticator, FIDO2)"
        }
    }
    
    # Summary
    Write-Host "`n=== Password Policy Summary ===" -ForegroundColor Cyan
    Write-Host "Password Expiration: $(if ($passwordPolicy -eq "2147483647") { "Never (Good)" } else { "$passwordPolicy days" })" -ForegroundColor $(if ($passwordPolicy -eq "2147483647") { "Green" } else { "Yellow" })
    Write-Host "Non-Expiring Password Users: $($passwordNeverExpires.Count)" -ForegroundColor Yellow
    Write-Host "Force Password Change: $($forceChangePassword.Count)" -ForegroundColor $(if ($forceChangePassword.Count -eq 0) { "Green" } else { "Yellow" })
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "PasswordPolicy_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "PasswordPolicy_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== Password Policy Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
