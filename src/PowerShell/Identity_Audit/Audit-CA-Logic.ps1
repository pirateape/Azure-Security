[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [switch]$Detailed
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-CA-Logic_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== Conditional Access Policy Logic Analyzer ===" -ForegroundColor Cyan
    Write-Host "Analyzing CA policies for security gaps and logic issues...`n" -ForegroundColor Gray
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "Policy.Read.All", "Group.Read.All", "User.Read.All", "RoleManagement.Read.Directory", "Directory.Read.All" -NoWelcome
    
    $results = @()
    $criticalFindings = @()
    $warningFindings = @()
    $infoFindings = @()
    
    # Get all CA policies
    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All
    $enabledPolicies = $caPolicies | Where-Object { $_.State -eq "enabled" }
    $allUsers = Get-MgUser -All -Property "id,userPrincipalName,assignedLicenses"
    $allGroups = Get-MgGroup -All
    $directoryRoles = Get-MgDirectoryRole -All
    
    Write-Host "Environment Overview:" -ForegroundColor Yellow
    Write-Host "  Total CA Policies: $($caPolicies.Count)" -ForegroundColor Cyan
    Write-Host "  Enabled Policies: $($enabledPolicies.Count)" -ForegroundColor Cyan
    Write-Host "  Total Users: $($allUsers.Count)" -ForegroundColor Cyan
    Write-Host "  Total Groups: $($allGroups.Count)" -ForegroundColor Cyan
    Write-Host ""
    
    # Check 1: Are there ANY enabled policies?
    if ($enabledPolicies.Count -eq 0) {
        $criticalFindings += "CRITICAL: No enabled Conditional Access policies found!"
        Write-Host "[CRITICAL] No enabled CA policies! Tenant is unprotected!" -ForegroundColor Red
    }
    
    # Check 2: MFA Enforcement
    Write-Host "[Check 1/10] MFA Enforcement Analysis..." -ForegroundColor Yellow
    $mfaPolicies = $enabledPolicies | Where-Object {
        $_.GrantControls.BuiltInControls -contains "mfa" -or
        $_.GrantControls.AuthenticationStrength.RequirementType -eq "mfa"
    }
    
    if ($mfaPolicies.Count -eq 0) {
        $criticalFindings += "CRITICAL: No CA policy enforces MFA!"
        Write-Host "  [CRITICAL] No CA policy requires MFA" -ForegroundColor Red
    }
    else {
        Write-Host "  [OK] $($mfaPolicies.Count) policies enforce MFA" -ForegroundColor Green
        
        # Check if MFA covers All Users or just specific groups
        $mfaAllUsers = $mfaPolicies | Where-Object {
            $_.Conditions.Users.IncludeUsers -contains "All"
        }
        
        if ($mfaAllUsers.Count -eq 0) {
            $warningFindings += "WARNING: MFA policies don't cover All Users - some users may not be protected"
            Write-Host "  [WARNING] MFA policies don't cover All Users" -ForegroundColor Yellow
        }
    }
    
    # Check 3: Legacy Authentication Blocking
    Write-Host "`n[Check 2/10] Legacy Authentication Blocking..." -ForegroundColor Yellow
    $legacyAuthPolicies = $enabledPolicies | Where-Object {
        $_.Conditions.ClientAppTypes -contains "other" -and
        $_.GrantControls.BuiltInControls -contains "block"
    }
    
    if ($legacyAuthPolicies.Count -eq 0) {
        $criticalFindings += "CRITICAL: No CA policy blocks legacy authentication!"
        Write-Host "  [CRITICAL] Legacy auth (Basic, IMAP, POP3) is NOT blocked!" -ForegroundColor Red
    }
    else {
        Write-Host "  [OK] Legacy auth is blocked by $($legacyAuthPolicies.Count) policy(s)" -ForegroundColor Green
    }
    
    # Check 4: Admin Protection
    Write-Host "`n[Check 3/10] Administrator Role Protection..." -ForegroundColor Yellow
    $adminRoles = @("Global Administrator", "Privileged Role Administrator", "Security Administrator", "Exchange Administrator", "SharePoint Administrator", "User Administrator")
    $adminProtected = $false
    
    foreach ($policy in $enabledPolicies) {
        $includedRoles = $policy.Conditions.Users.IncludeRoles
        if ($includedRoles) {
            foreach ($role in $adminRoles) {
                $roleId = ($directoryRoles | Where-Object { $_.DisplayName -eq $role }).RoleTemplateId
                if ($roleId -in $includedRoles) {
                    $adminProtected = $true
                    break
                }
            }
        }
        if ($adminProtected) { break }
    }
    
    if (-not $adminProtected) {
        $criticalFindings += "CRITICAL: No CA policy specifically targets administrator roles!"
        Write-Host "  [CRITICAL] Admin roles are NOT protected by CA policies!" -ForegroundColor Red
    }
    else {
        Write-Host "  [OK] Admin roles are protected by CA policies" -ForegroundColor Green
    }
    
    # Check 5: Break-Glass Accounts
    Write-Host "`n[Check 4/10] Break-Glass Account Exclusions..." -ForegroundColor Yellow
    $breakGlassAccounts = $allUsers | Where-Object { 
        $_.UserPrincipalName -match "breakglass|break.glass|emergency|bg-" -or
        $_.DisplayName -match "Break Glass|Emergency Access"
    }
    
    if ($breakGlassAccounts.Count -eq 0) {
        $warningFindings += "WARNING: No break-glass accounts found - recommended to have emergency access"
        Write-Host "  [WARNING] No break-glass accounts detected" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [INFO] Found $($breakGlassAccounts.Count) potential break-glass accounts" -ForegroundColor Cyan
        
        # Check if break-glass accounts are excluded from policies
        $bgExcludedCount = 0
        foreach ($account in $breakGlassAccounts) {
            $excludedInPolicies = $enabledPolicies | Where-Object {
                $_.Conditions.Users.ExcludeUsers -contains $account.Id
            }
            if ($excludedInPolicies.Count -gt 0) {
                $bgExcludedCount++
            }
        }
        
        if ($bgExcludedCount -eq 0) {
            $warningFindings += "WARNING: Break-glass accounts are NOT excluded from CA policies - may be locked out during emergency"
            Write-Host "  [WARNING] Break-glass accounts not excluded from CA policies!" -ForegroundColor Yellow
        }
        else {
            Write-Host "  [OK] Break-glass accounts properly excluded" -ForegroundColor Green
        }
    }
    
    # Check 6: Policies Without Conditions
    Write-Host "`n[Check 5/10] Policies Without Conditions..." -ForegroundColor Yellow
    $noConditionPolicies = $enabledPolicies | Where-Object {
        ($_.Conditions.Users.IncludeUsers -contains "All" -or $_.Conditions.Users.IncludeGroups -eq $null) -and
        $_.Conditions.Applications.IncludeApplications -contains "All" -and
        $_.Conditions.Locations.IncludeLocations -contains "All" -and
        ($_.Conditions.Platforms.IncludePlatforms -eq $null -or $_.Conditions.Platforms.IncludePlatforms -contains "All")
    }
    
    if ($noConditionPolicies.Count -gt 0) {
        $infoFindings += "INFO: $($noConditionPolicies.Count) policies apply to ALL scenarios - review for necessity"
        Write-Host "  [INFO] $($noConditionPolicies.Count) policies have no specific conditions (apply to All)" -ForegroundColor Cyan
        foreach ($policy in $noConditionPolicies) {
            Write-Host "    - $($policy.DisplayName)" -ForegroundColor Gray
        }
    }
    
    # Check 7: Risk-Based Policies
    Write-Host "`n[Check 6/10] Risk-Based Protection..." -ForegroundColor Yellow
    $riskPolicies = $enabledPolicies | Where-Object {
        $_.Conditions.UserRiskLevels -or $_.Conditions.SignInRiskLevels
    }
    
    if ($riskPolicies.Count -eq 0) {
        $warningFindings += "WARNING: No risk-based CA policies - recommend enabling Identity Protection integration"
        Write-Host "  [WARNING] No risk-based policies configured!" -ForegroundColor Yellow
        Write-Host "    Consider: User Risk (leaked credentials), Sign-in Risk (anonymous IP, impossible travel)" -ForegroundColor Gray
    }
    else {
        Write-Host "  [OK] $($riskPolicies.Count) risk-based policies found" -ForegroundColor Green
        foreach ($policy in $riskPolicies) {
            $riskTypes = @()
            if ($policy.Conditions.UserRiskLevels) { $riskTypes += "UserRisk" }
            if ($policy.Conditions.SignInRiskLevels) { $riskTypes += "SignInRisk" }
            Write-Host "    - $($policy.DisplayName) [$($riskTypes -join ', ')]" -ForegroundColor Gray
        }
    }
    
    # Check 8: Device Compliance
    Write-Host "`n[Check 7/10] Device Compliance Enforcement..." -ForegroundColor Yellow
    $deviceCompliancePolicies = $enabledPolicies | Where-Object {
        $_.GrantControls.BuiltInControls -contains "compliantDevice" -or
        $_.GrantControls.BuiltInControls -contains "domainJoinedDevice"
    }
    
    if ($deviceCompliancePolicies.Count -eq 0) {
        $warningFindings += "WARNING: No CA policy requires device compliance - unmanaged devices may access resources"
        Write-Host "  [WARNING] No device compliance policies!" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [OK] $($deviceCompliancePolicies.Count) policies enforce device compliance" -ForegroundColor Green
    }
    
    # Check 9: Named Locations
    Write-Host "`n[Check 8/10] Named Locations and Geo-blocking..." -ForegroundColor Yellow
    $namedLocations = Get-MgIdentityConditionalAccessNamedLocation -All
    
    if ($namedLocations.Count -eq 0) {
        $infoFindings += "INFO: No Named Locations defined - cannot geo-block specific countries"
        Write-Host "  [INFO] No Named Locations configured" -ForegroundColor Cyan
    }
    else {
        Write-Host "  [OK] $($namedLocations.Count) Named Locations configured" -ForegroundColor Green
        
        # Check if any policies use named locations
        $locationPolicies = $enabledPolicies | Where-Object {
            $_.Conditions.Locations.ExcludeLocations -or $_.Conditions.Locations.IncludeLocations
        }
        
        if ($locationPolicies.Count -eq 0) {
            $warningFindings += "WARNING: Named Locations exist but not used in any CA policies"
            Write-Host "  [WARNING] Named Locations exist but not used in CA policies!" -ForegroundColor Yellow
        }
    }
    
    # Check 10: Session Controls
    Write-Host "`n[Check 9/10] Session Controls..." -ForegroundColor Yellow
    $sessionControlPolicies = $enabledPolicies | Where-Object {
        $_.SessionControls.ApplicationEnforcedRestrictions -or
        $_.SessionControls.CloudAppSecurity -or
        $_.SessionControls.SignInFrequency -or
        $_.SessionControls.PersistentBrowser
    }
    
    if ($sessionControlPolicies.Count -eq 0) {
        $infoFindings += "INFO: No session control policies - consider sign-in frequency and persistent browser settings"
        Write-Host "  [INFO] No session control policies" -ForegroundColor Cyan
    }
    else {
        Write-Host "  [OK] $($sessionControlPolicies.Count) policies use session controls" -ForegroundColor Green
    }
    
    # Check 11: App Protection
    Write-Host "`n[Check 10/10] Application Protection..." -ForegroundColor Yellow
    $allAppsPolicy = $enabledPolicies | Where-Object {
        $_.Conditions.Applications.IncludeApplications -contains "All"
    }
    
    $specificAppsPolicy = $enabledPolicies | Where-Object {
        $_.Conditions.Applications.IncludeApplications -notcontains "All" -and
        $_.Conditions.Applications.IncludeApplications.Count -gt 0
    }
    
    if ($allAppsPolicy.Count -eq 0 -and $specificAppsPolicy.Count -eq 0) {
        $warningFindings += "WARNING: No CA policies target applications - all apps may be unprotected"
        Write-Host "  [WARNING] No application-specific CA policies!" -ForegroundColor Yellow
    }
    elseif ($allAppsPolicy.Count -eq 0) {
        Write-Host "  [INFO] Only specific apps are protected - verify all critical apps are covered" -ForegroundColor Cyan
    }
    else {
        Write-Host "  [OK] Policies exist that cover all applications" -ForegroundColor Green
    }
    
    # Check 12: Guest User Protection
    Write-Host "`n[Bonus Check] Guest User Protection..." -ForegroundColor Yellow
    $guestPolicies = $enabledPolicies | Where-Object {
        $_.Conditions.Users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes -contains "guest" -or
        $_.Conditions.Users.IncludeGuestsOrExternalUsers.GuestOrExternalUserTypes -contains "externalGuest"
    }
    
    if ($guestPolicies.Count -eq 0) {
        $warningFindings += "WARNING: No CA policies specifically target guest/external users"
        Write-Host "  [WARNING] Guest users may not be properly protected!" -ForegroundColor Yellow
    }
    else {
        Write-Host "  [OK] Guest user policies found" -ForegroundColor Green
    }
    
    # Generate Report
    Write-Host "`n=== CA Logic Analysis Summary ===" -ForegroundColor Cyan
    Write-Host "Critical Findings: $($criticalFindings.Count)" -ForegroundColor $(if ($criticalFindings.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "Warnings: $($warningFindings.Count)" -ForegroundColor $(if ($warningFindings.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Informational: $($infoFindings.Count)" -ForegroundColor Cyan
    
    # Build results object
    $results = [PSCustomObject]@{
        AnalysisDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalPolicies = $caPolicies.Count
        EnabledPolicies = $enabledPolicies.Count
        TotalUsers = $allUsers.Count
        TotalGroups = $allGroups.Count
        CriticalFindings = $criticalFindings
        WarningFindings = $warningFindings
        InformationalFindings = $infoFindings
        MfaPolicies = $mfaPolicies.Count
        LegacyAuthBlocked = $legacyAuthPolicies.Count -gt 0
        AdminProtected = $adminProtected
        RiskBasedPolicies = $riskPolicies.Count
        DeviceCompliancePolicies = $deviceCompliancePolicies.Count
        NamedLocations = $namedLocations.Count
        BreakGlassAccounts = $breakGlassAccounts.Count
        BreakGlassExcluded = $bgExcludedCount
    }
    
    if ($Detailed) {
        Write-Host "`n=== Detailed Findings ===" -ForegroundColor Cyan
        
        if ($criticalFindings.Count -gt 0) {
            Write-Host "`nCRITICAL:" -ForegroundColor Red
            $criticalFindings | ForEach-Object { Write-Host "  • $_" -ForegroundColor Red }
        }
        
        if ($warningFindings.Count -gt 0) {
            Write-Host "`nWARNINGS:" -ForegroundColor Yellow
            $warningFindings | ForEach-Object { Write-Host "  • $_" -ForegroundColor Yellow }
        }
        
        if ($infoFindings.Count -gt 0) {
            Write-Host "`nINFORMATIONAL:" -ForegroundColor Cyan
            $infoFindings | ForEach-Object { Write-Host "  • $_" -ForegroundColor Cyan }
        }
    }
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "CA-Logic_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        
        # Create detailed CSV rows
        $csvData = @()
        
        foreach ($policy in $enabledPolicies) {
            $row = [PSCustomObject]@{
                PolicyName = $policy.DisplayName
                State = $policy.State
                CreatedDateTime = $policy.CreatedDateTime
                ModifiedDateTime = $policy.ModifiedDateTime
                IncludeUsers = ($policy.Conditions.Users.IncludeUsers -join ";")
                ExcludeUsers = ($policy.Conditions.Users.ExcludeUsers -join ";")
                IncludeGroups = ($policy.Conditions.Users.IncludeGroups -join ";")
                ExcludeGroups = ($policy.Conditions.Users.ExcludeGroups -join ";")
                IncludeRoles = ($policy.Conditions.Users.IncludeRoles -join ";")
                IncludeApps = ($policy.Conditions.Applications.IncludeApplications -join ";")
                GrantControls = ($policy.GrantControls.BuiltInControls -join ";")
                HasMFA = $policy.GrantControls.BuiltInControls -contains "mfa"
                HasDeviceCompliance = $policy.GrantControls.BuiltInControls -contains "compliantDevice"
                BlocksLegacyAuth = ($policy.Conditions.ClientAppTypes -contains "other") -and ($policy.GrantControls.BuiltInControls -contains "block")
                HasRiskConditions = ($policy.Conditions.UserRiskLevels -or $policy.Conditions.SignInRiskLevels)
                HasSessionControls = ($policy.SessionControls.ApplicationEnforcedRestrictions -or $policy.SessionControls.SignInFrequency)
            }
            $csvData += $row
        }
        
        $csvData | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] Detailed policy CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "CA-Logic_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON report saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== CA Logic Analysis Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
