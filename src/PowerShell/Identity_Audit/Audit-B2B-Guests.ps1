[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON,
    [int]$StaleGuestDays = 90
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-B2B-Guests_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- B2B Guest Users & Cross-Tenant Audit ---" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "CrossTenantAccessPolicy.Read.All" -NoWelcome
    
    $results = @()
    
    $guestUsers = Get-MgUser -All -Filter "userType eq 'Guest'" -Property "id,userPrincipalName,displayName,creationType,externalUserState,externalUserStateChangeDateTime,createdDateTime,lastSignInDateTime,accountEnabled"
    
    Write-Host "`n[B2B Guest Users Analysis]" -ForegroundColor Yellow
    Write-Host "Total Guest Users Found: $($guestUsers.Count)" -ForegroundColor Gray
    
    foreach ($guest in $guestUsers) {
        $issues = @()
        $riskLevel = "Low"
        
        if ($guest.ExternalUserState -eq "PendingAcceptance") {
            $issues += "Guest invitation pending acceptance"
            if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
        }
        
        $daysSinceCreated = if ($guest.CreatedDateTime) { [math]::Floor(((Get-Date) - [datetime]$guest.CreatedDateTime).TotalDays) } else { 0 }
        $daysSinceSignIn = if ($guest.SignInActivity.LastSignInDateTime) { [math]::Floor(((Get-Date) - [datetime]$guest.SignInActivity.LastSignInDateTime).TotalDays) } else { $null }
        
        if ($guest.ExternalUserState -eq "Accepted" -and (-not $daysSinceSignIn -or $daysSinceSignIn -gt $StaleGuestDays)) {
            $issues += "Stale guest (no sign-in in $StaleGuestDays+ days or never signed in)"
            if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
        }
        
        if (-not $guest.AccountEnabled) {
            $issues += "Guest account is disabled"
        }
        
        if ($daysSinceCreated -gt 365 -and $guest.ExternalUserState -eq "PendingAcceptance") {
            $issues += "Old pending invitation (over 1 year)"
            $riskLevel = "High"
        }
        
        $result = [PSCustomObject]@{
            DisplayName = $guest.DisplayName
            UserPrincipalName = $guest.UserPrincipalName
            ObjectId = $guest.Id
            ExternalUserState = $guest.ExternalUserState
            AccountEnabled = $guest.AccountEnabled
            CreatedDateTime = $guest.CreatedDateTime
            DaysSinceCreated = $daysSinceCreated
            LastSignInDateTime = $guest.SignInActivity.LastSignInDateTime
            DaysSinceSignIn = $daysSinceSignIn
            RiskLevel = $riskLevel
            Issues = $issues -join "; "
            SourceTenant = ($guest.UserPrincipalName -split '#EXT#|@')[0]
        }
        
        $results += $result
        
        if ($riskLevel -eq "High") {
            Write-Host "[HIGH] $($guest.DisplayName) - $($issues -join ', ')" -ForegroundColor Yellow
        }
        elseif ($issues.Count -gt 0) {
            Write-Host "[MEDIUM] $($guest.DisplayName) - $($issues -join ', ')" -ForegroundColor DarkYellow
        }
    }
    
    Write-Host "`n[Cross-Tenant Access Policies]" -ForegroundColor Yellow
    
    $crossTenantPolicies = Get-MgPolicyCrossTenantAccessPolicy -ErrorAction SilentlyContinue
    
    if ($crossTenantPolicies) {
        Write-Host "  Cross-Tenant Access Policy: Configured" -ForegroundColor Green
        
        $partners = Get-MgPolicyCrossTenantAccessPolicyPartner -All -ErrorAction SilentlyContinue
        
        foreach ($partner in $partners) {
            $tenantInfo = [PSCustomObject]@{
                Type = "CrossTenantPartner"
                PartnerTenantId = $partner.TenantId
                IsInboundAllowed = $partner.InboundTrust -ne $null
                IsOutboundAllowed = $partner.OutboundTrust -ne $null
                RiskLevel = "Info"
                Issues = ""
            }
            $results += $tenantInfo
            Write-Host "  Partner Tenant: $($partner.TenantId)" -ForegroundColor Cyan
        }
    }
    else {
        Write-Host "  [WARNING] Cross-Tenant Access Policy: Not configured" -ForegroundColor Yellow
    }
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "  Total Guest Users: $($guestUsers.Count)"
    Write-Host "  Pending Acceptance: $(($guestUsers | Where-Object { $_.ExternalUserState -eq 'PendingAcceptance' }).Count)" -ForegroundColor Yellow
    Write-Host "  Active Guests: $(($guestUsers | Where-Object { $_.ExternalUserState -eq 'Accepted' -and $_.AccountEnabled }).Count)" -ForegroundColor Green
    Write-Host "  Stale Guests (>90 days): $(($results | Where-Object { $_.Issues -like '*Stale*' }).Count)" -ForegroundColor DarkYellow
    Write-Host "  High Risk: $(($results | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor Red
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "B2B_Guests_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "B2B_Guests_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n--- B2B Guest Audit Complete ---" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
