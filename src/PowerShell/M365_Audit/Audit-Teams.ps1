[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/M365",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-Teams_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- Microsoft Teams Security Audit ---" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
        Install-Module MicrosoftTeams -Scope CurrentUser -Force
    }
    
    Connect-MicrosoftTeams | Out-Null
    
    $results = @()
    
    Write-Host "`n[Teams Tenant Settings]" -ForegroundColor Yellow
    $csTeamsClientConfiguration = Get-CsTeamsClientConfiguration
    
    if ($csTeamsClientConfiguration.AllowGuestUser -eq $true) {
        Write-Host "[INFO] Guest access enabled in Teams" -ForegroundColor Cyan
        $results += [PSCustomObject]@{
            Category = "TenantSettings"
            Setting = "Guest Access"
            Value = "Enabled"
            RiskLevel = "Medium"
            Issues = "Guest users can access Teams"
        }
    }
    
    if ($csTeamsClientConfiguration.AllowEmailIntoChannel -eq $true) {
        Write-Host "[MEDIUM] Email into channel enabled" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            Category = "TenantSettings"
            Setting = "Email Into Channel"
            Value = "Enabled"
            RiskLevel = "Medium"
            Issues = "External emails can be sent to channels"
        }
    }
    
    Write-Host "`n[External Access Settings]" -ForegroundColor Yellow
    $csExternalAccessPolicy = Get-CsExternalAccessPolicy -Identity Global
    
    if ($csExternalAccessPolicy.EnableFederationAccess -eq $true) {
        Write-Host "[INFO] Federation with external domains enabled" -ForegroundColor Cyan
        $results += [PSCustomObject]@{
            Category = "ExternalAccess"
            Setting = "Federation"
            Value = "Enabled"
            RiskLevel = "Medium"
            Issues = "Can communicate with external Teams orgs"
        }
    }
    
    if ($csExternalAccessPolicy.EnablePublicCloudAccess -eq $true) {
        Write-Host "[MEDIUM] Public cloud (Skype) access enabled" -ForegroundColor Yellow
        $results += [PSCustomObject]@{
            Category = "ExternalAccess"
            Setting = "Skype Connectivity"
            Value = "Enabled"
            RiskLevel = "Medium"
            Issues = "Can communicate with Skype users"
        }
    }
    
    $allowedDomains = Get-CsAllowedDomain
    $blockedDomains = Get-CsBlockedDomain
    
    if ($allowedDomains.Count -eq 0 -and $csExternalAccessPolicy.EnableFederationAccess -eq $true) {
        Write-Host "[HIGH] Federation enabled but no domain restrictions!" -ForegroundColor Red
        $results += [PSCustomObject]@{
            Category = "ExternalAccess"
            Setting = "Domain Restrictions"
            Value = "None"
            RiskLevel = "High"
            Issues = "All external domains allowed"
        }
    }
    else {
        Write-Host "[OK] $($allowedDomains.Count) allowed domains configured" -ForegroundColor Green
    }
    
    Write-Host "`n[Guest Access Policies]" -ForegroundColor Yellow
    $csTeamsGuestCallingConfiguration = Get-CsTeamsGuestCallingConfiguration -ErrorAction SilentlyContinue
    $csTeamsGuestMeetingConfiguration = Get-CsTeamsGuestMeetingConfiguration -ErrorAction SilentlyContinue
    
    if ($csTeamsGuestCallingConfiguration -and $csTeamsGuestCallingConfiguration.AllowPrivateCalling -eq $true) {
        Write-Host "[INFO] Guests can make private calls" -ForegroundColor Cyan
        $results += [PSCustomObject]@{
            Category = "GuestAccess"
            Setting = "Guest Private Calling"
            Value = "Enabled"
            RiskLevel = "Low"
            Issues = ""
        }
    }
    
    if ($csTeamsGuestMeetingConfiguration) {
        if ($csTeamsGuestMeetingConfiguration.AllowIPVideo -eq $true) {
            Write-Host "[INFO] Guests can share video" -ForegroundColor Cyan
        }
        if ($csTeamsGuestMeetingConfiguration.ScreenSharingMode -eq "EntireScreen") {
            Write-Host "[MEDIUM] Guests can share entire screen" -ForegroundColor Yellow
            $results += [PSCustomObject]@{
                Category = "GuestAccess"
                Setting = "Guest Screen Sharing"
                Value = "EntireScreen"
                RiskLevel = "Medium"
                Issues = "Guests can share full screen"
            }
        }
    }
    
    Write-Host "`n[Meeting Policies]" -ForegroundColor Yellow
    $meetingPolicies = Get-CsTeamsMeetingPolicy
    
    foreach ($policy in $meetingPolicies | Where-Object { $_.Identity -in @("Global", "Tag:Default") }) {
        $issues = @()
        
        if ($policy.AllowExternalParticipantGiveRequestControl -eq $true) {
            $issues += "External participants can give control"
        }
        if ($policy.AllowPowerPointSharing -eq $false) {
            $issues += "PowerPoint sharing disabled"
        }
        if ($policy.AllowWhiteboard -eq $true -and $policy.Identity -eq "Global") {
            $issues += "Whiteboard enabled globally"
        }
        if ($policy.RecordingMode -eq "AlwaysOn") {
            $issues += "Always recording (privacy concern)"
        }
        
        $results += [PSCustomObject]@{
            Category = "MeetingPolicy"
            Setting = $policy.Identity
            Value = "Active"
            RiskLevel = if ($issues.Count -gt 0) { "Medium" } else { "Low" }
            Issues = $issues -join "; "
        }
    }
    
    Write-Host "`n[File Sharing Settings]" -ForegroundColor Yellow
    $spoSharing = Get-SPOTenant -ErrorAction SilentlyContinue
    
    if ($spoSharing) {
        $results += [PSCustomObject]@{
            Category = "FileSharing"
            Setting = "Default Sharing Link Type"
            Value = $spoSharing.DefaultSharingLinkType
            RiskLevel = if ($spoSharing.DefaultSharingLinkType -eq "AnonymousAccess") { "High" } else { "Low" }
            Issues = ""
        }
        
        $results += [PSCustomObject]@{
            Category = "FileSharing"
            Setting = "External User Expiration"
            Value = if ($spoSharing.SharingCapability -eq "ExternalUserAndGuestSharing") { "Enabled" } else { "Restricted" }
            RiskLevel = if ($spoSharing.SharingCapability -eq "ExternalUserAndGuestSharing") { "Medium" } else { "Low" }
            Issues = ""
        }
    }
    
    Write-Host "`n[Teams with External Sharing]" -ForegroundColor Yellow
    $teams = Get-Team | Select-Object -First 100
    
    foreach ($team in $teams) {
        $teamInfo = Get-Team -GroupId $team.GroupId
        $guestSettings = $teamInfo.GuestSettings
        
        if ($guestSettings.AllowCreateUpdateChannels -eq $true) {
            $results += [PSCustomObject]@{
                Category = "TeamSettings"
                Setting = "Guest Channel Creation"
                Value = $team.DisplayName
                RiskLevel = "Medium"
                Issues = "Guests can create channels"
            }
        }
    }
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "  Teams Analyzed: $($teams.Count)"
    Write-Host "  High Risk Settings: $(($results | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor Red
    Write-Host "  Medium Risk Settings: $(($results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count)" -ForegroundColor Yellow
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "Teams_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "Teams_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n--- Teams Audit Complete ---" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue
    Stop-Transcript
}

return $results
