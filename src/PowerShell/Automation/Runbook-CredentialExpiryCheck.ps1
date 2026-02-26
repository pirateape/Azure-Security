<#
.SYNOPSIS
    Azure Automation Runbook: Expired Credential Notification
    
.DESCRIPTION
    This runbook checks for expired or expiring credentials (secrets/certificates)
    in App Registrations and sends notifications.
    
    Requires: Microsoft.Graph module and System Assigned Managed Identity with
    Application.Read.All permission.
#>

[CmdletBinding()]
param(
    [int]$ExpiryWarningDays = 30,
    [string]$NotificationEmail = "security@contoso.com"
)

$ErrorActionPreference = "Stop"

# Install and import Microsoft Graph module if needed
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

Import-Module Microsoft.Graph

# Connect using Managed Identity
try {
    Connect-MgGraph -Identity -ErrorAction Stop
    Write-Output "Connected to Microsoft Graph using Managed Identity"
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    throw
}

$expiredCredentials = @()
$expiringCredentials = @()

# Get all app registrations
$apps = Get-MgApplication -All -Property "id,appId,displayName,passwordCredentials,keyCredentials"

foreach ($app in $apps) {
    # Check password credentials (secrets)
    foreach ($secret in $app.PasswordCredentials) {
        $daysUntilExpiry = if ($secret.EndDateTime) { [math]::Floor((([datetime]$secret.EndDateTime) - (Get-Date)).TotalDays) } else { $null }
        
        if ($daysUntilExpiry -lt 0) {
            $expiredCredentials += [PSCustomObject]@{
                AppName = $app.DisplayName
                AppId = $app.AppId
                CredentialType = "Secret"
                CredentialName = $secret.DisplayName
                ExpiredDaysAgo = [math]::Abs($daysUntilExpiry)
                ExpiryDate = $secret.EndDateTime
            }
        }
        elseif ($daysUntilExpiry -le $ExpiryWarningDays) {
            $expiringCredentials += [PSCustomObject]@{
                AppName = $app.DisplayName
                AppId = $app.AppId
                CredentialType = "Secret"
                CredentialName = $secret.DisplayName
                DaysUntilExpiry = $daysUntilExpiry
                ExpiryDate = $secret.EndDateTime
            }
        }
    }
    
    # Check key credentials (certificates)
    foreach ($cert in $app.KeyCredentials) {
        $daysUntilExpiry = if ($cert.EndDateTime) { [math]::Floor((([datetime]$cert.EndDateTime) - (Get-Date)).TotalDays) } else { $null }
        
        if ($daysUntilExpiry -lt 0) {
            $expiredCredentials += [PSCustomObject]@{
                AppName = $app.DisplayName
                AppId = $app.AppId
                CredentialType = "Certificate"
                CredentialName = $cert.DisplayName
                ExpiredDaysAgo = [math]::Abs($daysUntilExpiry)
                ExpiryDate = $cert.EndDateTime
            }
        }
        elseif ($daysUntilExpiry -le $ExpiryWarningDays) {
            $expiringCredentials += [PSCustomObject]@{
                AppName = $app.DisplayName
                AppId = $app.AppId
                CredentialType = "Certificate"
                CredentialName = $cert.DisplayName
                DaysUntilExpiry = $daysUntilExpiry
                ExpiryDate = $cert.EndDateTime
            }
        }
    }
}

# Output summary
Write-Output "`nCredential Audit Summary:"
Write-Output "Expired Credentials: $($expiredCredentials.Count)"
Write-Output "Expiring Soon (within $ExpiryWarningDays days): $($expiringCredentials.Count)"

if ($expiredCredentials.Count -gt 0) {
    Write-Output "`nEXPIRED CREDENTIALS:"
    $expiredCredentials | Format-Table -AutoSize | Out-String | Write-Output
}

if ($expiringCredentials.Count -gt 0) {
    Write-Output "`nEXPIRING CREDENTIALS:"
    $expiringCredentials | Format-Table -AutoSize | Out-String | Write-Output
}

# Note: Actual email notification would require additional configuration
# with SendGrid, Office 365, or other email service
Write-Output "`nNotification would be sent to: $NotificationEmail"

Disconnect-MgGraph | Out-Null
