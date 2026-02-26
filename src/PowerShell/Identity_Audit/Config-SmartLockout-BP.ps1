# Check Smart Lockout Configuration (Best Practices)
# Prevents DoS by ensuring "Lockout threshold" and "Observation window" are balanced.
# Recommended: Threshold = 10, Duration = 60s (Default is often too high)

Connect-MgGraph -Scopes "Directory.Read.All"

$policy = Get-MgPolicyAuthenticationMethodPolicy

Write-Host "--- Entra ID Smart Lockout Configuration ---" -ForegroundColor Cyan
Write-Host "Lockout Threshold (Failures): $($policy.AuthenticationMethodConfigurations[0].LockoutThreshold)"
Write-Host "Lockout Duration (Seconds):   $($policy.AuthenticationMethodConfigurations[0].LockoutDurationInSeconds)"

if ($policy.AuthenticationMethodConfigurations[0].LockoutThreshold -gt 10) {
    Write-Host "[WARNING] Threshold > 10. High risk of Brute Force success before lockout." -ForegroundColor Yellow
}
if ($policy.AuthenticationMethodConfigurations[0].LockoutDurationInSeconds -gt 300) {
    Write-Host "[WARNING] Duration > 5 mins. High risk of legitimate user DoS." -ForegroundColor Yellow
}
Write-Host "--------------------------------------------"
