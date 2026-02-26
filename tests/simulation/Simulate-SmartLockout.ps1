# Simulate Smart Lockout (Attack Simulation)
# Generates failed login attempts to trigger Smart Lockout detection.
# WARNING: Run this against a TEST USER only. Do NOT run against production accounts.

param(
    [Parameter(Mandatory = $true)]
    [string]$TargetUserPrincipalName
)

Write-Host "Starting Smart Lockout Simulation against $TargetUserPrincipalName..." -ForegroundColor Yellow
Write-Host "This will generate 10 failed login attempts."

for ($i = 1; $i -le 10; $i++) {
    try {
        # Attempt login with a definitely wrong password
        $pass = ConvertTo-SecureString "WrongPass$i!" -AsPlainText -Force
        $creds = New-Object System.Management.Automation.PSCredential($TargetUserPrincipalName, $pass)
        
        # This cmdlet doesn't actually log in to Azure, but sends auth request. 
        # Using Connect-AzAccount might prompt interactive. 
        # For simulation, we can use a simple web request to an Azure endpoint if we want "network" traffic,
        # but for Entra logs, we actually need to hit the IDP.
        # Simplest way that generates a sign-in log entry:
        Connect-AzAccount -Credential $creds -ServicePrincipal -TenantId "00000000-0000-0000-0000-000000000000" -ErrorAction SilentlyContinue
    }
    catch {
        Write-Host "Attempt ${i}: Failed (Expected)" -ForegroundColor Gray
    }
    Start-Sleep -Seconds 1
}

Write-Host "Simulation Complete. Check Sentinel/Entra ID Sign-in Logs in ~5 minutes." -ForegroundColor Green
