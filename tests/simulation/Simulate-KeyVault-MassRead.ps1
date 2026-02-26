# Simulate Key Vault Mass Read (Attack Simulation)
# Iterates through all secrets in a Key Vault and reads them.
# Goal: Trigger "Insider Risk" or "Mass Secret Retrieval" detections.

param(
    [Parameter(Mandatory = $true)]
    [string]$KeyVaultName
)

Connect-AzAccount -ErrorAction SilentlyContinue

Write-Host "Starting Mass Secret Retrieval Simulation on $KeyVaultName..." -ForegroundColor Yellow

$secrets = Get-AzKeyVaultSecret -VaultName $KeyVaultName
$count = 0

foreach ($secret in $secrets) {
    $count++
    Write-Host "Reading Secret $($count): $($secret.Name)" -ForegroundColor Gray
    
    # The act of "Getting" the secret value generates the audit log
    $null = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $secret.Name
    
    # Artificial delay to mimic a specialized tool vs script
    Start-Sleep -Milliseconds 200
}

Write-Host "Simulation Complete. Read $count secrets. Check Sentinel in ~5-10 minutes." -ForegroundColor Green
