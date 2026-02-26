# Audit Network Security Groups (NSG) and Public Access
# Checks for:
# 1. NSGs with "Any/Any" Inbound Allow rules (High Risk)
# 2. Public IPs attached directly to VMs (should use Load Balancer/Bastion)
# 3. NSGs without Flow Logs enabled.

Connect-AzAccount -Identity -ErrorAction SilentlyContinue

Write-Host "--- Starting Network Security Audit ---" -ForegroundColor Cyan

# 1. Audit NSGs for Any/Any Allow
$nsgs = Get-AzNetworkSecurityGroup
foreach ($nsg in $nsgs) {
    $riskyRules = $nsg.SecurityRules | Where-Object { 
        $_.Access -eq "Allow" -and 
        $_.Direction -eq "Inbound" -and 
        $_.SourceAddressPrefix -eq "*" -and 
        ($_.DestinationPortRange -eq "*" -or $_.DestinationPortRange -contains "3389" -or $_.DestinationPortRange -contains "22")
    }
    
    if ($riskyRules) {
        Write-Host "[RISK] NSG '$($nsg.Name)' allows open inbound access (SSH/RDP/Any)." -ForegroundColor Red
    }
}

# 2. Public IPs on VMs
$publicIps = Get-AzPublicIpAddress
foreach ($ip in $publicIps) {
    if ($ip.IpConfiguration.Id -match "/virtualMachines/") {
        Write-Host "[WARNING] Public IP '$($ip.Name)' is directly attached to a VM: $($ip.IpConfiguration.Id)" -ForegroundColor Yellow
    }
}

# 3. Flow Logs Check (Simplified)
$watchers = Get-AzNetworkWatcher
if (-not $watchers) {
    Write-Host "[INFO] No Network Watchers found. Flow Logs might not be configured." -ForegroundColor Yellow
}
else {
    Write-Host "[INFO] Network Watchers exist. Ensure Flow Logs are mapped to a Workspace." -ForegroundColor Green
}

Write-Host "--- Audit Complete ---"
