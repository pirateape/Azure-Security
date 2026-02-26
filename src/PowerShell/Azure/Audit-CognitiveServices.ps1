[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-CognitiveServices_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- Azure Cognitive Services Security Audit ---" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Host "Az.Accounts module required. Please install it." -ForegroundColor Red
        return
    }
    if (-not (Get-Module -ListAvailable -Name Az.CognitiveServices)) {
        Write-Host "Az.CognitiveServices module required. Please install it." -ForegroundColor Red
        return
    }

    # Ensure connected to Azure
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "Please connect to Azure using Connect-AzAccount first." -ForegroundColor Yellow
        return
    }
    
    $results = @()
    $services = Get-AzCognitiveServicesAccount
    
    Write-Host "`n[Cognitive Services Analysis]" -ForegroundColor Yellow
    Write-Host "Total Services Found: $($services.Count)" -ForegroundColor Gray
    
    foreach ($service in $services) {
        $issues = @()
        $riskLevel = "Low"
        
        # 1. Public Network Access Check
        if ($service.PublicNetworkAccess -ne "Disabled") {
            $issues += "Public Network Access is Enabled"
            $riskLevel = "High"
        }

        # 2. Local Authentication (Access Keys) Check
        if ($service.DisableLocalAuth -ne $true) {
            $issues += "Local Authentication (Access Keys) is Enabled"
            if ($riskLevel -ne "High") { $riskLevel = "Medium" }
        }

        # 3. Private Endpoint Connections Check
        $peCount = 0
        if ($service.PrivateEndpointConnections) {
            $peCount = $service.PrivateEndpointConnections.Count
        }
        if ($peCount -eq 0) {
            $issues += "No Private Endpoints configured"
            if ($riskLevel -eq "Low") { $riskLevel = "Medium" }
        }

        $result = [PSCustomObject]@{
            Name                 = $service.AccountName
            ResourceGroupName    = $service.ResourceGroupName
            Location             = $service.Location
            Kind                 = $service.Kind
            Sku                  = $service.SkuName
            PublicNetworkAccess  = $service.PublicNetworkAccess
            DisableLocalAuth     = $service.DisableLocalAuth -eq $true
            PrivateEndpointCount = $peCount
            RiskLevel            = $riskLevel
            Issues               = $issues -join "; "
        }
        
        $results += $result
        
        if ($riskLevel -eq "Critical") {
            Write-Host "[CRITICAL] $($service.AccountName) - $($issues -join ', ')" -ForegroundColor Red
        }
        elseif ($riskLevel -eq "High") {
            Write-Host "[HIGH] $($service.AccountName) - $($issues -join ', ')" -ForegroundColor Yellow
        }
        elseif ($issues.Count -gt 0) {
            Write-Host "[MEDIUM] $($service.AccountName) - $($issues -join ', ')" -ForegroundColor DarkYellow
        }
    }
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "  Total Services: $($services.Count)"
    Write-Host "  Critical Risk: $(($results | Where-Object { $_.RiskLevel -eq 'Critical' }).Count)" -ForegroundColor Red
    Write-Host "  High Risk: $(($results | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor Yellow
    Write-Host "  Medium Risk: $(($results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count)" -ForegroundColor DarkYellow
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "CognitiveServices_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "CognitiveServices_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n--- Cognitive Services Audit Complete ---" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
