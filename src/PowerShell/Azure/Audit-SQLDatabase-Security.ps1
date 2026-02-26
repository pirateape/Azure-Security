[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Azure",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-SQLDatabase-Security_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "=== SQL Database & Managed Instance Security Audit ===" -ForegroundColor Cyan
    
    # Connect to Azure
    $connected = $false
    try {
        $context = Get-AzContext
        if ($context) { $connected = $true }
    }
    catch { $connected = $false }
    
    if (-not $connected) {
        try {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
            Write-Host "[OK] Connected using Managed Identity" -ForegroundColor Green
        }
        catch {
            Connect-AzAccount | Out-Null
            Write-Host "[OK] Connected using interactive login" -ForegroundColor Green
        }
    }
    
    $results = @()
    
    Write-Host "`n[Azure SQL Servers]" -ForegroundColor Yellow
    $sqlServers = Get-AzSqlServer
    Write-Host "  SQL Servers Found: $($sqlServers.Count)" -ForegroundColor Cyan
    
    foreach ($server in $sqlServers) {
        Write-Host "`n  Server: $($server.ServerName)" -ForegroundColor Cyan
        
        # Check public network access
        $publicAccess = $server.PublicNetworkAccess
        Write-Host "    Public Network Access: $publicAccess" -ForegroundColor $(if ($publicAccess -eq 'Disabled') { 'Green' } else { 'Red' })
        
        # Check Azure AD admin
        $adAdmin = Get-AzSqlServerActiveDirectoryAdministrator -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
        if ($adAdmin) {
            Write-Host "    Azure AD Admin: $($adAdmin.DisplayName)" -ForegroundColor Green
        }
        else {
            Write-Host "    [WARNING] No Azure AD Administrator configured!" -ForegroundColor Red
        }
        
        # Check auditing
        $auditing = Get-AzSqlServerAudit -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
        if ($auditing.BlobAuditState -eq 'Enabled' -or $auditing.LogAnalyticsTargetState -eq 'Enabled' -or $auditing.EventHubTargetState -eq 'Enabled') {
            Write-Host "    Auditing: ENABLED" -ForegroundColor Green
        }
        else {
            Write-Host "    [WARNING] Auditing NOT enabled!" -ForegroundColor Red
        }
        
        # Check threat detection
        $threatDetection = Get-AzSqlServerAdvancedThreatProtectionSetting -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
        Write-Host "    Advanced Threat Protection: $($threatDetection.ThreatDetectionState)" -ForegroundColor $(if ($threatDetection.ThreatDetectionState -eq 'Enabled') { 'Green' } else { 'Yellow' })
        
        # Check for SQL Vulnerability Assessment
        $vaSettings = Get-AzSqlServerVulnerabilityAssessmentSetting -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue
        Write-Host "    Vulnerability Assessment: $(if ($vaSettings) { 'CONFIGURED' } else { 'NOT CONFIGURED' })" -ForegroundColor $(if ($vaSettings) { 'Green' } else { 'Yellow' })
        
        # Check firewall rules
        $firewallRules = Get-AzSqlServerFirewallRule -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName
        $openRules = $firewallRules | Where-Object { $_.StartIpAddress -eq '0.0.0.0' -and $_.EndIpAddress -eq '255.255.255.255' }
        
        Write-Host "    Firewall Rules: $($firewallRules.Count)" -ForegroundColor Gray
        if ($openRules) {
            Write-Host "    [CRITICAL] Open firewall rules found (0.0.0.0 - 255.255.255.255)!" -ForegroundColor Red
        }
        
        # Check databases on this server
        $databases = Get-AzSqlDatabase -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName | Where-Object { $_.DatabaseName -ne 'master' }
        Write-Host "    Databases: $($databases.Count)" -ForegroundColor Gray
        
        $results += [PSCustomObject]@{
            CheckType = "SqlServer"
            ServerName = $server.ServerName
            ResourceGroup = $server.ResourceGroupName
            Location = $server.Location
            PublicNetworkAccess = $publicAccess
            AdAdminConfigured = ($null -ne $adAdmin)
            AuditingEnabled = ($auditing.BlobAuditState -eq 'Enabled' -or $auditing.LogAnalyticsTargetState -eq 'Enabled')
            ThreatProtectionEnabled = ($threatDetection.ThreatDetectionState -eq 'Enabled')
            VulnerabilityAssessmentConfigured = ($null -ne $vaSettings)
            OpenFirewallRules = $openRules.Count
            DatabaseCount = $databases.Count
            RiskLevel = if ($publicAccess -eq 'Enabled' -or $openRules.Count -gt 0) { 'High' } elseif (-not $adAdmin -or -not $auditing) { 'Medium' } else { 'Low' }
            Issues = @() | ForEach-Object {
                if ($publicAccess -eq 'Enabled') { $_ += "Public network access enabled" }
                if (-not $adAdmin) { $_ += "No Azure AD admin" }
                if (-not ($auditing.BlobAuditState -eq 'Enabled')) { $_ += "Auditing not enabled" }
                if ($openRules.Count -gt 0) { $_ += "Open firewall rules" }
                $_ -join "; "
            }
        }
        
        # Check TDE (Transparent Data Encryption)
        foreach ($db in $databases | Select-Object -First 5) {
            $tde = Get-AzSqlDatabaseTransparentDataEncryption -ServerName $server.ServerName -DatabaseName $db.DatabaseName -ResourceGroupName $server.ResourceGroupName
            if ($tde.State -ne 'Enabled') {
                Write-Host "    [WARNING] Database '$($db.DatabaseName)' - TDE $($tde.State)" -ForegroundColor Yellow
            }
        }
        
        # Check for private endpoints
        $privateEndpoints = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $server.ResourceId -ErrorAction SilentlyContinue
        if (-not $privateEndpoints) {
            Write-Host "    [WARNING] No private endpoints configured" -ForegroundColor Yellow
        }
        else {
            Write-Host "    [OK] Private endpoints configured" -ForegroundColor Green
        }
    }
    
    # Check for SQL Managed Instances
    Write-Host "`n[SQL Managed Instances]" -ForegroundColor Yellow
    $managedInstances = Get-AzSqlInstance -ErrorAction SilentlyContinue
    
    if ($managedInstances) {
        Write-Host "  Managed Instances: $($managedInstances.Count)" -ForegroundColor Cyan
        
        foreach ($mi in $managedInstances) {
            Write-Host "  Instance: $($mi.InstanceName)" -ForegroundColor Cyan
            Write-Host "    Proxy Override: $($mi.ProxyOverride)" -ForegroundColor Gray
            Write-Host "    Public Data Endpoint: $($mi.PublicDataEndpointEnabled)" -ForegroundColor $(if ($mi.PublicDataEndpointEnabled -eq $false) { 'Green' } else { 'Red' })
            
            $results += [PSCustomObject]@{
                CheckType = "ManagedInstance"
                InstanceName = $mi.InstanceName
                ResourceGroup = $mi.ResourceGroupName
                PublicDataEndpoint = $mi.PublicDataEndpointEnabled
                RiskLevel = if ($mi.PublicDataEndpointEnabled -eq $true) { 'High' } else { 'Low' }
                Issues = if ($mi.PublicDataEndpointEnabled -eq $true) { "Public data endpoint enabled" } else { "" }
            }
        }
    }
    
    # Check for SQL Vulnerability Assessments
    Write-Host "`n[SQL Vulnerability Assessment Results]" -ForegroundColor Yellow
    $vaFindings = @()
    
    foreach ($server in $sqlServers) {
        $databases = Get-AzSqlDatabase -ServerName $server.ServerName -ResourceGroupName $server.ResourceGroupName | Where-Object { $_.DatabaseName -ne 'master' }
        
        foreach ($db in $databases | Select-Object -First 2) {
            try {
                $scanResult = Get-AzSqlDatabaseVulnerabilityAssessmentScanRecord -ServerName $server.ServerName -DatabaseName $db.DatabaseName -ResourceGroupName $server.ResourceGroupName -ErrorAction SilentlyContinue | Select-Object -First 1
                
                if ($scanResult) {
                    Write-Host "  Database '$($db.DatabaseName)' - Last Scan: $($scanResult.ScanStartTime), Status: $($scanResult.Status)" -ForegroundColor $(if ($scanResult.Status -eq 'Failed') { 'Red' } else { 'Gray' })
                }
            }
            catch {
                # Ignore errors
            }
        }
    }
    
    # Summary
    Write-Host "`n=== SQL Database Security Summary ===" -ForegroundColor Cyan
    $highRisk = ($results | Where-Object { $_.RiskLevel -eq 'High' }).Count
    $mediumRisk = ($results | Where-Object { $_.RiskLevel -eq 'Medium' }).Count
    $serversWithoutAD = ($results | Where-Object { $_.CheckType -eq 'SqlServer' -and -not $_.AdAdminConfigured }).Count
    $serversWithoutAuditing = ($results | Where-Object { $_.CheckType -eq 'SqlServer' -and -not $_.AuditingEnabled }).Count
    
    Write-Host "SQL Servers: $($sqlServers.Count)" -ForegroundColor Cyan
    Write-Host "High Risk: $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { "Red" } else { "Green" })
    Write-Host "Medium Risk: $mediumRisk" -ForegroundColor $(if ($mediumRisk -gt 0) { "Yellow" } else { "Green" })
    Write-Host "Without Azure AD Admin: $serversWithoutAD" -ForegroundColor $(if ($serversWithoutAD -gt 0) { "Red" } else { "Green" })
    Write-Host "Without Auditing: $serversWithoutAuditing" -ForegroundColor $(if ($serversWithoutAuditing -gt 0) { "Red" } else { "Green" })
    
    # Recommendations
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  1. Disable public network access, use private endpoints" -ForegroundColor Gray
    Write-Host "  2. Configure Azure AD authentication (disable SQL auth if possible)" -ForegroundColor Gray
    Write-Host "  3. Enable auditing to Log Analytics or storage account" -ForegroundColor Gray
    Write-Host "  4. Enable Advanced Threat Protection" -ForegroundColor Gray
    Write-Host "  5. Configure Vulnerability Assessment" -ForegroundColor Gray
    Write-Host "  6. Remove 0.0.0.0 firewall rules" -ForegroundColor Gray
    Write-Host "  7. Ensure TDE is enabled on all databases" -ForegroundColor Gray
    Write-Host "  8. Enable SQL vulnerability assessment scanning" -ForegroundColor Gray
    
    # Export
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "SQLDatabase-Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "SQLDatabase-Security_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 5 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n=== SQL Database Security Audit Complete ===" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
