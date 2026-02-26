[CmdletBinding()]
param(
    [string]$OutputPath = "./Reports/Identity",
    [switch]$ExportCSV,
    [switch]$ExportJSON
)

$ErrorActionPreference = "Stop"
$transcriptPath = Join-Path $OutputPath "Audit-AccessReviews_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $transcriptPath -IncludeInvocationHeader

try {
    Write-Host "--- Entra ID Access Reviews Audit ---" -ForegroundColor Cyan
    
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Install-Module Microsoft.Graph -Scope CurrentUser -Force
    }
    
    Connect-MgGraph -Scopes "AccessReview.Read.All", "Directory.Read.All" -NoWelcome
    
    $results = @()
    
    $accessReviewDefinitions = Get-MgIdentityGovernanceAccessReviewDefinition -All -ErrorAction SilentlyContinue
    
    if (-not $accessReviewDefinitions) {
        Write-Host "[INFO] No Access Review definitions found or insufficient permissions." -ForegroundColor Yellow
        Write-Host "       Ensure you have an Entra ID P2 license and AccessReview.Read.All permission." -ForegroundColor Gray
        return
    }
    
    Write-Host "`n[Access Review Definitions]" -ForegroundColor Yellow
    Write-Host "Total Access Reviews Found: $($accessReviewDefinitions.Count)" -ForegroundColor Gray
    
    foreach ($review in $accessReviewDefinitions) {
        $issues = @()
        $riskLevel = "Low"
        
        if ($review.Status -eq "Completed") {
            $completedInstances = Get-MgIdentityGovernanceAccessReviewDefinitionInstance -AccessReviewScheduleDefinitionId $review.Id -ErrorAction SilentlyContinue
            $latestInstance = $completedInstances | Sort-Object EndDateTime -Descending | Select-Object -First 1
            
            if ($latestInstance) {
                $decisions = Get-MgIdentityGovernanceAccessReviewDefinitionInstanceDecision -AccessReviewScheduleDefinitionId $review.Id -AccessReviewInstanceId $latestInstance.Id -ErrorAction SilentlyContinue
                
                $denyCount = ($decisions | Where-Object { $_.Decision -eq "Deny" }).Count
                $notReviewedCount = ($decisions | Where-Object { $_.Decision -eq "NotReviewed" }).Count
                $totalDecisions = $decisions.Count
                
                if ($notReviewedCount -gt 0 -and $totalDecisions -gt 0) {
                    $notReviewedPercent = [math]::Round(($notReviewedCount / $totalDecisions) * 100, 1)
                    $issues += "$notReviewedPercent% of decisions not reviewed"
                    if ($notReviewedPercent -gt 50) { $riskLevel = "High" }
                    elseif ($notReviewedPercent -gt 25) { $riskLevel = "Medium" }
                }
                
                if ($denyCount -gt 0) {
                    $issues += "$denyCount access denies recorded"
                }
            }
        }
        elseif ($review.Status -eq "InProgress") {
            $issues += "Review currently in progress"
        }
        elseif ($review.Status -eq "NotStarted") {
            $issues += "Review not started"
            $riskLevel = "Medium"
        }
        
        $result = [PSCustomObject]@{
            DisplayName = $review.DisplayName
            Description = $review.Description
            DefinitionId = $review.Id
            Status = $review.Status
            CreatedDateTime = $review.CreatedDateTime
            LastModifiedDateTime = $review.LastModifiedDateTime
            ScopeType = $review.Scope.'@odata.type' -replace '#microsoft.graph.'
            ReviewerType = if ($review.Reviewers) { "Assigned" } else { "Self-Review" }
            RecurrencePattern = if ($review.Settings.RecurrencePattern) { $review.Settings.RecurrencePattern.Type } else { "One-time" }
            AutoApplyDecisions = $review.Settings.AutoApplyDecisionsEnabled
            RiskLevel = $riskLevel
            Issues = $issues -join "; "
        }
        
        $results += $result
        
        if ($riskLevel -eq "High") {
            Write-Host "[HIGH] $($review.DisplayName) - Status: $($review.Status) - $($issues -join ', ')" -ForegroundColor Red
        }
        elseif ($riskLevel -eq "Medium") {
            Write-Host "[MEDIUM] $($review.DisplayName) - Status: $($review.Status) - $($issues -join ', ')" -ForegroundColor Yellow
        }
        else {
            Write-Host "[OK] $($review.DisplayName) - Status: $($review.Status)" -ForegroundColor Green
        }
    }
    
    Write-Host "`n[Summary]" -ForegroundColor Cyan
    Write-Host "  Total Access Reviews: $($accessReviewDefinitions.Count)"
    Write-Host "  Completed: $(($results | Where-Object { $_.Status -eq 'Completed' }).Count)" -ForegroundColor Green
    Write-Host "  In Progress: $(($results | Where-Object { $_.Status -eq 'InProgress' }).Count)" -ForegroundColor Yellow
    Write-Host "  High Risk: $(($results | Where-Object { $_.RiskLevel -eq 'High' }).Count)" -ForegroundColor Red
    
    $rolesWithoutReview = @("Global Administrator", "Security Administrator", "Exchange Administrator")
    Write-Host "`n[Recommendations]" -ForegroundColor Yellow
    Write-Host "  - Ensure high-privilege roles have recurring access reviews" -ForegroundColor Gray
    Write-Host "  - Review roles: $($rolesWithoutReview -join ', ')" -ForegroundColor Gray
    Write-Host "  - Enable auto-apply for decisions to remove access automatically" -ForegroundColor Gray
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    if ($ExportCSV) {
        $csvPath = Join-Path $OutputPath "AccessReviews_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "`n[EXPORT] CSV saved to: $csvPath" -ForegroundColor Green
    }
    
    if ($ExportJSON) {
        $jsonPath = Join-Path $OutputPath "AccessReviews_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $results | ConvertTo-Json -Depth 10 | Out-File $jsonPath
        Write-Host "[EXPORT] JSON saved to: $jsonPath" -ForegroundColor Green
    }
    
    Write-Host "`n--- Access Reviews Audit Complete ---" -ForegroundColor Cyan
    
}
catch {
    Write-Host "[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    throw
}
finally {
    Stop-Transcript
}

return $results
