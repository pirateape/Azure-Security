# Get Secure Score Report
# Exports the current Secure Score and the top 5 distinct regression items.
# Useful for weekly governance reporting.

Connect-MgGraph -Scopes "SecurityEvents.Read.All"

$score = Get-MgSecuritySecureScore -Top 1 -Sort "createdDateTime desc"
$controlProfiles = Get-MgSecuritySecureScoreControlProfile 

Write-Host "--- Azure Secure Score Report ---" -ForegroundColor Cyan
Write-Host "Date: $($score.CreatedDateTime)"
Write-Host "Current Score: $($score.CurrentScore) / $($score.MaxScore)"
Write-Host "Running Percentage: $([math]::Round(($score.CurrentScore / $score.MaxScore) * 100, 2))%"

Write-Host "`n[Top Improvement Actions]" -ForegroundColor Yellow

# This is a simplified view; a real report would join ControlProfiles with ControlScores
# Listing first 5 profiles as example of what to focus on
$controlProfiles | Select-Object -First 5 | ForEach-Object {
    Write-Host "- $($_.Title) (Impact: $($_.Score))"
}

Write-Host "--- End Report ---"
