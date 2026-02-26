# Audit Conditional Access Policy Exclusions
# Lists specific users/groups excluded from policies.
# Gaps often hide here (e.g., "Exclude: Executives" from MFA).

Connect-MgGraph -Scopes "Policy.Read.All", "Group.Read.All", "User.Read.All"

$policies = Get-MgIdentityConditionalAccessPolicy | Where-Object { $_.State -eq "enabled" }

foreach ($policy in $policies) {
    $exclusions = $policy.Conditions.Users.ExcludeUsers
    $excludedGroups = $policy.Conditions.Users.ExcludeGroups

    if ($exclusions -or $excludedGroups) {
        Write-Host "Policy: $($policy.DisplayName)" -ForegroundColor Cyan
        
        if ($exclusions) {
            Write-Host "  - Excluded User IDs: $($exclusions -join ', ')"
            # Note: Resolve IDs to Names if needed, but IDs are safer for logging.
        }
        
        if ($excludedGroups) {
            foreach ($groupId in $excludedGroups) {
                try {
                    $group = Get-MgGroup -GroupId $groupId -ErrorAction SilentlyContinue
                    Write-Host "  - Excluded Group: $($group.DisplayName) ($groupId)"
                }
                catch {
                    Write-Host "  - Excluded Group ID: $groupId (Name not resolved)"
                }
            }
        }
    }
}
