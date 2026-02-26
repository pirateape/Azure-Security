# Install Maester Module
Install-Module Maester -Scope CurrentUser -Force

# Connect to Maester (Requires Graph Permissions)
Connect-Maester

# Run Comprehensive Audit
# Scans against the EIDSCA (Entra ID Security Config Analyzer) baseline.
Invoke-Maester -OutputFolder ./Reports/Identity -Verbose

# Review Key Checks:
# - MFA Enforcement
# - Break-Glass Accounts
# - Legacy Authentication
# - Device Compliance
