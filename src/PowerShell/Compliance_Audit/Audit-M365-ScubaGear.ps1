# Install ScubaGear Module
Install-Module -Name ScubaGear -Scope CurrentUser -Force

# Run Assessment
# Scans Exchange, SharePoint, Teams, and Power Platform.
Invoke-SCuBA -ProductNames * -OutputFolder ./Reports/Tenant

# Analyze Report:
# - Open the generated HTML report.
# - Focus on "Fail" outcomes in the External Sharing and Admin Consent sections.
