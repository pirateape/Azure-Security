# Azure Sentinel Defense-in-Depth Repository

**A comprehensive security library for Azure infrastructure, Entra ID (Identity), M365, and Edge security.**

This repository consolidates KQL threat hunting queries, PowerShell audit scripts, Azure Policy definitions, Bicep templates, and best practice knowledge into a single, deployable structure.

## 📂 Repository Structure

```text
/
├── src/                        # Source Code
│   ├── KQL/                    # Threat Hunting Queries (Sentinel)
│   │   ├── Identity/           # Password Spray, Brute Force, Smart Lockout, PIM, Stale Accounts
│   │   ├── Edge/               # Firewall Threats, WAF Attacks
│   │   ├── Endpoint/           # Base64 PowerShell, LOLBins
│   │   ├── Data/               # KeyVault, Storage, Cosmos DB, SQL monitoring
│   │   ├── Health/             # Ingestion checks, Silent connectors
│   │   ├── M365/               # Teams, Exchange, SharePoint detections
│   │   └── LateralMovement/    # VM-to-VM, Cross-subnet, Cross-subscription movement
│   ├── PowerShell/             # Audit & Compliance Scripts
│   │   ├── Identity_Audit/     # Comprehensive Identity Security Audits
│   │   ├── M365_Audit/         # Exchange, Teams, SharePoint, Purview
│   │   ├── Network_Audit/      # NSG & Public IP Checks
│   │   ├── Data_Audit/         # Storage, KeyVault public access
│   │   ├── Azure/              # RBAC, Backup/DR, Resource Configuration
│   │   ├── SecurityOperations/ # Defender, Identity Protection, Sentinel
│   │   ├── Governance/         # Secure Score, Compliance
│   │   └── Automation/         # Azure Automation Runbooks & Master Audit
│   ├── Policy/                 # Azure Policy Definitions
│   │   ├── Deny/               # Deny policies (Public IPs, open ports)
│   │   ├── Modify/             # Auto-remediation policies
│   │   └── DeployIfNotExists/  # DINE policies (Flow Logs, Diagnostics)
│   ├── Bicep/                  # Infrastructure as Code
│   │   └── Modules/            # Secure baseline modules
│   ├── AlertRules/             # Defender/Sentinel Alert Rules
│   └── Workbooks/              # Sentinel Dashboards
├── docs/                       # Knowledge Base
│   ├── Architecture/           # Diagrams & Visuals
│   ├── Hardening/              # Best Practices & Guides
│   └── Procedures/             # Operational procedures
├── tests/                      # Validation Scripts
└── .agent/                     # Agent configuration
```

## 🚀 Quick Start

### 🔥 Master Audit - Run Everything

```powershell
# Run comprehensive security audit across all areas
.\src\PowerShell\Automation\Run-MasterAudit.ps1 -RunAll -GenerateReport

# Run specific categories
.\src\PowerShell\Automation\Run-MasterAudit.ps1 -RunAllIdentity -GenerateReport
.\src\PowerShell\Automation\Run-MasterAudit.ps1 -RunAllM365 -GenerateReport
.\src\PowerShell\Automation\Run-MasterAudit.ps1 -RunAllAzure -GenerateReport
```

**Output:**
- `MASTER_AUDIT_REPORT.html` - Executive dashboard
- `MASTER_AUDIT_REPORT.json` - Machine-readable summary
- Individual audit reports in respective folders

---

## 🔴 CRITICAL PRIORITY AUDITS (Run Weekly)

### Conditional Access Security

| Script | Purpose | Critical Checks |
|--------|---------|-----------------|
| `Audit-CA-Logic.ps1` | **10-point CA analysis** | MFA enforcement, legacy auth blocking, admin protection, break-glass, risk policies, device compliance, guest protection, named locations, session controls, app protection |
| `Audit-CA-Conflicts.ps1` | **Conflict detection** | Duplicate policies, block vs allow conflicts, exclusion gaps, missing critical app coverage |
| `Audit-CA-Exclusions.ps1` | Exclusion audit | Excluded users/groups with name resolution |
| `Config-SmartLockout-BP.ps1` | Smart lockout check | Threshold and duration settings |

### Identity Protection & Risk

| Script | Purpose |
|--------|---------|
| `Audit-IdentityProtection.ps1` | **Risk detection analysis**: Risky users, anonymous IPs, impossible travel, leaked credentials, password spray, malware-linked IPs |
| `Audit-MFA-Registration.ps1` | Per-user MFA status, SMS-only detection, admin compliance |
| `Audit-PIM-Config.ps1` | PIM role assignments, permanent vs eligible, risk analysis |

### Application & Service Principal Security

| Script | Purpose |
|--------|---------|
| `Audit-AppRegistrations.ps1` | Expired credentials, high-privilege permissions, multi-tenant apps |
| `Audit-ServicePrincipals.ps1` | SPN credentials, high-privilege app roles, exposed permissions |

### M365 Security

| Script | Purpose |
|--------|---------|
| `Audit-ExchangeOnline.ps1` | Mail forwarding, inbox rules, delegates, DKIM, transport rules |
| `Audit-SharePoint.ps1` | Sharing settings, anonymous links, external access, legacy auth |
| `Audit-Purview.ps1` | DLP policies, sensitivity labels, retention, audit logging |

### Azure Infrastructure Security

| Script | Purpose |
|--------|---------|
| `Audit-NetworkSecurity.ps1` | NSG rules, public IPs, flow logs, risky configurations |
| `Audit-PublicResources.ps1` | Publicly accessible KeyVaults/Storage with auto-remediation |
| `Audit-RBAC-Permissions.ps1` | **RBAC audit**: High privilege assignments, classic admins, custom roles, orphaned assignments, resource locks |

### Security Operations

| Script | Purpose |
|--------|---------|
| `Audit-DefenderStatus.ps1` | Defender for Cloud status, secure score, recommendations, alerts, JIT access |

---

## 🟡 MEDIUM PRIORITY AUDITS (Run Monthly)

### Identity Hygiene

| Script | Purpose |
|--------|---------|
| `Audit-PasswordPolicy.ps1` | Password expiration, banned passwords, SSPR, MFA methods |
| `Audit-DeviceCompliance.ps1` | Device management, compliance policies, stale devices |
| `Audit-B2B-Guests.ps1` | Guest lifecycle, stale guests, cross-tenant policies |
| `Audit-AccessReviews.ps1` | Access review configuration & completion status |
| `Audit-AzureADConnect.ps1` | Sync health, hybrid join, password hash sync |

### M365 Collaboration

| Script | Purpose |
|--------|---------|
| `Audit-Teams.ps1` | Guest access, external sharing, federation, meeting policies |

### Azure Configuration

| Script | Purpose |
|--------|---------|
| `Audit-BackupRecovery.ps1` | Backup vaults, soft delete, unprotected VMs, storage versioning, Site Recovery |
| `Enable-NSGFlowLogs.ps1` | Bulk enable NSG Flow Logs v2 |

### Governance

| Script | Purpose |
|--------|---------|
| `Get-SecureScore-Report.ps1` | Secure Score summary |
| `Run-ProwlerScan.ps1` | Prowler compliance scan |
| `Audit-M365-ScubaGear.ps1` | ScubaGear baseline assessment |
| `Audit-EntraID-Maester.ps1` | Maester framework validation |

---

## 🔧 Azure Policy & Infrastructure (14 Policies)

### Deny Policies (6)
- `Deny-PublicIP.json` - Block public IP creation
- `Deny-PublicIP-OnNIC.json` - Block public IPs on NICs
- `Deny-OpenRDPSSH.json` - Block open RDP/SSH rules
- `Deny-StoragePublicAccess.json` - Block storage public access
- `Deny-KeyVaultPublicAccess.json` - Block KeyVault public access
- `Deny-UnapprovedRegions.json` - Enforce allowed regions

### Modify Policies (5)
- `Modify-StorageTLS12.json` - Auto-set TLS 1.2
- `Modify-StorageHTTPSOnly.json` - Enforce HTTPS-only
- `Modify-AppServiceHTTPSOnly.json` - Enforce HTTPS on App Services
- `Modify-AddTagToRG.json` - Auto-add tags to resource groups
- `Modify-NSGDefaultDeny.json` - Add default deny rule to NSGs

### DeployIfNotExists (3)
- `DINE-NSGFlowLogs.json` - Deploy flow logs to all NSGs
- `DINE-DiagnosticSettings.json` - Deploy diagnostics to resources
- `DINE-VM-MonitoringAgent.json` - Deploy monitoring agents to VMs

---

## 🏗️ Bicep Modules (5)

- `vnet-secure.bicep` - Secure VNet with NSG & flow logs
- `keyvault-secure.bicep` - Secure Key Vault with private endpoint
- `storage-secure.bicep` - Secure Storage Account with private endpoint
- `log-analytics-sentinel.bicep` - Log Analytics with Sentinel onboarding
- `policy-assignment.bicep` - Policy assignment with managed identity

---

## 📊 KQL Detections (30+)

### Identity (12)
- `Identity_PasswordSpray.kql`
- `Identity_BruteForceSuccess.kql`
- `Identity_SmartLockout_Events.kql`
- `Identity_PIM_AfterHours.kql`
- `Identity_StaleAccountLogin.kql`
- `Identity_SPN_CredentialAdded.kql`
- `Identity_SuspiciousConsent.kql`
- `Identity_AppRegistrationByUser.kql`
- `Identity_CrossTenantSync.kql`
- `Identity_BreakGlassUsage.kql`
- `Identity_GeoBlocking_Candidates.kql`
- `Identity_PotentialDoS_Lockout.kql`

### M365 (6)
- `Exchange_SuspiciousForwarding.kql`
- `Exchange_MassEmailDeletion.kql`
- `Teams_ExternalUserAdded.kql`
- `Teams_ExternalMassDownload.kql`
- `SharePoint_AnonymousLinkCreated.kql`
- `SharePoint_ExternalBulkDownload.kql`

### Data Protection (6)
- `KeyVault_MassSecretRetrieval.kql`
- `Storage_AnomalousGeo.kql`
- `Data_LargeBlobAccess.kql`
- `Data_CosmosSuspiciousQueries.kql`
- `Data_SQLBulkExport.kql`

### Lateral Movement (3)
- `LatMov_VMInternalRDP_SSH.kql`
- `LatMov_UnusualPorts.kql`
- `LatMov_CrossSubscriptionAccess.kql`

### Health (5)
- `Health_LastLogReceived.kql`
- `Health_SilentConnectors.kql`
- `Health_FailedAnalyticRules.kql`
- `Health_IngestionVolume.kql`

---

## 🤖 Automation & Runbooks (4)

| Script | Purpose |
|--------|---------|
| `Run-MasterAudit.ps1` | **Master orchestrator** - Run all audits |
| `Runbook-ScheduledRemediation.ps1` | Auto-remediate policy violations |
| `Runbook-NSGCleanup.ps1` | Remove risky NSG rules |
| `Runbook-CredentialExpiryCheck.ps1` | Monitor expiring credentials |

---

## 🚨 Sentinel Alert Rules (4)

- `Alert-PasswordSpray.json`
- `Alert-KeyVaultMassRetrieval.json`
- `Alert-ExchangeForwarding.json`
- `Alert-SuspiciousConsent.json`

---

## 🧪 Attack Simulation

Validate detections with `tests/simulation/`:
- `Simulate-SmartLockout.ps1` - Test Identity alerts
- `Simulate-KeyVault-MassRead.ps1` - Test Data exfiltration alerts

---

## 📈 Usage Examples

### Deploy Azure Policies

```powershell
Connect-AzAccount

# Deploy deny policy for public IPs
$policyDef = Get-Content -Path "src/Policy/Deny/Deny-PublicIP.json" | ConvertFrom-Json
New-AzPolicyDefinition `
  -Name "Deny-PublicIP" `
  -Policy ($policyDef | Select-Object -ExpandProperty policyRule) `
  -Parameter ($policyDef | Select-Object -ExpandProperty parameters)

# Assign policy
New-AzPolicyAssignment `
  -Name "Deny-PublicIP-Assignment" `
  -PolicyDefinition (Get-AzPolicyDefinition -Name "Deny-PublicIP") `
  -Scope "/subscriptions/$((Get-AzContext).Subscription.Id)" `
  -PolicyParameterObject @{ effect = "Deny" }
```

### Run Critical Audits

```powershell
# CA Logic Analysis
.\src\PowerShell\Identity_Audit\Audit-CA-Logic.ps1 -ExportCSV -Detailed

# CA Conflict Detection
.\src\PowerShell\Identity_Audit\Audit-CA-Conflicts.ps1 -ExportCSV -ShowConflictsOnly

# Identity Protection Risks
.\src\PowerShell\SecurityOperations\Audit-IdentityProtection.ps1 -ExportCSV -ShowTopFindings

# RBAC Permissions
.\src\PowerShell\Azure\Audit-RBAC-Permissions.ps1 -ExportCSV -ShowDetails

# Defender Status
.\src\PowerShell\SecurityOperations\Audit-DefenderStatus.ps1 -ExportCSV

# MFA Registration
.\src\PowerShell\Identity_Audit\Audit-MFA-Registration.ps1 -ExportCSV -IncludeDetails

# Backup/DR
.\src\PowerShell\Azure\Audit-BackupRecovery.ps1 -ExportCSV

# Public Resources
.\src\PowerShell\Data_Audit\Audit-PublicResources.ps1 -ExportCSV -AutoRemediate
```

---

## 📋 Requirements

### PowerShell Modules
```powershell
# Azure
Install-Module Az -Scope CurrentUser

# Microsoft Graph
Install-Module Microsoft.Graph -Scope CurrentUser

# M365
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module MicrosoftTeams -Scope CurrentUser
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
```

### Required Permissions
- **Azure**: Reader/Contributor
- **Microsoft Graph**: Directory.Read.All, Policy.Read.All, User.Read.All, Application.Read.All, IdentityRiskEvent.Read.All, IdentityRiskyUser.Read.All
- **Exchange**: Exchange Administrator or Global Reader
- **SharePoint**: SharePoint Administrator

---

## 🎯 Audit Priority Matrix

| Priority | Frequency | Scripts |
|----------|-----------|---------|
| 🔴 **CRITICAL** | Weekly | CA Logic, CA Conflicts, Identity Protection, MFA, PIM, App Registrations, Exchange, RBAC, Defender Status |
| 🟡 **MEDIUM** | Monthly | Password Policy, Device Compliance, B2B, Access Reviews, Teams, Backup/DR, Azure AD Connect |
| 🟢 **INFO** | Quarterly | Maester, ScubaGear, Secure Score, Prowler |

---

## 📊 Security Coverage Matrix

| Area | Coverage |
|------|----------|
| **Identity** | 100% (CA, MFA, PIM, Apps, SPNs, Protection, Passwords, Devices, Guests, Reviews) |
| **M365** | 100% (Exchange, Teams, SharePoint, Purview) |
| **Azure Infrastructure** | 95% (Network, RBAC, Backup, Storage, Policies, Diagnostics) |
| **Security Operations** | 90% (Defender, Sentinel, Identity Protection) |
| **Compliance** | 80% (Secure Score, DLP, Labels, Retention) |

---

## 🤝 Contributing

All contributions should:
- Follow security best practices
- Include error handling and logging
- Support export formats (CSV/JSON)
- Include comprehensive documentation

---

*Created by PirateApe | Comprehensive Azure & M365 Security Audit Framework v2.0*
