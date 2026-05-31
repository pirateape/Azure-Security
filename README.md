# Azure Security Audit Framework

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/pirateape/Azure-Security/actions/workflows/ci.yml/badge.svg)](https://github.com/pirateape/Azure-Security/actions/workflows/ci.yml)

**A comprehensive security library for Azure infrastructure, Entra ID, M365, and Edge security.**  
51 KQL queries · 43 PowerShell audit scripts · 15 Azure Policies · 6 Sentinel Workbooks · 7 Alert Rules · 2 SOAR Playbooks · 8 Bicep modules

This repository consolidates KQL threat hunting queries, PowerShell audit scripts, Azure Policy definitions, Bicep templates, Sentinel alert rules, Logic App playbooks, and operational runbooks into a single deployable structure. All content is **MIT licensed** — use it freely in your own environment.

---

## 📂 Repository Structure

```text
/
├── src/
│   ├── KQL/                         # Sentinel Threat Hunting Queries (51)
│   │   ├── Identity/                # Password spray, brute force, token theft, PIM, stales (18)
│   │   ├── M365/                    # Exchange, Teams, SharePoint detections (6)
│   │   ├── Data/                    # KeyVault, Storage, Cosmos, SQL monitoring (5)
│   │   ├── AdvancedHunting/         # Cross-domain hunts: RBAC, Tor/VPN, lateral, inbox rules (8)
│   │   ├── Health/                  # Ingestion checks, silent connectors, rule failures (5)
│   │   ├── Edge/                    # Firewall threats, WAF attacks, public IP detection (3)
│   │   ├── Endpoint/                # Base64 PowerShell, LOLBins (3)
│   │   └── LateralMovement/         # Cross-subnet, cross-subscription access (3)
│   ├── PowerShell/                  # Audit & Compliance Scripts (43)
│   │   ├── Identity_Audit/          # CA logic, MFA, PIM, app registrations, B2B (14)
│   │   ├── Azure/                   # RBAC, backup/DR, KeyVault, SQL, VMs, policy compliance (12)
│   │   ├── Automation/              # Master orchestrator, runbooks, NSG cleanup (5)
│   │   ├── M365_Audit/              # Exchange, Teams, SharePoint, Purview (4)
│   │   ├── Compliance_Audit/        # Prowler, ScubaGear integration (2)
│   │   ├── SecurityOperations/      # Defender status, Identity Protection (2)
│   │   ├── Data_Audit/              # Public KeyVault/Storage assessment (1)
│   │   ├── EntraID/                 # Risky user analysis (1)
│   │   ├── Governance/              # Secure Score reporting (1)
│   │   └── Network_Audit/           # NSG & public IP checks (1)
│   ├── Policy/                      # Azure Policy Definitions (15)
│   │   ├── Deny/                    # Public IP, open RDP/SSH, storage/KeyVault public access (7)
│   │   ├── Modify/                  # Auto-remediate TLS 1.2, HTTPS, NSG defaults, tags (5)
│   │   └── DeployIfNotExists/       # NSG flow logs, diagnostic settings, monitoring agents (3)
│   ├── Bicep/                       # Infrastructure as Code (8)
│   │   ├── Modules/                 # VNet, KeyVault, Storage, Sentinel, Policy assignment (5)
│   │   └── Templates/               # Deployment orchestrator + alternatives (2)
│   ├── AlertRules/                  # Defender/Sentinel scheduled alert rules (7)
│   ├── Playbooks/                   # Logic App ARM templates for SOAR (2)
│   └── Workbooks/                   # Sentinel dashboards for posture & operations (6)
├── docs/
│   ├── Architecture/                # STRIDE threat model, defense diagram
│   ├── Hardening/                   # Azure BP, Entra ID CA hardening, tooling guides
│   └── Procedures/                  # IR playbook, workbook deployment
└── tests/simulation/                # Attack simulation scripts (2)
```

---

## 🚀 Quick Start

### Master Audit — Run Everything

```powershell
# Full security audit across all areas
.\src\PowerShell\Automation\Run-MasterAudit.ps1 -RunAll -GenerateReport

# Specific categories
.\src\PowerShell\Automation\Run-MasterAudit.ps1 -RunAllIdentity -GenerateReport
.\src\PowerShell\Automation\Run-MasterAudit.ps1 -RunAllM365 -GenerateReport
.\src\PowerShell\Automation\Run-MasterAudit.ps1 -RunAllAzure -GenerateReport
```

**Output:**
- `MASTER_AUDIT_REPORT.html` — Executive dashboard
- `MASTER_AUDIT_REPORT.json` — Machine-readable summary
- Individual audit reports in respective folders

### SOAR Playbooks (`src/Playbooks`)

Deploy these Logic App ARM templates to automate incident response in Sentinel:

| Playbook | Function |
|----------|----------|
| `Block-EntraUser.json` | Extracts compromised account entities from the Sentinel Incident, disables the account in Entra ID, revokes all active sessions, and posts a comment back |
| `Isolate-AzureVM.json` | Applies a top-priority "Deny All" NSG rule to isolate the compromised machine while preserving local forensic access |

---

## 🔴 Critical Priority Audits (Run Weekly)

### Conditional Access

| Script | Purpose |
|--------|---------|
| `Audit-CA-Logic.ps1` | 10-point CA analysis — MFA enforcement, legacy auth, admin protection, break-glass, risk policies, device compliance, guest, named locations, session, app protection |
| `Audit-CA-Conflicts.ps1` | Duplicate policy detection, block vs allow conflicts, exclusion gaps, missing app coverage |
| `Audit-CA-Exclusions.ps1` | Exclusion audit with user/group name resolution |
| `Config-SmartLockout-BP.ps1` | Smart lockout threshold and duration benchmarking |

### Identity Protection & Risk

| Script | Purpose |
|--------|---------|
| `Audit-IdentityProtection.ps1` | Risky users, anonymous IPs, impossible travel, leaked credentials, password spray, malware-linked IPs |
| `Audit-MFA-Registration.ps1` | Per-user MFA status, SMS-only detection, admin compliance |
| `Audit-PIM-Config.ps1` | PIM role assignments, permanent vs eligible, risk analysis |
| `Audit-RiskyUsers.ps1` | Entra ID risky user overview with risk level scoring |

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

### Azure Infrastructure

| Script | Purpose |
|--------|---------|
| `Audit-NetworkSecurity.ps1` | NSG rules, public IPs, flow logs, risky configurations |
| `Audit-PublicResources.ps1` | Publicly accessible KeyVaults/Storage with auto-remediation |
| `Audit-RBAC-Permissions.ps1` | High-privilege assignments, classic admins, custom roles, orphaned assignments, resource locks |
| `Audit-AppServiceConfig.ps1` | TLS 1.2+, HTTPS Only, VNET Integration, Managed Identities |
| `Audit-ActivityLogs.ps1` | Activity log anomalies, break-glass operations, configuration changes |
| `Audit-CostAnomalies.ps1` | Cost spike detection as early indicator of resource compromise |
| `Audit-KeyVault-Security.ps1` | KeyVault firewall, soft-delete, purge protection, RBAC |
| `Audit-SQLDatabase-Security.ps1` | Auditing, TDE, threat detection, firewall rules, vulnerability assessments |
| `Audit-VirtualMachines.ps1` | Disk encryption, boot diagnostics, RDP/SSH access review |
| `Audit-Encryption-Compliance.ps1` | Cross-resource encryption compliance check |

### Security Operations

| Script | Purpose |
|--------|---------|
| `Audit-DefenderStatus.ps1` | Defender for Cloud status, secure score, recommendations, alerts, JIT access |
| `Audit-PolicyCompliance.ps1` | Azure Policy compliance state per resource and initiative |

---

## 🟡 Medium Priority Audits (Run Monthly)

### Identity Hygiene

| Script | Purpose |
|--------|---------|
| `Audit-PasswordPolicy.ps1` | Password expiration, banned passwords, SSPR, MFA methods |
| `Audit-DeviceCompliance.ps1` | Device management, compliance policies, stale devices |
| `Audit-B2B-Guests.ps1` | Guest lifecycle, stale guests, cross-tenant policies |
| `Audit-AccessReviews.ps1` | Access review configuration and completion status |
| `Audit-AzureADConnect.ps1` | Sync health, hybrid join, password hash sync |

### M365 Collaboration

| Script | Purpose |
|--------|---------|
| `Audit-Teams.ps1` | Guest access, external sharing, federation, meeting policies |

### Azure Configuration

| Script | Purpose |
|--------|---------|
| `Audit-BackupRecovery.ps1` | Backup vaults, soft delete, unprotected VMs, storage versioning, Site Recovery |
| `Audit-AppServices.ps1` | App Service plan security, CORS, authentication, TLS configuration |
| `Audit-CognitiveServices.ps1` | Network ACLs, identity-based access, data encryption |
| `Enable-NSGFlowLogs.ps1` | Bulk enable NSG Flow Logs v2 across subscriptions |

### Governance

| Script | Purpose |
|--------|---------|
| `Get-SecureScore-Report.ps1` | Secure Score summary with trend analysis |
| `Run-ProwlerScan.ps1` | Prowler compliance scan orchestrator |
| `Audit-M365-ScubaGear.ps1` | ScubaGear baseline assessment for M365 |
| `Audit-EntraID-Maester.ps1` | Maester framework validation for Entra ID |

---

## 🔧 Azure Policies (15)

| Category | Count | Purpose |
|----------|:-----:|---------|
| **Deny** | 7 | Block creation of public IPs, open RDP/SSH, public Storage/KeyVault, unapproved regions |
| **Modify** | 5 | Auto-remediate TLS 1.2, HTTPS-only, NSG deny rules, resource tagging |
| **DeployIfNotExists** | 3 | Deploy NSG flow logs, diagnostic settings, VM monitoring agents |

Deploy via Azure CLI or Bicep:

```powershell
Connect-AzAccount

# Deploy individual policy
$policyDef = Get-Content -Path "src/Policy/Deny/Deny-PublicIP.json" | ConvertFrom-Json
New-AzPolicyDefinition -Name "Deny-PublicIP" -Policy $policyDef

# Deploy full baseline via Bicep
New-AzResourceGroupDeployment -TemplateFile src/Bicep/Templates/main.bicep
```

---

## 🏗️ Bicep Infrastructure (8 templates)

| Template | Purpose |
|----------|---------|
| `Modules/vnet-secure.bicep` | Secure VNet with NSG and flow logs |
| `Modules/keyvault-secure.bicep` | Key Vault with private endpoint, soft-delete, purge protection |
| `Modules/storage-secure.bicep` | Storage Account with private endpoint, TLS enforced |
| `Modules/log-analytics-sentinel.bicep` | Log Analytics workspace + Sentinel onboarding |
| `Modules/policy-assignment.bicep` | Policy assignment with managed identity |
| `Templates/main.bicep` | AZ-Wall Security Baseline — orchestrates all modules |
| `Templates/infrastructure-main.bicep` | Alternative: deploy Log Analytics + Sentinel standalone |
| `Templates/main.parameters.json` | Parameter file for `main.bicep` |

---

## 📊 KQL Threat Hunting Queries (51)

### Identity (18)

| Query | Detects |
|-------|---------|
| `Identity_PasswordSpray.kql` | High-volume failed logins targeting multiple accounts per IP |
| `Identity_BruteForceSuccess.kql` | Successful logins following password spray from same IP |
| `Identity_SmartLockout_Events.kql` | Accounts hitting Entra ID smart lockout threshold |
| `Identity_ImpossibleTravel.kql` | Logins from geographically impossible locations in short windows |
| `Identity_TokenTheft.kql` | Token replay anomalies (same token, different locations/IPs) |
| `Identity_PIM_AfterHours.kql` | Privileged role activations outside business hours |
| `Identity_StaleAccountLogin.kql` | Re-authentication of accounts dormant for 90+ days |
| `Identity_SPN_CredentialAdded.kql` | New credentials added to service principals |
| `Identity_SuspiciousConsent.kql` | OAuth consent grants to high-risk or multi-tenant apps |
| `Identity_AppRegistrationByUser.kql` | Non-admin users registering applications |
| `Identity_CrossTenantSync.kql` | Cross-tenant synchronization attempts |
| `Identity_BreakGlassUsage.kql` | Emergency break-glass account activity patterns |
| `Identity_GeoBlocking_Candidates.kql` | User country profiles for Conditional Access geo-blocking |
| `Identity_PotentialDoS_Lockout.kql` | Accounts triggering repeated lockouts (potential denial-of-service) |
| `Identity_LegacyAuth_Usage.kql` | Legacy authentication protocol usage by application |
| `Identity_NewAdminAccount.kql` | Recently created privileged accounts |
| `Identity_FederatedCredentialAdded.kql` | New federated credentials on applications/SPNs |
| `Infra_PIM_Activation.kql` | PIM activation details and approval status |

### M365 (6)

| Query | Detects |
|-------|---------|
| `Exchange_SuspiciousForwarding.kql` | Mailbox forwarding rules to external domains |
| `Exchange_MassEmailDeletion.kql` | Bulk email deletion by a single user |
| `Teams_ExternalUserAdded.kql` | External users added to Teams/Channels |
| `Teams_ExternalMassDownload.kql` | Bulk download from Teams/SharePoint by external users |
| `SharePoint_AnonymousLinkCreated.kql` | Anonymous sharing link creation |
| `SharePoint_ExternalBulkDownload.kql` | High-volume download by external IPs |

### Data Protection (5)

| Query | Detects |
|-------|---------|
| `KeyVault_MassSecretRetrieval.kql` | Bulk secrets retrieval from Key Vault |
| `Storage_AnomalousGeo.kql` | Storage access from unusual geographic regions |
| `Data_LargeBlobAccess.kql` | Unusually large blob read operations |
| `Data_CosmosSuspiciousQueries.kql` | Cosmos DB query anomalies (RU spikes, unusual operations) |
| `Data_SQLBulkExport.kql` | Large-scale SQL database export operations |

### Advanced Hunting (8)

| Query | Detects |
|-------|---------|
| `Anomalous-AppCredential.kql` | Unusual application credential usage patterns |
| `Anomalous-KeyVaultAccess.kql` | Key Vault access outside normal operational baselines |
| `Failed-Logons.kql` | Aggregated failed sign-in analysis across protocols |
| `Lateral-Movement.kql` | Cross-resource authentication indicating lateral movement |
| `Malicious-InboxRules.kql` | Suspicious inbox rule creation (forwarding, deletion) |
| `Suspicious-PowerShell.kql` | PowerShell execution anomalies in Entra ID |
| `Suspicious-RBAC.kql` | Suspicious role assignment activity |
| `Tor-VPN-Signins.kql` | Sign-ins from known Tor exit nodes and VPN providers |

### Edge & Network (3)

| Query | Detects |
|-------|---------|
| `Infra_NewPublicIP.kql` | Recent public IP address creation |
| `Network_Firewall_Threats.kql` | Azure Firewall blocked traffic by threat intelligence |
| `Web_WAF_Attacks.kql` | WAF-detected attacks (SQLi, XSS, OWASP top 10) |

### Endpoint (3)

| Query | Detects |
|-------|---------|
| `Endpoint_Base64PowerShell.kql` | Base64-encoded PowerShell execution |
| `Endpoint_LOLBin_CertUtil.kql` | CertUtil used for binary download (LOLBin pattern) |
| `Endpoint_LOLBins_Comprehensive.kql` | Broader LOLBin detection (mshta, wmic, regsvr32, cscript) |

### Lateral Movement (3)

| Query | Detects |
|-------|---------|
| `LatMov_VMInternalRDP_SSH.kql` | VM-to-VM RDP/SSH connections |
| `LatMov_UnusualPorts.kql` | Cross-subnet connections on non-standard ports |
| `LatMov_CrossSubscriptionAccess.kql` | Authentication across subscription boundaries |

### Sentinel Health (5)

| Query | Detects |
|-------|---------|
| `Health_LastLogReceived.kql` | Tables with no recent data ingestion |
| `Health_SilentConnectors.kql` | Data connectors with zero data flow |
| `Health_FailedAnalyticRules.kql` | Scheduled analytics rules with execution errors |
| `Health_IngestionVolume.kql` | Daily ingestion volume by table |
| `Health_TestRule_SubscriptionList.kql` | Active subscription inventory for rule targeting |

---

## 🚨 Sentinel Alert Rules (7)

| Alert Rule | MITRE Mapping | Logic |
|------------|---------------|-------|
| `Alert-PasswordSpray.json` | T1110.003 | Failed logins across multiple accounts from single IP |
| `Alert-BruteForceSuccess.json` | T1110 | Successful logon after password spray pattern |
| `Alert-ImpossibleTravel.json` | T1078 | Geo-coordinates impossible by transit time |
| `Alert-TokenTheft.json` | T1528 | Token replay from geographically distinct locations |
| `Alert-KeyVaultMassRetrieval.json` | T1552.004 | Bulk secrets enumeration from Key Vault |
| `Alert-ExchangeForwarding.json` | T1114.003 | Mailbox forwarding rule to external domain |
| `Alert-SuspiciousConsent.json` | T1525 | OAuth consent to multi-tenant / high-risk application |

---

## 📈 Sentinel Workbooks (6)

| Workbook | Focus |
|----------|-------|
| `IdentityPosture-Dashboard.json` | Entra ID risk, MFA compliance, risky sign-ins, legacy auth |
| `M365Threats-Dashboard.json` | Exchange forwarding, SharePoint mass downloads, Teams anomalies |
| `ComplianceMaturity-Dashboard.json` | CIS/NIST regulatory compliance mapped to Defender controls |
| `SOCOperations-Dashboard.json` | Alert triage, incident volume, Sentinel health, rule efficacy |
| `ThreatHunting-Dashboard.json` | Cross-domain hunting surface for advanced threat investigations |
| `Defense_Dashboard.json` | Azure Defense-in-depth: smart lockout, firewall, secure score |

**Deployment:** Import via Sentinel Workbooks blade or deploy via Bicep templates.

---

## 🧪 Attack Simulations

Test your detections with `tests/simulation/`:

| Script | Target |
|--------|--------|
| `Simulate-SmartLockout.ps1` | Triggers Entra ID smart lockout via repeated failed auth |
| `Simulate-KeyVault-MassRead.ps1` | Bulk enumerates Key Vault secrets to trigger detection |

---

## 🤖 Automation & Runbooks

| Script | Purpose |
|--------|---------|
| `Run-MasterAudit.ps1` | Master orchestrator — runs all audit categories and collates reports |
| `Runbook-ScheduledRemediation.ps1` | Scheduled remediation of common policy violations |
| `Runbook-NSGCleanup.ps1` | Remove or flag risky NSG rules on a schedule |
| `Runbook-CredentialExpiryCheck.ps1` | Monitor expiring application and SPN credentials |
| `Enable-NSGFlowLogs.ps1` | Bulk-enable NSG Flow Logs v2 across all NSGs in a subscription |

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

| Scope | Minimum Role |
|-------|-------------|
| **Azure** | Reader (Contributor for auto-remediation) |
| **Microsoft Graph** | Directory.Read.All, Policy.Read.All, Application.Read.All, IdentityRiskEvent.Read.All, IdentityRiskyUser.Read.All |
| **Exchange Online** | Exchange Administrator or Global Reader |
| **SharePoint** | SharePoint Administrator |
| **Sentinel** | Sentinel Reader |

---

## 🎯 Audit Priority Matrix

| Priority | Frequency | Scripts |
|----------|-----------|---------|
| 🔴 **CRITICAL** | Weekly | CA Logic, CA Conflicts, Identity Protection, MFA, PIM, App Registrations, Exchange, RBAC, Defender, Network Security, KeyVault Security |
| 🟡 **MEDIUM** | Monthly | Password Policy, Device Compliance, B2B, Access Reviews, Teams, Backup/DR, App Services, SQL Security, VM Security |
| 🟢 **INFO** | Quarterly | ScubaGear, Maester, Secure Score, Prowler, Encryption Compliance |

---

## 📊 Coverage Snapshot

| Area | Coverage |
|------|:--------:|
| **Identity (Entra ID)** | 100% — CA, MFA, PIM, App Reg, SPNs, Identity Protection, Password, Devices, B2B, Access Reviews |
| **M365 (Exchange, Teams, SharePoint, Purview)** | 100% — Forwarding, sharing, DLP, labels, retention, audit |
| **Azure Infrastructure** | 95% — Network, RBAC, Backup, Storage, KeyVault, SQL, VMs, App Service, Policies, Diagnostics |
| **Security Operations** | 90% — Defender, Sentinel, Identity Protection, Secure Score, Compliance |
| **Compliance Frameworks** | 80% — CIS, NIST, Prowler, ScubaGear, Maester integration |

---

## 🤝 Contributing

All contributions should:
- Follow Microsoft security best practices
- Include error handling and structured logging
- Support export formats (CSV/JSON/HTML)
- Include inline documentation
- Never store credentials or tokens

---

## 📄 License

**MIT** — Use it freely. See [LICENSE](LICENSE) for details.

## 🔗 Related

- [ApeGuard](https://github.com/pirateape/ape-guard) — One-command local security posture assessment
- [ApeGuard GitHub Action](https://github.com/pirateape/apeguard-action) — Run ApeGuard scans in CI/CD with SARIF upload
- [Unified Zero Trust Framework](https://github.com/pirateape/unified-zero-trust-framework) — 8-pillar maturity model aligned to CISA ZTMM

---

*Azure Security Audit Framework v2.0 — 51 KQL · 43 PowerShell · 15 Policies · 6 Workbooks · 7 Alert Rules · 2 Playbooks · 8 Bicep*
