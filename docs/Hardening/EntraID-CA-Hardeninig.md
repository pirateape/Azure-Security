# Tools That Cover Azure Hardening, Entra ID, Conditional Access & Identity Security

## The Short Answer

No single tool covers everything — Azure infrastructure hardening, NSG/ASG configuration, Azure Policy compliance, Conditional Access gap analysis, Entra ID identity security, and threat detection all in one. However, **Microsoft's own native stack** (Defender for Cloud + Microsoft Security Exposure Management + Entra ID Protection) comes closest when combined, and a handful of open-source and third-party tools fill the remaining gaps. The optimal approach is a layered toolset.

***

## Tool-to-Domain Coverage Matrix

| Tool | Azure Policy | NSG/Network | Conditional Access | Entra ID / Identity | Auto-Remediation | Cost |
|---|---|---|---|---|---|---|
| **Microsoft Defender for Cloud** | ✅ Full | ✅ Full | ⚠️ Partial | ⚠️ Partial | ✅ Yes | Free tier + paid plans |
| **Microsoft Security Exposure Management (MSEM)** | ✅ Full | ✅ Full | ✅ Full | ✅ Full | ⚠️ Guidance only | E5 / add-on |
| **Maester** | ❌ No | ❌ No | ✅ Full | ✅ Full | ❌ Report only | Free (open source) |
| **CISA ScubaGear** | ❌ No | ❌ No | ✅ Full | ✅ Full | ❌ Report only | Free (open source) |
| **PSRule for Azure** | ✅ Full | ✅ Full | ❌ No | ❌ No | ❌ Pre-deploy only | Free (open source) |
| **Prowler** | ✅ Full | ✅ Full | ⚠️ Partial | ⚠️ Partial | ⚠️ Fixer (limited) | Free (open source) + paid |
| **Azure Tenant Security (AzTS)** | ✅ Full | ✅ Full | ❌ No | ❌ No | ❌ Report only | Free (Microsoft CSEO) |
| **Prisma Cloud (Palo Alto)** | ✅ Full | ✅ Full | ❌ No | ⚠️ Partial | ✅ Yes | Enterprise pricing |
| **CrowdStrike Falcon Cloud** | ⚠️ Partial | ⚠️ Partial | ❌ No | ✅ Full | ⚠️ Detection focus | Enterprise pricing |

***

## Tier 1: Microsoft Native Tools (The Foundation)

### Microsoft Defender for Cloud

The closest thing to an all-in-one for **Azure infrastructure** security. It acts as both a Cloud Security Posture Management (CSPM) and Cloud Workload Protection Platform (CWPP).[1][2]

**What it covers:**
- Continuous assessment of all Azure resources against the Microsoft Cloud Security Benchmark (420+ policy definitions)[3]
- NSG misconfiguration detection (open management ports, overly permissive rules)
- Azure Policy compliance monitoring and Secure Score
- Just-in-Time VM access controls
- Vulnerability scanning (Qualys or built-in)
- Threat detection across VMs, databases, containers, storage, Key Vault, DNS, and App Service
- Auto-provisioning of monitoring agents and endpoint protection[1]

**What it doesn't cover well:**
- Conditional Access policy analysis (it can flag MFA gaps but doesn't do deep CA policy auditing)
- Entra ID configuration hardening (focuses on Azure resources, not identity config)
- Application/service principal risk analysis

**How to enable:**
Navigate to **Defender for Cloud → Environment Settings → your subscription → Enable all plans**. The foundational CSPM tier is free; enhanced features (Defender for Servers, Containers, etc.) are paid per resource.[4]

### Microsoft Security Exposure Management (MSEM)

This is Microsoft's **newest and most comprehensive** security posture tool, released GA in November 2024. MSEM unifies signals from Defender for Cloud, Defender for Endpoint, Defender for Identity, Entra ID, and external attack surface management into a single view.[5][6]

**What it covers:**
- Unified asset discovery across endpoints, identities, cloud resources, and external attack surfaces[6]
- Attack path analysis — shows how an attacker could chain vulnerabilities to reach critical assets[5]
- Identity exposure (risky users, over-permissioned roles, stale credentials)
- Cloud posture across Azure, AWS, and GCP[7]
- Critical asset identification and protection prioritisation
- Risk-based prioritisation aligned with Gartner's CTEM framework[8]

**What makes it unique:**
MSEM correlates across workloads — it can show that a vulnerable VM + over-permissioned service principal + missing NSG rule = an exploitable attack path to a critical database. No other Microsoft tool provides this cross-domain correlation.[9]

**Requirements:** Available in the Microsoft Defender portal (`security.microsoft.com`), included with E5 licenses.[8]

### Entra ID Protection + Identity Secure Score

Built into Entra ID, this covers the identity threat detection side:[1]
- Risky sign-in detection (impossible travel, anonymous IPs, password spray)
- Risky user detection (leaked credentials, anomalous behaviour)
- Identity Secure Score with specific recommendations
- Automated risk remediation via Conditional Access integration

***

## Tier 2: Open-Source Scanning & Assessment Tools

### Maester — Entra ID & Conditional Access Focus

The **best tool for Conditional Access and Entra ID configuration auditing**. Created by Microsoft Entra ID product manager Merill Fernando and Security MVPs.[10]

**What it covers:**
- 40+ Entra ID Security Config Analyzer (EIDSCA) tests[11]
- 20+ Conditional Access policy tests (break-glass exclusions, MFA coverage, legacy auth blocking)[12]
- CISA SCuBA baseline tests (integrated as a test suite)[13]
- CIS Microsoft 365 Foundations Benchmark controls[13]
- Conditional Access What-If regression testing via Graph API[14]
- Automatic test generation from your existing CA policies[15]
- Validates that CA policy security groups are protected by Restricted Management Admin Units[16]

**How to use:**
```powershell
Install-Module Maester -Scope CurrentUser
md maester-tests && cd maester-tests
Install-MaesterTests .\tests
Connect-MgGraph
Invoke-Maester
```

**Automation:** Schedule via Azure DevOps pipelines to run nightly and send reports to Teams/email. The Maester team provides a GitHub Actions template for this.[17]

### CISA ScubaGear — M365 Security Baselines

Developed by the US Cybersecurity and Infrastructure Security Agency (CISA), ScubaGear assesses your entire M365 tenant against the SCuBA Secure Configuration Baselines.[18][19]

**What it covers:**
- **Entra ID**: Identity and access management policies
- **Defender**: Advanced threat protection settings
- **Exchange Online**: Email security and compliance
- **SharePoint**: Document collaboration and access controls
- **Teams**: Communication and meeting security policies
- **Power BI & Power Platform**: Data visualisation and low-code security

Each control is mapped to **NIST SP 800-53** and **MITRE ATT&CK** frameworks.[18]

**How to use:**
```powershell
Install-Module -Name ScubaGear
Initialize-SCuBA  # Install dependencies
Invoke-SCuBA -ProductNames *  # Assess all products
```

Outputs HTML, JSON, and CSV reports with pass/fail/warning status per control.[20]

### PSRule for Azure — Infrastructure-as-Code Security

PSRule validates your **Azure Bicep/ARM templates** and deployed resources against 500+ pre-built rules aligned to the Azure Well-Architected Framework.[21][22]

**What it covers:**
- NSG rule validation (blocking open inbound from `*`, ensuring flow logs enabled)
- Azure Policy alignment checks
- Storage account security (HTTPS-only, network restrictions)
- Key Vault access policies
- VM encryption and endpoint protection
- Resource naming conventions and tagging

**Key strength:** It works **before deployment** in your CI/CD pipeline, catching misconfigurations in pull requests before they ever reach Azure.[23][24]

```powershell
Install-Module -Name 'PSRule.Rules.Azure' -Scope CurrentUser
Export-AzRuleData -OutputPath 'out/templates/'
Assert-PSRule -Module 'PSRule.Rules.Azure' -InputPath 'out/templates/'
```

### Prowler — Multi-Cloud Security Scanner

An open-source tool with 160+ Azure-specific checks covering compute, storage, databases, AKS, ACR, and Microsoft Defender configuration.[25][26]

**What it covers:**
- Misconfiguration detection across Azure services
- IAM and privilege escalation risk analysis
- Compliance checks (CIS, NIST, PCI-DSS, SOC 2, HIPAA)
- MITRE ATT&CK mapping of findings[27]
- **Prowler Fixer**: Auto-remediation for selected misconfigurations[27]

**Unique advantage:** Multi-cloud — same tool works across Azure, AWS, GCP, and Kubernetes.[26][28]

### Azure Tenant Security Solution (AzTS)

Built by Microsoft's internal CSEO team, AzTS scans large numbers of subscriptions in a centralised model using Azure Functions.[29][30]

**What it covers:**
- Resource configuration compliance across many subscriptions
- Transition path from custom controls to native Azure Policy/Defender-based approach
- Central scan model with Reader-level managed identity access
- Web dashboard for visualising compliance results

**Note:** AzTS hasn't been actively updated since 2022 and Microsoft is transitioning its capabilities into Defender for Cloud and MSEM.[30][31]

***

## Tier 3: Enterprise Third-Party Tools

### Prisma Cloud (Palo Alto Networks)

Full CNAPP platform with CSPM, CWPP, CIEM, IaC scanning, and container security.[32]
- Strongest in policy-as-code enforcement and multi-cloud compliance automation
- Lacks deep Conditional Access/Entra ID auditing
- **Pricing:** Premium enterprise tier

### CrowdStrike Falcon Cloud Security

AI-driven runtime threat detection and identity protection.[33]
- Exceptional at behavioral analytics and cloud EDR
- Includes identity threat protection (detects credential-based attacks)
- Agent-based model — not ideal for all workloads
- **Pricing:** Enterprise tier

### Wiz

CNAPP focused on agentless cloud security scanning.[32]
- Discovers attack paths across cloud resources
- Strong in vulnerability management and compliance
- Lacks Entra ID/Conditional Access depth
- **Pricing:** Enterprise tier

***

## The Recommended Stack for Full Coverage

For an organisation wanting comprehensive coverage across everything discussed in the previous reports, here's the optimal combination:

### The "Microsoft-Native + Open Source" Stack (Best Value)

| Layer | Tool | Covers |
|---|---|---|
| **Infrastructure Posture** | Microsoft Defender for Cloud (CSPM) | Azure Policy, NSG, resource compliance, vulnerability scanning, auto-remediation |
| **Unified Exposure** | Microsoft Security Exposure Management | Cross-domain attack paths, identity + cloud + endpoint correlation |
| **Identity Threats** | Entra ID Protection + Conditional Access | Risk-based sign-in/user detection, automated CA enforcement |
| **CA & Entra Config Audit** | Maester (scheduled nightly) | CA policy regression testing, EIDSCA checks, break-glass validation |
| **M365 Baseline Compliance** | CISA ScubaGear (monthly) | Full M365 security baseline assessment against NIST/MITRE |
| **Pre-Deployment IaC** | PSRule for Azure (in CI/CD) | Catch NSG/policy misconfigs in Bicep/ARM before deployment |
| **Multi-Cloud Scanning** | Prowler (weekly) | Additional Azure checks, CIS benchmarks, MITRE mapping |

### How They Work Together

```
Code Commit → PSRule catches misconfigs in PR review
                ↓
Deployment → Azure Policy (deny/modify/deployIfNotExists) enforces at ARM level
                ↓
Runtime → Defender for Cloud monitors posture + auto-provisions agents
                ↓
Identity → Entra ID Protection + CA policies evaluate every sign-in
                ↓
Nightly → Maester runs CA regression tests, alerts on drift via Teams
                ↓
Weekly → Prowler scans full Azure estate for additional findings
                ↓
Monthly → ScubaGear validates full M365 baseline compliance
                ↓
Continuous → MSEM correlates everything into unified attack paths
```

This layered approach means:
- **Misconfigurations are caught before deployment** (PSRule)
- **Dangerous configs are blocked at deployment** (Azure Policy deny)
- **Missing companion settings are auto-fixed** (Azure Policy deployIfNotExists/modify)
- **Runtime drift is detected and flagged** (Defender for Cloud)
- **Identity threats are blocked in real-time** (Entra ID Protection + CA)
- **Configuration drift in CA/Entra is detected nightly** (Maester)
- **Full compliance posture is validated regularly** (ScubaGear + Prowler)
- **Cross-domain attack paths are visualised** (MSEM)

The total cost of the open-source layer (Maester + ScubaGear + PSRule + Prowler) is **zero** — they're all free community tools. The Microsoft native layer cost depends on your licensing (E5 includes most of it; otherwise Defender for Cloud plans are per-resource).[4][8]