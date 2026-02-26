# Threat Model Template (STRIDE)

This template is designed to conduct Threat Modeling for new architectures or workload deployments in Azure.

## Overview
**Architecture Name:** [Insert Name]
**Date:** [YYYY-MM-DD]
**Reviewer(s):** [Insert Names]
**Description:** [Briefly describe the architecture, its purpose, data classification, and primary components.]

---

## 🔒 1. Spoofing
*Can an attacker pretend to be something or someone else?*

| Threat | Description | Azure Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| **Spoofing User Identity** | An attacker steals or guesses user credentials. | Enforce Entra ID MFA, Risk-based Conditional Access. | [Open/Mitigated] |
| **Spoofing Service Principal** | An attacker obtains client secret/certificate. | Use Managed Identities instead of Service Principals; store secrets in Key Vault; rotate secrets regularly; use short-lived certs. | [Open/Mitigated] |
| **Spoofing System Provider** | DNS hijacking, spoofed application endpoints. | Use TLS certificates from trusted CA; implement DNSSEC; Azure Front Door / WAF custom domain verification. | [Open/Mitigated] |

## 🛠️ 2. Tampering
*Can an attacker modify data in transit or at rest?*

| Threat | Description | Azure Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| **Tampering with Data at Rest** | Modifying backup data or database records. | Azure Storage / Managed Disks encryption at rest (CMK or PMK); RBAC restrictions on storage accounts; immutable blob storage. | [Open/Mitigated] |
| **Tampering with Data in Transit** | Man-in-the-Middle (MitM) altering requests. | Enforce HTTPS-Only; TLS 1.2 minimum; Disable HTTP/FTP. | [Open/Mitigated] |
| **Tampering with Code/Configs** | Changing app settings, deployments. | CI/CD pipeline security; branch protection rules; remove write access for users in Production; deploy only via automated pipelines. | [Open/Mitigated] |

## 📜 3. Repudiation
*Can an attacker perform an action without consequence or traceability?*

| Threat | Description | Azure Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| **Action Deniability** | A user performs a malicious action and deletes logs or denies doing it. | Enable Azure Activity Logs forwarding to a central, immutable Log Analytics Workspace. | [Open/Mitigated] |
| **App Level Deniability** | Application fails to log transactions securely. | Integrate App Insights; forward diagnostic logs from App Services/Key Vault to Sentinel. | [Open/Mitigated] |

## 🕵️ 4. Information Disclosure
*Can an attacker access confidential data they aren't authorized to see?*

| Threat | Description | Azure Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| **Data Leakage** | Private data exposed to the public internet. | Disable public blob access; configure VNet Service Endpoints / Private Links; use Azure Policy to block public access. | [Open/Mitigated] |
| **Credential/Key Leakage** | Hardcoded secrets in source code or connection strings. | Do not store secrets in App Settings or Code; reference Azure Key Vault explicitly; use Azure Defender for Cloud secret scanning. | [Open/Mitigated] |

## 🛑 5. Denial of Service (DoS)
*Can an attacker disrupt the service availability?*

| Threat | Description | Azure Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| **Resource Exhaustion** | Volumetric attacks overwhelming the frontend. | Azure DDoS Protection; WAF Rate Limiting; Front Door caching. | [Open/Mitigated] |
| **Application DoS** | CPU/Memory exhaustion via slowloris or heavy queries. | Enable Azure App Service Auto-scaling; implement application-level throttling and timeouts. | [Open/Mitigated] |

## 🚀 6. Elevation of Privilege
*Can an attacker gain higher permissions than intended?*

| Threat | Description | Azure Mitigation Strategy | Status |
| :--- | :--- | :--- | :--- |
| **RBAC Escalation** | Compromised "Contributor" account grants "Owner" to another. | Enforce strict Least Privilege (e.g., specific Action/NotAction scopes); use PIM (Privileged Identity Management) for JIT access. | [Open/Mitigated] |
| **Application Compromise** | Web App logic flaw leads to underlying VM execution. | Run App Services with Managed Identities; do not give the Managed Identity excessive permissions (e.g., only `Key Vault Secrets User`). | [Open/Mitigated] |

---
## Summary of Action Items
1. [Insert required changes or tickets to track remediation]
2. ...
