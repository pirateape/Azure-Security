# Azure Incident Response Playbook

This playbook outlines the standard procedures for identifying, responding to, and recovering from security incidents in the Azure environment. Based on the NIST SP 800-61 framework.

## 1. Preparation
- **Contact List:** Ensure the contact list for the CSIRT (Computer Security Incident Response Team), IT Leads, and Legal/PR is up to date in `docs/Contacts.md`.
- **RBAC Roles:** Security responders should have the `Security Reader` and `Reader` roles at the subscription or management group level to investigate issues, and `Security Admin` for remediation actions.
- **Log Forwarding:** Ensure all critical resources are forwarding diagnostic logs to a central Log Analytics Workspace.
- **Alerting:** Configure Azure Monitor / Microsoft Defender for Cloud alerts to notify the `#security-alerts` channel.

## 2. Detection and Analysis
When an alert triggers (e.g., from Defender for Cloud or Microsoft Sentinel):
1. **Triage:** Review the alert severity, affected resources, and specific triggered logic.
2. **investigate:**
   - Run relevant KQL queries in the Log Analytics Workspace (see `src/KQL/`).
   - Check Entra ID Sign-in logs for suspicious authentications (e.g., MFA bypassed, risky IP).
   - Check Resource Activity Logs for administrative actions taken by compromised accounts.
3. **Categorize:** Classify the incident (e.g., Credential Compromise, Data Exfiltration, Resource Hijacking/Cryptomining, Malware Infection).
4. **Declare:** If a true positive is confirmed, formally declare a security incident and open a tracking ticket.

## 3. Containment
*Immediate actions to prevent further damage.*
1. **Identity Containment:**
   - Revoke active sessions for compromised users.
   - Force password resets.
   - Disable compromised accounts temporarily.
   - Restrict access via Conditional Access policies.
2. **Resource Containment:**
   - Apply a restrictive Network Security Group (NSG) to block traffic to/from compromised VMs or App Services.
   - Shut down or isolate compromised VMs (`Stop-AzVM`).
   - For malicious IPs, add block rules to the Azure Firewall or WAF.
   - Revoke compromised Service Principal credentials/certificates.

## 4. Eradication
*Remove the threat from the environment.*
1. **Malware/Backdoors:** Rebuild infected VMs from a known-good configuration rather than attempting to clean them (Immutable Infrastructure).
2. **Permissions:** Remove any unauthorized RBAC assignments, App Registrations, or API permissions granted by the attacker.
3. **Secrets:** Rotate all keys, secrets, and certificates stored in Key Vaults that the attacker may have accessed.
4. **Vulnerabilities:** Apply missing patches, enable Endpoint Protection, or correct unsafe configurations (e.g., enabling HTTPS only) that allowed the initial vector.

## 5. Recovery
*Restore systems to normal operation.*
1. **Restore:** Redeploy applications, VMs, and PaaS resources using IaC (Bicep/ARM).
2. **Data Restoration:** Restore from Azure Backup or geo-redundant storage if data was encrypted (ransomware) or deleted.
3. **Monitor:** Perform heightened monitoring on the recovered resources for 48 hours.

## 6. Post-Incident Activity
1. **Lessons Learned:** Within 72 hours, hold a post-mortem meeting.
2. **Update Playbooks:** Revise this playbook and KQL detection rules based on the incident findings.
3. **Reporting:** Generate the final incident report for stakeholders.
