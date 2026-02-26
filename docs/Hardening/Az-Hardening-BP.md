# Azure Hardening Best Practices: Policies, Network Security & Auto-Remediation

## Overview

This guide covers the full stack of Azure security hardening — from Network Security Groups (NSGs) and Application Security Groups (ASGs) to public IP black hole routing, Azure Policy enforcement effects, and auto-remediation strategies. The goal is to ensure that even if a resource creator forgets a security setting, Azure will either block the deployment, fix it automatically, or flag it immediately for remediation.

***

## Azure Policy: The Enforcement Engine

Azure Policy is the primary mechanism for enforcing security standards across your Azure environment. It evaluates resources during creation, updates, and ongoing compliance scans. There are several **policy effects** you can use depending on whether you want to block, fix, or audit.[1][2][3]

### Policy Effects Cheat Sheet

| Effect | Behaviour | When to Use |
|---|---|---|
| **Deny** | Blocks the resource creation or update entirely | Prevent dangerous configurations (e.g., public IPs, open RDP/SSH) |
| **Modify** | Alters resource properties during creation/update (e.g., adds tags, changes settings) | Auto-fix properties on new deployments without blocking |
| **DeployIfNotExists** | Deploys a dependent resource (e.g., diagnostic settings, encryption) if it's missing | Ensure companion configs always exist |
| **AuditIfNotExists** | Flags non-compliance but takes no action | Visibility-only mode before enforcing |
| **Audit** | Logs a warning event but allows the action | Soft enforcement / testing phase |
| **Disabled** | Policy exists but isn't evaluated | Temporarily pausing a policy |

### How Auto-Remediation Works

The `modify` and `deployIfNotExists` effects are the two that can **actively fix** resources:[3][1]

- **`modify`** evaluates **before** the request is processed by the Resource Provider. It applies changes (add, replace, or remove properties/tags) inline during creation or update. For existing non-compliant resources, you trigger a **remediation task**.[3]
- **`deployIfNotExists`** runs **after** a resource is successfully created/updated. It checks whether a related resource exists (via `existenceCondition`). If not, it deploys an ARM template to create it. Existing non-compliant resources also require a remediation task.[2]

Both effects require a **managed identity** (system-assigned or user-assigned) with the appropriate RBAC roles to perform the remediation deployment.[1]

### Creating Remediation Tasks

Remediation tasks can be created in three ways:[1]

1. **From the Remediation page** — Navigate to Policy → Remediation → select a non-compliant policy
2. **From a non-compliant policy assignment** — Go to Compliance → select the policy → Create Remediation Task
3. **During policy assignment** — Check "Create a remediation task" on the Remediation tab when assigning

PowerShell example to trigger remediation:

```powershell
Start-AzPolicyRemediation -Name 'myRemediation' `
  -PolicyAssignmentId '/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/policyAssignments/{assignmentId}'
```

**Important caveat**: Remediation tasks for `deployIfNotExists` may not automatically re-run if a resource drifts back to non-compliance after initial remediation. You may need to schedule periodic remediation tasks or use Azure Automation to handle drift detection.[4]

***

## Public IP Protection: Black Hole Routing & Deny Policies

### Deny Public IP Creation with Azure Policy

Azure provides a **built-in policy** called "Network interfaces should not have public IPs" that denies NIC configurations with public IPs:[5]

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Network/networkInterfaces"
      },
      {
        "not": {
          "field": "Microsoft.Network/networkInterfaces/ipconfigurations[*].publicIpAddress.id",
          "notLike": "*"
        }
      }
    ]
  },
  "then": {
    "effect": "deny"
  }
}
```

You can also **block creation of Public IP address resources entirely** using a deny policy on the resource type itself:[6][7]

```json
{
  "if": {
    "field": "type",
    "equals": "Microsoft.Network/publicIPAddresses"
  },
  "then": {
    "effect": "deny"
  }
}
```

The Azure Landing Zone (Enterprise-Scale) repository includes a `Deny-PublicIP` policy definition for this exact purpose, though it's been superseded by a parametrised built-in version that allows Audit/Deny/Disabled modes.[7]

**Exceptions handling**: Azure Policy is "all or nothing" per scope — you can't exempt specific AD groups. Use **policy exemptions** scoped to specific resource groups or resources for legitimate use cases (e.g., bastion hosts, WAF endpoints). Alternatively, use RBAC to restrict who can create public IPs.[8][9]

### Block Open RDP/SSH to the Internet

A common custom deny policy blocks NSG rules that expose RDP (3389) or SSH (22) to any source (`*`):[10]

```json
{
  "if": {
    "allOf": [
      {
        "field": "type",
        "equals": "Microsoft.Network/networkSecurityGroups/securityRules"
      },
      {
        "field": "Microsoft.Network/networkSecurityGroups/securityRules/access",
        "equals": "Allow"
      },
      {
        "field": "Microsoft.Network/networkSecurityGroups/securityRules/direction",
        "equals": "Inbound"
      },
      {
        "field": "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix",
        "in": ["*", "Internet", "0.0.0.0/0"]
      },
      {
        "anyOf": [
          {
            "field": "Microsoft.Network/networkSecurityGroups/securityRules/destinationPortRange",
            "in": ["22", "3389"]
          }
        ]
      }
    ]
  },
  "then": {
    "effect": "deny"
  }
}
```

### Black Hole Routing with User-Defined Routes (UDRs)

A **black hole route** uses `Next Hop Type: None` in a User-Defined Route (UDR) to silently drop traffic destined for specific address prefixes:[11][12]

```bash
az network route-table route create \
  --resource-group rg-routing-demo \
  --route-table-name rt-custom-routes \
  --name route-blackhole \
  --address-prefix 10.99.0.0/16 \
  --next-hop-type None
```

Azure UDR next hop types:[12]

| Next Hop Type | Description |
|---|---|
| **VirtualAppliance** | Send traffic to a specific IP (firewall, NVA) |
| **VirtualNetworkGateway** | Send traffic through VPN or ExpressRoute |
| **VnetLocal** | Route to the local virtual network |
| **Internet** | Route directly to the internet |
| **None** | Drop the traffic (black hole) |

Use black hole routes to:
- Prevent specific subnets from reaching certain destinations
- Drop traffic to known-malicious IP ranges
- Enforce network segmentation by dropping cross-tier traffic that shouldn't flow

Azure also automatically creates default black hole routes for RFC 1918 private address ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and RFC 6598 (100.64.0.0/10) to prevent routing leakage.[11]

***

## Network Security Groups (NSGs): Hardening Best Practices

### Default Rules to Understand

Every NSG includes these default rules that cannot be deleted:[13][14]

| Rule | Priority | Direction | Action | Notes |
|---|---|---|---|---|
| AllowVNetInBound | 65000 | Inbound | Allow | All intra-VNet traffic — overly permissive by default |
| AllowAzureLoadBalancerInBound | 65001 | Inbound | Allow | Required for health probes |
| DenyAllInBound | 65500 | Inbound | Deny | Catch-all deny |
| AllowVNetOutBound | 65000 | Outbound | Allow | All intra-VNet traffic |
| AllowInternetOutBound | 65001 | Outbound | Allow | **Overly permissive** — consider restricting |
| DenyAllOutBound | 65500 | Outbound | Deny | Catch-all deny |

### NSG Hardening Recommendations

- **Restrict the `AllowInternetOutBound` default**: Add higher-priority deny rules to block unnecessary outbound traffic, allowing only required ports via explicit allow rules[14][13]
- **Never use `*` as a source for inbound allow rules**: This exposes services to the entire internet. Use specific IPs, service tags, or ASGs instead[15]
- **Space priority numbers**: Use intervals like 100, 200, 300 so you can insert rules later without renumbering (e.g., 120, 220, 320)[13]
- **Use descriptive rule names**: A name like `Allow-HTTPS-From-AppGW` is far more maintainable than `Rule1`[13]
- **Associate NSGs at the subnet level**, not individual NICs, to reduce management overhead. Use NIC-level NSGs only for exceptions[13]
- **Enable NSG Flow Logs (Version 2)**: Essential for visibility — sends traffic logs to Azure Storage in JSON format for SIEM ingestion. Version 2 includes flow state and bandwidth metrics[13]
- **Use service tags** instead of raw IP ranges for Azure services (e.g., `AzureLoadBalancer`, `Storage`, `Sql.EastUS`). Microsoft maintains the IP mappings automatically[13]

### NSG vs Azure Firewall

| Feature | NSG | Azure Firewall |
|---|---|---|
| OSI Layers | 3-4 | 3-4-7 |
| FQDN Filtering | No | Yes |
| Threat Intelligence | No | Yes |
| NAT | No | SNAT + DNAT |
| ASG Support | Yes | No |
| Cost | Free | Per deployment hour + data processing |

Use both together: NSGs for host/subnet-level filtering and Azure Firewall for perimeter threat detection and application-layer inspection.[13]

***

## Application Security Groups (ASGs): Simplifying Rule Management

ASGs let you group VMs logically by workload (e.g., "WebServers", "DatabaseServers") and reference those groups directly in NSG rules instead of managing IP addresses.[16][17]

### How ASGs Work

1. **Create an ASG** (e.g., `AsgWeb`, `AsgLogic`, `AsgDb`)
2. **Assign VM NICs** to the appropriate ASG
3. **Reference ASGs in NSG rules** as source or destination

Example NSG rules using ASGs:[17]

| Priority | Source | Destination | Port | Protocol | Access |
|---|---|---|---|---|---|
| 100 | Internet | AsgWeb | 80 | TCP | Allow |
| 110 | AsgLogic | AsgDb | 1433 | TCP | Allow |
| 120 | * | AsgDb | 1433 | Any | Deny |

### ASG Best Practices

- **Plan groupings by application tier**: Create separate ASGs for web, app, and database tiers to enforce micro-segmentation[18]
- **Use descriptive names**: `WebServerASG` and `DatabaseASG` instead of `ASG1`[18]
- **Combine ASGs with NSGs**: NSGs provide broad network-level security while ASGs offer granular, application-centric control within those NSGs[18]
- **Leverage dynamic membership**: When VMs are added/removed from an ASG, rules automatically apply — critical for autoscaling scenarios[16]
- **A NIC can belong to multiple ASGs**: Up to Azure limits, enabling overlapping security profiles[17]
- **Zero-trust alignment**: By default, deny all traffic between ASGs and only allow what's explicitly permitted[18]

***

## Azure Policy Initiatives & Microsoft Cloud Security Benchmark

### Microsoft Cloud Security Benchmark (MCSB)

The MCSB is the **default security initiative** in Microsoft Defender for Cloud. It maps directly to Azure Policy definitions and covers:[19][20]

- **Network Security (NS)**: Segmentation, NSG rules, private endpoints
- **Identity Management (IM)**: MFA, Conditional Access, PIM
- **Privileged Access (PA)**: JIT access, RBAC
- **Data Protection (DP)**: Encryption at rest/in transit
- **Logging and Threat Detection (LT)**: Diagnostic settings, flow logs
- **Posture and Vulnerability Management (PV)**: Patching, endpoint protection
- **Backup and Recovery (BR)**: Azure Backup configuration

MCSB v2 (preview) includes **420+ Azure Policy built-in definitions** mapped to security controls, plus a new AI Security domain.[19]

### Key Built-In Policy Initiatives for Security

Assign these at the **management group level** to ensure all subscriptions inherit them:

- **Microsoft cloud security benchmark** — The default Defender for Cloud initiative with comprehensive controls[20]
- **CIS Microsoft Azure Foundations Benchmark** — Maps to CIS controls
- **NIST SP 800-53** — For compliance-heavy environments

### Recommended Security Policies to Assign

| Policy | Effect | Purpose |
|---|---|---|
| Network interfaces should not have public IPs | Deny | Block public IP attachment to NICs |
| Deny creation of Public IP addresses | Deny | Block public IP resource creation entirely |
| NSG rules should restrict RDP/SSH from Internet | Deny | Block open management ports |
| Deploy diagnostic settings for NSGs to Log Analytics | DeployIfNotExists | Auto-configure NSG diagnostics |
| Storage accounts should restrict network access | Deny/Audit | Prevent public blob access |
| SQL servers should use private endpoints | Audit/Deny | Enforce private connectivity |
| Azure Key Vault should disable public network access | Deny | Protect secrets |
| Managed disks should use specific set of disk encryption types | Audit/Deny | Enforce encryption |
| VMs should have endpoint protection | AuditIfNotExists | Detect missing AV |

***

## Ensuring Misconfigurations Are Fixed: The Auto-Fix Strategy

### Strategy 1: Deny (Prevent the Problem)

Use `deny` effect policies for configurations that should **never exist**:
- Public IPs on NICs[5]
- Open RDP/SSH from the internet[10]
- Storage accounts with public access
- Resources in unapproved regions

This is the strongest control — it blocks the ARM deployment entirely.

### Strategy 2: Modify (Fix Inline During Deployment)

Use `modify` effect for settings that should always be a certain value:[3]
- Force specific tags on all resources (e.g., `CostCenter`, `Environment`)
- Ensure minimum TLS version on storage accounts
- Set HTTPS-only on App Services
- Configure network rules on Key Vaults

The `modify` effect changes properties **before** the Resource Provider processes the request, so the resource is compliant from the moment of creation.

### Strategy 3: DeployIfNotExists (Deploy Companion Resources)

Use `deployIfNotExists` for resources that need a companion configuration:[21][2]
- Deploy diagnostic settings for all NSGs to Log Analytics
- Deploy Azure Monitor agents on VMs
- Enable TDE on SQL databases
- Configure backup policies on VMs

For **new resources**, the policy triggers automatically after provisioning. For **existing resources**, run a remediation task.

### Strategy 4: Defender for Cloud Recommendations + Auto-Fix

Microsoft Defender for Cloud provides security recommendations with a **Fix** button that generates the remediation action for you:[22]

1. Navigate to **Defender for Cloud → Recommendations**
2. Select a recommendation (e.g., "Management ports should be closed on VMs")
3. Click **Fix** to apply the recommended change

For automated remediation at scale:[23][24]
- Enable **auto-provisioning** in Defender for Cloud → Environment Settings → Defender Plans → toggle on agents/extensions
- Defender for Cloud will automatically push MDE agents, monitoring agents, and vulnerability scanners to eligible VMs

### Strategy 5: Azure Automation + Scheduled Remediation

Since Azure Policy remediation tasks don't automatically re-trigger after drift, implement a scheduled approach:

```powershell
# Scheduled via Azure Automation Runbook — runs daily
$assignments = Get-AzPolicyAssignment | Where-Object {
    $_.Properties.policyDefinitionAction -in @('deployIfNotExists','modify')
}

foreach ($assignment in $assignments) {
    $nonCompliant = Get-AzPolicyState -PolicyAssignmentName $assignment.Name |
        Where-Object { $_.ComplianceState -eq 'NonCompliant' }

    if ($nonCompliant.Count -gt 0) {
        Start-AzPolicyRemediation -Name "auto-remediate-$($assignment.Name)" `
            -PolicyAssignmentId $assignment.PolicyAssignmentId
    }
}
```

***

## Recommended Layered Security Architecture

### Layer 1: Perimeter (Azure Firewall + DDoS Protection)
- Deploy Azure Firewall in a hub VNet with threat intelligence enabled
- Enable **Azure DDoS Protection** on VNets with public-facing resources[25]
- Use forced tunnelling (UDR 0.0.0.0/0 → Virtual Appliance) to route all egress through the firewall

### Layer 2: Network Segmentation (NSGs + ASGs + UDRs)
- Associate NSGs with every subnet
- Use ASGs to define application-tier boundaries[16][17]
- Deploy black hole routes (Next Hop: None) for unwanted traffic paths[12]
- Enable NSG Flow Logs v2 for all NSGs

### Layer 3: Policy Enforcement (Azure Policy)
- Assign MCSB initiative at the management group level[20]
- Layer custom deny policies for public IPs, open management ports, and unapproved regions
- Use modify/deployIfNotExists for auto-remediation of settings and companion resources[1]

### Layer 4: Continuous Monitoring (Defender for Cloud)
- Enable Defender for Cloud on all subscriptions
- Review Secure Score regularly
- Enable auto-provisioning for endpoint protection and monitoring agents[23]
- Use Security Recommendations with Fix actions[22]

### Layer 5: Identity & Access (Entra ID)
- Enforce MFA on all accounts
- Use Conditional Access policies
- Enable Privileged Identity Management (PIM) for JIT admin access
- Review access quarterly[26]

***

## Quick Reference: Policy Effect Decision Tree

```
Is this configuration NEVER acceptable?
├── YES → Use "deny" effect (blocks deployment)
└── NO → Should the setting be auto-corrected?
    ├── YES → Is it a property on the resource itself?
    │   ├── YES → Use "modify" effect (fixes inline)
    │   └── NO → Is it a companion/child resource?
    │       └── YES → Use "deployIfNotExists" (deploys the companion)
    └── NO → Use "audit" or "auditIfNotExists" (flag only)
```

This decision tree ensures you pick the right enforcement level: block what shouldn't exist, auto-fix what can be corrected, and audit everything else for visibility.