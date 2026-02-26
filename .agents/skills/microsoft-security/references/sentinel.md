# Microsoft Sentinel (SIEM)

## Overview
Cloud-native SIEM with AI-powered analytics, threat hunting, and automation.

## API Endpoints

Base URL: `https://management.azure.com`

### Incidents
```
GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/incidents
```

### Alerts
```
GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/alertRules
```

### Watchlists
```
GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/watchlists
```

## KQL Queries

### Log Analytics Workspace Query
```
POST https://api.loganalytics.io/v1/workspaces/{workspace-id}/query
```

Body:
```json
{
  "query": "SecurityEvent | where TimeGenerated > ago(24h) | take 100"
}
```

### Common Security Tables

| Table | Description |
|-------|-------------|
| SecurityEvent | Windows Security logs |
| Syslog | Linux syslog |
| AzureActivity | Azure activity logs |
| SigninLogs | Azure AD sign-ins |
| AuditLogs | Azure AD audits |
| OfficeActivity | M365 activity |
| ThreatIntelligenceIndicator | TI IOCs |
| CommonSecurityLog | CEF format logs |

### Hunting Queries

```kql
// Anomalous sign-in locations
SigninLogs
| where ResultType == 0
| summarize Countries = make_set(Location) by UserPrincipalName
| where array_length(Countries) > 3

// Brute force detection
SecurityEvent
| where EventID == 4625
| summarize FailedLogins = count() by TargetAccount, IpAddress, bin(TimeGenerated, 5m)
| where FailedLogins > 10

// Suspicious process creation
SecurityEvent
| where EventID == 4688
| where NewProcessName has_any ("powershell", "cmd", "wscript", "cscript")
| where CommandLine has_any ("-enc", "-exec bypass", "downloadstring")

// Data exfiltration indicators
CommonSecurityLog
| where DeviceVendor == "Palo Alto Networks"
| where BytesSent > 100000000
| summarize TotalSent = sum(BytesSent) by SourceIP, DestinationIP
```

## Analytics Rules

### Create Scheduled Rule
```python
def create_analytics_rule(token, subscription, rg, workspace, rule_name, query):
    """Create scheduled analytics rule."""
    url = f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/alertRules/{rule_name}"
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "kind": "Scheduled",
        "properties": {
            "displayName": rule_name,
            "enabled": True,
            "query": query,
            "queryFrequency": "PT5H",  # Every 5 hours
            "queryPeriod": "PT5H",
            "severity": "High",
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
            "tactics": ["InitialAccess"],
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0
        }
    }
    
    response = requests.put(url, headers=headers, json=payload, params={"api-version": "2022-11-01"})
    return response.json()
```

## Automation Rules & Playbooks

### Automation Rule
Trigger Logic Apps based on incident creation/update:
```json
{
  "displayName": "Auto-assign high severity",
  "triggeringLogic": {
    "isEnabled": true,
    "triggersOn": "Incidents",
    "triggersWhen": "Created",
    "conditions": [{
      "conditionType": "Property",
      "conditionProperties": {
        "propertyName": "IncidentSeverity",
        "operator": "Equals",
        "propertyValues": ["High"]
      }
    }]
  },
  "actions": [{
    "actionType": "ModifyProperties",
    "actionConfiguration": {
      "owner": {
        "email": "soc@company.com"
      }
    }
  }]
}
```

### Logic App Integration
- Enrich incidents with external threat intel
- Auto-remediate common alerts
- Notify via Teams/Slack/email
- Create tickets in ITSM

## Watchlists

IOC and reference data management:
```python
def create_watchlist(token, subscription, rg, workspace, name, items):
    """Create watchlist for IOCs or reference data."""
    url = f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/watchlists/{name}"
    
    payload = {
        "properties": {
            "displayName": name,
            "provider": "Custom",
            "source": "api",
            "itemsSearchKey": "value",
            "rawContent": "value,description\n" + "\n".join([f"{i['value']},{i['desc']}" for i in items])
        }
    }
    
    response = requests.put(url, headers=headers, json=payload, params={"api-version": "2022-11-01"})
    return response.json()
```

Use in queries:
```kql
let MaliciousIPs = _GetWatchlist('MaliciousIPs') | project IPAddress;
CommonSecurityLog
| where SourceIP in (MaliciousIPs) or DestinationIP in (MaliciousIPs)
```
