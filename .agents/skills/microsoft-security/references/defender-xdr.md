# Defender XDR (Extended Detection and Response)

## Overview
Unified security across endpoints, identities, email, and cloud apps.

## Incident Management

### List Incidents
```
GET https://graph.microsoft.com/v1.0/security/incidents
```

Query parameters:
- `$filter`: OData filter
- `$orderby`: Sort field
- `$top`: Limit results
- `$skip`: Pagination offset

### Filter Examples
```
// High severity incidents
$filter=severity eq 'high'

// Active incidents
$filter=status eq 'active'

// Time range
$filter=createdDateTime ge 2024-01-01T00:00:00Z

// Combined
$filter=severity eq 'high' and status eq 'active'
```

### Incident Schema
```json
{
  "id": "incident-id",
  "displayName": "Multi-stage incident involving Initial access & Execution",
  "severity": "high",
  "status": "active",
  "classification": "truePositive",
  "determination": "malware",
  "createdDateTime": "2024-01-15T10:00:00Z",
  "lastUpdateDateTime": "2024-01-15T12:00:00Z",
  "assignedTo": "analyst@company.com",
  "alerts": [...],
  "comments": [...],
  "tags": ["ransomware", "lateral-movement"]
}
```

### Update Incident
```python
def update_incident(token, incident_id, status, classification, comment):
    """Update incident status and classification."""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "status": status,  # active, resolved, redirected
        "classification": classification,  # truePositive, falsePositive, benignPositive
        "comment": comment
    }
    
    response = requests.patch(
        f"https://graph.microsoft.com/v1.0/security/incidents/{incident_id}",
        headers=headers,
        json=payload
    )
    return response.json()
```

## Alert Management

### List Alerts
```
GET https://graph.microsoft.com/v1.0/security/alerts_v2
```

### Alert Schema
```json
{
  "id": "alert-id",
  "title": "Suspicious PowerShell command line",
  "severity": "high",
  "status": "new",
  "category": "Execution",
  "classification": null,
  "determination": null,
  "serviceSource": "microsoftDefenderForEndpoint",
  "detectorId": "defender-rule-id",
  "createdDateTime": "2024-01-15T10:00:00Z",
  "evidence": [...],
  "mitreTechniques": ["T1059.001"]
}
```

## Advanced Hunting

### Execute Query
```
POST https://graph.microsoft.com/v1.0/security/runHuntingQuery
```

Body:
```json
{
  "query": "DeviceProcessEvents | where FileName == 'powershell.exe' | take 100"
}
```

### Common Hunting Queries

```kql
// Persistence via scheduled tasks
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Credential access attempts
DeviceEvents
| where ActionType == "CredentialsAccess"
| project Timestamp, DeviceName, AccountName, ActionType

// Lateral movement via WMI
DeviceProcessEvents
| where FileName =~ "wmic.exe"
| where ProcessCommandLine contains "/node:"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

## Device Management

### List Devices
```
GET https://graph.microsoft.com/v1.0/security/microsoft/graph/devices
```

### Device Actions
- Isolate device
- Run antivirus scan
- Collect investigation package
- Restrict app execution

```python
def isolate_device(token, device_id, comment):
    """Isolate device from network."""
    headers = {"Authorization": f"Bearer {token}"}
    
    response = requests.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{device_id}/isolate",
        headers=headers,
        json={"Comment": comment, "IsolationType": "Full"}
    )
    return response.json()
```

## Threat Intelligence

### Create Indicator
```python
def create_ti_indicator(token, indicator_type, value, action, title):
    """Create threat intelligence indicator."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    payload = {
        "targetProduct": "Microsoft Defender ATP",
        "action": action,  # alert, block, allow
        "title": title,
        "description": "Created via API",
        "indicatorType": indicator_type,  # IpAddress, DomainName, Url, FileSha256
        "indicatorValue": value,
        "severity": "high"
    }
    
    response = requests.post(
        "https://graph.microsoft.com/beta/security/tiIndicators",
        headers=headers,
        json=payload
    )
    return response.json()
```
