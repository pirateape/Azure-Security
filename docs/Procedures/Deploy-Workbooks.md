# How to Deploy Azure Sentinel Workbooks (Dashboards)

This repository contains several JSON-based Azure Workbooks designed to be imported directly into your Azure Sentinel environment.

## Available Workbooks

- **IdentityPosture-Dashboard.json**: Identity risk, MFA compliance, and legacy auth tracking.
- **M365Threats-Dashboard.json**: Focuses on M365 (Exchange, SharePoint, Teams) security events.
- **ComplianceMaturity-Dashboard.json**: Maps your Azure resources against regulatory standards like CIS and NIST.
- **SOCOperations-Dashboard.json**: Tracks alert triage, analyst performance, and ingestion health.

## Deployment Instructions

### Method 1: Manual Import via Azure Portal (Recommended for Testing)

The easiest way to view these dashboards is to manually import the JSON directly into the Azure Portal:

1. Navigate to your **Microsoft Sentinel** workspace in the Azure Portal.
2. In the left-hand navigation menu under *Threat management*, click on **Workbooks**.
3. At the top of the Workbooks page, click **+ Add workbook**.
4. In the new workbook view, click the **</> (Advanced Editor)** icon in the top toolbar.
5. In the Advanced Editor, you will see a JSON input area. Delete the existing default JSON.
6. Open the raw JSON file from this repository (e.g., `src/KQL/Workbooks/IdentityPosture-Dashboard.json`).
7. Copy the entire contents of the JSON file and paste it into the Advanced Editor.
8. Click **Apply**. The workbook should now render the visualizations.
9. Click the **Save** icon (floppy disk) at the top.
10. Provide a **Title** (e.g., "AZ-Wall Identity Posture"), select the appropriate Subscription, Resource Group, and Location.
11. Click **Apply**.

### Method 2: Deployment via ARM Template (Recommended for Production)

*(Coming Soon - Pending Bicep integration)*
The workbooks can be deployed programmatically by wrapping the JSON content inside a `Microsoft.Insights/workbooks` ARM or Bicep template.

## Troubleshooting

- **No Data Showing**: Ensure you have selected the correct Workspace, Time Range, and Subscriptions from the dropdown parameters at the top of the workbook.
- **"Table not found" errors**: Some workbooks require specific data connectors to be enabled.
    - *Identity Posture* requires `SigninLogs` and `AADUserRiskEvents`.
    - *M365 Threats* requires the `Office 365` connector (`OfficeActivity` table).
    - *Compliance Maturity* uses Azure Resource Graph and does not require a specific Sentinel table, but **does** require the user to have `Reader` access to the subscriptions being queried to see the compliance data.
