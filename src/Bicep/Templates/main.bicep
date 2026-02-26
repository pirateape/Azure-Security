// AZ-Wall Security Baseline - Main Deployment Template
// Orchestrates all secure-baseline modules:
//   • Log Analytics + Microsoft Sentinel
//   • Secure Key Vault
//   • Secure Storage Account
//   • Secure VNet with NSG + Flow Logs
//   • Azure Policy assignments (Deny / Modify / DINE)
//
// Deploy at subscription scope:
//   az deployment sub create \
//     --location eastus \
//     --template-file src/Bicep/Templates/main.bicep \
//     --parameters @src/Bicep/Templates/main.parameters.json

targetScope = 'subscription'

// ─── Required parameters ────────────────────────────────────────────────────

@description('Primary Azure region for all resources')
param location string

@description('Environment abbreviation (prod, dev, staging)')
@allowed(['prod', 'dev', 'staging'])
param environment string = 'prod'

@description('Organisation / project prefix used in resource names')
@maxLength(8)
param prefix string

@description('Address space for the VNet (CIDR)')
param vnetAddressPrefix string = '10.0.0.0/16'

@description('Address prefix for the default subnet (CIDR)')
param subnetAddressPrefix string = '10.0.0.0/24'

// ─── Optional parameters ────────────────────────────────────────────────────

@description('Log Analytics workspace retention in days (90–730)')
@minValue(90)
@maxValue(730)
param logRetentionDays int = 90

@description('Enable private endpoints on Key Vault and Storage (requires a pre-existing PE subnet)')
param enablePrivateEndpoints bool = false

@description('Subnet resource ID for private endpoints (required if enablePrivateEndpoints = true)')
param privateEndpointSubnetId string = ''

@description('Soft-delete retention for Key Vault in days')
@minValue(7)
@maxValue(90)
param kvSoftDeleteRetentionDays int = 90

@description('Tags applied to all resources')
param tags object = {
  environment: environment
  managedBy: 'AZ-Wall'
  deployedWith: 'Bicep'
}

// ─── Derived names ───────────────────────────────────────────────────────────

var workspaceName      = '${prefix}-law-${environment}'
var keyVaultName       = '${prefix}-kv-${environment}'
var storageAccountName = replace('${prefix}st${environment}', '-', '')  // storage names: no hyphens
var vnetName           = '${prefix}-vnet-${environment}'
var rgName             = '${prefix}-security-rg-${environment}'

// ─── Resource Group ──────────────────────────────────────────────────────────

resource securityRg 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: rgName
  location: location
  tags: tags
}

// ─── Log Analytics + Microsoft Sentinel ─────────────────────────────────────

module sentinel '../Modules/log-analytics-sentinel.bicep' = {
  name: 'deploy-sentinel'
  params: {
    location: location
    workspaceName: workspaceName
    retentionInDays: logRetentionDays
    enableSentinel: true
    tags: tags
  }
}

// ─── Secure Key Vault ────────────────────────────────────────────────────────

module keyVault '../Modules/keyvault-secure.bicep' = {
  name: 'deploy-keyvault'
  scope: securityRg
  params: {
    location: location
    keyVaultName: keyVaultName
    enableSoftDelete: true
    softDeleteRetentionDays: kvSoftDeleteRetentionDays
    enablePurgeProtection: true
    enableRbacAuthorization: true
    defaultAction: 'Deny'
    enablePrivateEndpoint: enablePrivateEndpoints
    privateEndpointSubnetId: privateEndpointSubnetId
    tags: tags
  }
}

// ─── Secure Storage Account ──────────────────────────────────────────────────

module storage '../Modules/storage-secure.bicep' = {
  name: 'deploy-storage'
  scope: securityRg
  params: {
    location: location
    storageAccountName: storageAccountName
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultAction: 'Deny'
    enableBlobPrivateEndpoint: enablePrivateEndpoints
    blobPrivateEndpointSubnetId: privateEndpointSubnetId
    tags: tags
  }
}

// ─── Secure VNet + NSG + Flow Logs ───────────────────────────────────────────

module vnet '../Modules/vnet-secure.bicep' = {
  name: 'deploy-vnet'
  scope: securityRg
  params: {
    location: location
    vnetName: vnetName
    vnetAddressPrefix: vnetAddressPrefix
    subnetAddressPrefix: subnetAddressPrefix
    enableFlowLogs: true
    logAnalyticsWorkspaceId: sentinel.outputs.workspaceId
    flowLogsStorageAccountId: storage.outputs.storageAccountId
  }
}

// ─── Policy: Deny Public IPs ─────────────────────────────────────────────────

module policyDenyPublicIp '../Modules/policy-assignment.bicep' = {
  name: 'policy-deny-publicip'
  params: {
    assignmentName: 'deny-public-ip-${environment}'
    displayName: '[AZ-Wall] Deny Public IP Addresses'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/6c112d4e-5bc7-47ae-a041-ea2d9dccd749'
    nonComplianceMessage: 'Public IP addresses are not permitted in this environment'
    identityLocation: location
  }
}

// ─── Policy: Deny Open RDP/SSH ───────────────────────────────────────────────

module policyDenyOpenRdpSsh '../Modules/policy-assignment.bicep' = {
  name: 'policy-deny-open-rdpssh'
  params: {
    assignmentName: 'deny-open-rdpssh-${environment}'
    displayName: '[AZ-Wall] Deny NSG rules allowing RDP/SSH from Internet'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/e372f825-a257-4fb8-9175-797a8a8627d6'
    nonComplianceMessage: 'NSG rules allowing unrestricted RDP/SSH are not permitted'
    identityLocation: location
  }
}

// ─── Policy: DINE Diagnostic Settings ───────────────────────────────────────

module policyDineDiagnostics '../Modules/policy-assignment.bicep' = {
  name: 'policy-dine-diagnostics'
  params: {
    assignmentName: 'dine-diagnostics-${environment}'
    displayName: '[AZ-Wall] Deploy Diagnostic Settings to Log Analytics'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/b0f33259-77d7-4c9e-aac6-3aabcfae693c'
    parameters: {
      logAnalyticsWorkspaceId: {
        value: sentinel.outputs.workspaceId
      }
    }
    nonComplianceMessage: 'Resource must send diagnostics to the central Log Analytics workspace'
    identityLocation: location
  }
}

// ─── Outputs ─────────────────────────────────────────────────────────────────

output resourceGroupName    string = securityRg.name
output workspaceId          string = sentinel.outputs.workspaceId
output workspaceCustomerId  string = sentinel.outputs.workspaceCustomerId
output keyVaultId           string = keyVault.outputs.keyVaultId
output keyVaultUri          string = keyVault.outputs.keyVaultUri
output storageAccountId     string = storage.outputs.storageAccountId
output vnetId               string = vnet.outputs.vnetId
output subnetId             string = vnet.outputs.subnetId
output nsgId                string = vnet.outputs.nsgId
