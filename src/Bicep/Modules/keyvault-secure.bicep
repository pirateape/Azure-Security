@description('Location for all resources')
param location string = resourceGroup().location

@description('Name of the Key Vault')
param keyVaultName string

@description('SKU for the Key Vault')
param sku object = {
  family: 'A'
  name: 'standard'
}

@description('Tenant ID for the Key Vault')
param tenantId string = subscription().tenantId

@description('Enable soft delete')
param enableSoftDelete bool = true

@description('Soft delete retention days')
param softDeleteRetentionDays int = 90

@description('Enable purge protection')
param enablePurgeProtection bool = true

@description('Enable RBAC authorization')
param enableRbacAuthorization bool = true

@description('Default network action')
param defaultAction string = 'Deny'

@description('Allowed IP ranges')
param ipRules array = []

@description('Allowed virtual network subnet IDs')
param virtualNetworkRules array = []

@description('Enable private endpoint')
param enablePrivateEndpoint bool = false

@description('Private endpoint subnet ID')
param privateEndpointSubnetId string = ''

@description('Tags for the Key Vault resource')
param tags object = {}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  tags: tags
  properties: {
    tenantId: tenantId
    sku: sku
    enableSoftDelete: enableSoftDelete
    softDeleteRetentionInDays: softDeleteRetentionDays
    enablePurgeProtection: enablePurgeProtection
    enableRbacAuthorization: enableRbacAuthorization
    networkAcls: {
      defaultAction: defaultAction
      bypass: 'AzureServices'
      ipRules: ipRules
      virtualNetworkRules: virtualNetworkRules
    }
  }
}

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-04-01' = if (enablePrivateEndpoint && privateEndpointSubnetId != '') {
  name: '${keyVaultName}-pe'
  location: location
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${keyVaultName}-plsc'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

output keyVaultId string = keyVault.id
output keyVaultUri string = keyVault.properties.vaultUri
output privateEndpointId string = enablePrivateEndpoint && privateEndpointSubnetId != '' ? privateEndpoint.id : ''
