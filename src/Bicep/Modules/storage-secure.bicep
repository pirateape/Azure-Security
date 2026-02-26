@description('Location for all resources')
param location string = resourceGroup().location

@description('Name of the storage account')
param storageAccountName string

@description('SKU for the storage account')
param sku object = {
  name: 'Standard_GRS'
  tier: 'Standard'
}

@description('Kind of storage account')
param kind string = 'StorageV2'

@description('Enable HTTPS traffic only')
param supportsHttpsTrafficOnly bool = true

@description('Minimum TLS version')
param minimumTlsVersion string = 'TLS1_2'

@description('Allow blob public access')
param allowBlobPublicAccess bool = false

@description('Allow shared key access')
param allowSharedKeyAccess bool = false

@description('Default network action')
param defaultAction string = 'Deny'

@description('Allowed IP ranges')
param ipRules array = []

@description('Allowed virtual network subnet IDs')
param virtualNetworkRules array = []

@description('Enable private endpoint for blob')
param enableBlobPrivateEndpoint bool = false

@description('Private endpoint subnet ID for blob')
param blobPrivateEndpointSubnetId string = ''

@description('Tags for the Storage Account resource')
param tags object = {}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  kind: kind
  sku: sku
  tags: tags
  properties: {
    supportsHttpsTrafficOnly: supportsHttpsTrafficOnly
    minimumTlsVersion: minimumTlsVersion
    allowBlobPublicAccess: allowBlobPublicAccess
    allowSharedKeyAccess: allowSharedKeyAccess
    networkAcls: {
      bypass: 'AzureServices'
      virtualNetworkRules: virtualNetworkRules
      ipRules: ipRules
      defaultAction: defaultAction
    }
  }
}

resource blobPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-04-01' = if (enableBlobPrivateEndpoint && blobPrivateEndpointSubnetId != '') {
  name: '${storageAccountName}-blob-pe'
  location: location
  properties: {
    subnet: {
      id: blobPrivateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${storageAccountName}-blob-plsc'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
}

output storageAccountId string = storageAccount.id
output primaryBlobEndpoint string = storageAccount.properties.primaryEndpoints.blob
output blobPrivateEndpointId string = enableBlobPrivateEndpoint && blobPrivateEndpointSubnetId != '' ? blobPrivateEndpoint.id : ''
