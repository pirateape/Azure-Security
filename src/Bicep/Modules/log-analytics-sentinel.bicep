targetScope = 'subscription'

@description('Location for the Log Analytics workspace')
param location string

@description('Name of the Log Analytics workspace')
param workspaceName string

@description('SKU for the workspace')
param sku string = 'PerGB2018'

@description('Retention period in days')
param retentionInDays int = 90

@description('Enable Sentinel')
param enableSentinel bool = true

@description('Tags for resources')
param tags object = {}

resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: sku
    }
    retentionInDays: retentionInDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource sentinel 'Microsoft.SecurityInsights/onboardingStates@2023-02-01' = if (enableSentinel) {
  name: 'default'
  scope: workspace
  properties: {
    customerManagedKey: false
  }
}

var solutions = [
  {
    name: 'SecurityInsights'
    publisher: 'Microsoft'
    product: 'OMSGallery/SecurityInsights'
  }
  {
    name: 'AzureActivity'
    publisher: 'Microsoft'
    product: 'OMSGallery/AzureActivity'
  }
  {
    name: 'Security'
    publisher: 'Microsoft'
    product: 'OMSGallery/Security'
  }
  {
    name: 'AntiMalware'
    publisher: 'Microsoft'
    product: 'OMSGallery/AntiMalware'
  }
  {
    name: 'NetworkMonitoring'
    publisher: 'Microsoft'
    product: 'OMSGallery/NetworkMonitoring'
  }
]

resource solution 'Microsoft.OperationsManagement/solutions@2015-11-01-preview' = [for sol in solutions: {
  name: '${sol.name}(${workspaceName})'
  location: location
  tags: tags
  properties: {
    workspaceResourceId: workspace.id
    containedResources: [
      '${workspace.id}/views/${sol.name}'
    ]
    referencedResources: []
  }
  plan: {
    name: '${sol.name}(${workspaceName})'
    publisher: sol.publisher
    product: sol.product
    promotionCode: ''
  }
}]

output workspaceId string = workspace.id
output workspaceCustomerId string = workspace.properties.customerId
output sentinelEnabled bool = enableSentinel
