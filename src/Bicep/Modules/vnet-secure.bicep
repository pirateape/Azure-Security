@description('Location for all resources')
param location string = resourceGroup().location

@description('Name of the virtual network')
param vnetName string

@description('Address space for the virtual network')
param vnetAddressPrefix string = '10.0.0.0/16'

@description('Name of the subnet')
param subnetName string = 'default'

@description('Address prefix for the subnet')
param subnetAddressPrefix string = '10.0.0.0/24'

@description('NSG name - will be auto-generated if not provided')
param nsgName string = ''

@description('Enable NSG flow logs')
param enableFlowLogs bool = true

@description('Log Analytics Workspace Resource ID for flow logs')
param logAnalyticsWorkspaceId string = ''

@description('Storage Account ID for flow logs')
param flowLogsStorageAccountId string = ''

@description('Name of the Network Watcher (default follows Azure convention)')
param networkWatcherName string = 'NetworkWatcher_${location}'

@description('Resource group of the Network Watcher (Azure auto-creates NetworkWatcherRG)')
param networkWatcherResourceGroup string = 'NetworkWatcherRG'

var effectiveNsgName = nsgName != '' ? nsgName : '${vnetName}-${subnetName}-nsg'

resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
  name: vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        vnetAddressPrefix
      ]
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: subnetAddressPrefix
          networkSecurityGroup: {
            id: nsg.id
          }
          privateEndpointNetworkPolicies: 'Disabled'
          privateLinkServiceNetworkPolicies: 'Enabled'
        }
      }
    ]
    enableDdosProtection: false
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: effectiveNsgName
  location: location
  properties: {
    securityRules: [
      {
        name: 'DenyAllInbound'
        properties: {
          protocol: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Deny'
          direction: 'Inbound'
          priority: 4096
          sourcePortRange: '*'
          destinationPortRange: '*'
          description: 'Default deny all inbound traffic'
        }
      }
    ]
  }
}

resource networkWatcher 'Microsoft.Network/networkWatchers@2023-04-01' existing = {
  name: networkWatcherName
  scope: resourceGroup(networkWatcherResourceGroup)
}

resource flowLog 'Microsoft.Network/networkWatchers/flowLogs@2023-04-01' = if (enableFlowLogs && logAnalyticsWorkspaceId != '' && flowLogsStorageAccountId != '') {
  parent: networkWatcher
  name: '${vnetName}-${subnetName}-flowlog'
  location: location
  properties: {
    targetResourceId: nsg.id
    storageId: flowLogsStorageAccountId
    enabled: true
    format: {
      type: 'JSON'
      version: 2
    }
    flowAnalyticsConfiguration: {
      networkWatcherFlowAnalyticsConfiguration: {
        enabled: true
        workspaceResourceId: logAnalyticsWorkspaceId
        trafficAnalyticsInterval: 60
      }
    }
  }
}

output vnetId string = vnet.id
output subnetId string = '${vnet.id}/subnets/${subnetName}'
output nsgId string = nsg.id
