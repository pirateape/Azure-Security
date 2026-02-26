// Complete Web Application Infrastructure Template
// Creates: App Service, SQL Database, Storage, Key Vault, Application Insights
// Best practices: Managed Identity, Private Endpoints, Monitoring

@description('Name of the application (used as prefix for all resources)')
param appName string

@description('Environment (dev, qa, prod)')
@allowed([
  'dev'
  'qa'
  'prod'
])
param environment string = 'dev'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('App Service Plan SKU')
@allowed([
  'B1'   // Basic - Dev/Test
  'B2'
  'S1'   // Standard - Production
  'S2'
  'S3'
  'P1v3' // Premium - High performance
  'P2v3'
  'P3v3'
])
param appServicePlanSku string = environment == 'prod' ? 'S1' : 'B1'

@description('SQL Database SKU')
@allowed([
  'Basic'
  'S0'
  'S1'
  'S2'
  'P1'
  'P2'
])
param sqlDatabaseSku string = environment == 'prod' ? 'S1' : 'Basic'

@description('SQL Admin username')
param sqlAdminUsername string = 'sqladmin'

@description('SQL Admin password')
@secure()
param sqlAdminPassword string

@description('Enable zone redundancy for App Service Plan')
param enableZoneRedundancy bool = environment == 'prod'

// Variables
var resourcePrefix = '${appName}-${environment}'
var appServicePlanName = 'plan-${resourcePrefix}'
var webAppName = 'app-${resourcePrefix}-${uniqueString(resourceGroup().id)}'
var sqlServerName = 'sql-${resourcePrefix}-${uniqueString(resourceGroup().id)}'
var sqlDatabaseName = 'sqldb-${appName}'
var storageAccountName = 'st${replace(appName, '-', '')}${environment}${uniqueString(resourceGroup().id)}'
var keyVaultName = 'kv-${resourcePrefix}-${uniqueString(resourceGroup().id)}'
var appInsightsName = 'appi-${resourcePrefix}'
var logAnalyticsName = 'log-${resourcePrefix}'

// Tags
var commonTags = {
  Environment: environment
  Application: appName
  ManagedBy: 'Bicep'
}

// Log Analytics Workspace
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: logAnalyticsName
  location: location
  tags: commonTags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: environment == 'prod' ? 90 : 30
  }
}

// Application Insights
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  tags: commonTags
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

// App Service Plan
resource appServicePlan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: appServicePlanName
  location: location
  tags: commonTags
  sku: {
    name: appServicePlanSku
  }
  kind: 'linux'
  properties: {
    reserved: true
    zoneRedundant: enableZoneRedundancy
  }
}

// Web App
resource webApp 'Microsoft.Web/sites@2022-09-01' = {
  name: webAppName
  location: location
  tags: commonTags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'DOTNETCORE|8.0' // Change as needed: NODE|20-lts, PYTHON|3.11, etc.
      alwaysOn: environment == 'prod'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      http20Enabled: true
      healthCheckPath: '/health'
      appSettings: [
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'ApplicationInsightsAgent_EXTENSION_VERSION'
          value: '~3'
        }
        {
          name: 'ASPNETCORE_ENVIRONMENT'
          value: environment == 'prod' ? 'Production' : 'Development'
        }
      ]
      connectionStrings: [
        {
          name: 'DefaultConnection'
          connectionString: '@Microsoft.KeyVault(SecretUri=${keyVault.properties.vaultUri}secrets/SqlConnectionString/)'
          type: 'SQLAzure'
        }
      ]
    }
  }
}

// Staging Slot (Production only)
resource stagingSlot 'Microsoft.Web/sites/slots@2022-09-01' = if (environment == 'prod') {
  parent: webApp
  name: 'staging'
  location: location
  tags: commonTags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'DOTNETCORE|8.0'
      alwaysOn: true
      appSettings: [
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'ASPNETCORE_ENVIRONMENT'
          value: 'Staging'
        }
      ]
    }
  }
}

// SQL Server
resource sqlServer 'Microsoft.Sql/servers@2022-05-01-preview' = {
  name: sqlServerName
  location: location
  tags: commonTags
  properties: {
    administratorLogin: sqlAdminUsername
    administratorLoginPassword: sqlAdminPassword
    version: '12.0'
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Enabled' // Change to 'Disabled' with Private Endpoint
  }
}

// SQL Database
resource sqlDatabase 'Microsoft.Sql/servers/databases@2022-05-01-preview' = {
  parent: sqlServer
  name: sqlDatabaseName
  location: location
  tags: commonTags
  sku: {
    name: sqlDatabaseSku
    tier: sqlDatabaseSku == 'Basic' ? 'Basic' : 'Standard'
  }
  properties: {
    collation: 'SQL_Latin1_General_CP1_CI_AS'
    maxSizeBytes: environment == 'prod' ? 268435456000 : 2147483648 // 250GB prod, 2GB dev
    zoneRedundant: environment == 'prod'
  }
}

// SQL Firewall Rule - Allow Azure Services
resource sqlFirewallRule 'Microsoft.Sql/servers/firewallRules@2022-05-01-preview' = {
  parent: sqlServer
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

// Storage Account
resource storageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: take(storageAccountName, 24)
  location: location
  tags: commonTags
  sku: {
    name: environment == 'prod' ? 'Standard_ZRS' : 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    accessTier: 'Hot'
  }
}

// Blob Container
resource blobContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2022-09-01' = {
  name: '${storageAccount.name}/default/uploads'
  properties: {
    publicAccess: 'None'
  }
}

// Key Vault
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: take(keyVaultName, 24)
  location: location
  tags: commonTags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    networkAcls: {
      defaultAction: 'Allow' // Change to 'Deny' with Private Endpoint
      bypass: 'AzureServices'
    }
  }
}

// Store SQL Connection String in Key Vault
resource sqlConnectionStringSecret 'Microsoft.KeyVault/vaults/secrets@2023-02-01' = {
  parent: keyVault
  name: 'SqlConnectionString'
  properties: {
    value: 'Server=tcp:${sqlServer.properties.fullyQualifiedDomainName},1433;Initial Catalog=${sqlDatabase.name};Authentication=Active Directory Default;'
  }
}

// Store Storage Connection String in Key Vault
resource storageConnectionStringSecret 'Microsoft.KeyVault/vaults/secrets@2023-02-01' = {
  parent: keyVault
  name: 'StorageConnectionString'
  properties: {
    value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${az.environment().suffixes.storage}'
  }
}

// RBAC: Grant Web App access to Key Vault (Key Vault Secrets User)
resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, webApp.id, 'Key Vault Secrets User')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: webApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// RBAC: Grant Web App access to Storage (Storage Blob Data Contributor)
resource storageRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storageAccount.id, webApp.id, 'Storage Blob Data Contributor')
  scope: storageAccount
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
    principalId: webApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// RBAC: Grant Web App access to SQL Database (SQL DB Contributor)
resource sqlRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(sqlServer.id, webApp.id, 'SQL DB Contributor')
  scope: sqlDatabase
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '9b7fa17d-e63e-47b0-bb0a-15c516ac86ec')
    principalId: webApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Outputs
output webAppName string = webApp.name
output webAppUrl string = 'https://${webApp.properties.defaultHostName}'
output stagingSlotUrl string = environment == 'prod' ? 'https://${webApp.name}-staging.azurewebsites.net' : ''
output sqlServerFqdn string = sqlServer.properties.fullyQualifiedDomainName
output sqlDatabaseName string = sqlDatabase.name
output storageAccountName string = storageAccount.name
output keyVaultName string = keyVault.name
output appInsightsName string = appInsights.name
output appInsightsConnectionString string = appInsights.properties.ConnectionString

// Deployment Instructions:
//
// 1. Deploy the template:
//    az deployment group create \
//      --resource-group myapp-rg \
//      --template-file webapp-template.bicep \
//      --parameters appName=myapp environment=prod sqlAdminPassword='MySecureP@ss123!'
//
// 2. Configure SQL Database for Azure AD authentication:
//    - Set Azure AD admin in the Azure Portal
//    - Run this SQL to create user for managed identity:
//      CREATE USER [app-myapp-prod-xxx] FROM EXTERNAL PROVIDER;
//      ALTER ROLE db_datareader ADD MEMBER [app-myapp-prod-xxx];
//      ALTER ROLE db_datawriter ADD MEMBER [app-myapp-prod-xxx];
//
// 3. Deploy your application code:
//    az webapp deployment source config-zip \
//      --resource-group myapp-rg --name <webAppName> --src ./app.zip
//
// 4. Monitor with Application Insights:
//    Open the Application Insights resource in the portal
