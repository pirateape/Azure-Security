// Azure Functions Application Template
// Creates: Function App (Consumption/Premium), Storage, Application Insights, Key Vault
// Best practices: Managed Identity, Monitoring, Secure configuration

@description('Name of the function app')
param functionAppName string

@description('Environment (dev, qa, prod)')
@allowed([
  'dev'
  'qa'
  'prod'
])
param environment string = 'dev'

@description('Azure region for all resources')
param location string = resourceGroup().location

@description('Function App hosting plan')
@allowed([
  'Consumption' // Pay per execution, 5 min timeout
  'Premium'     // Pre-warmed, VNet, unlimited duration
])
param hostingPlan string = 'Consumption'

@description('Runtime stack')
@allowed([
  'dotnet'
  'dotnet-isolated'
  'node'
  'python'
  'java'
])
param runtime string = 'dotnet-isolated'

@description('Runtime version')
param runtimeVersion string = '8.0' // dotnet: 8.0, node: 20, python: 3.11, java: 17

// Variables
var resourcePrefix = '${functionAppName}-${environment}'
var storageAccountName = 'st${replace(functionAppName, '-', '')}${environment}${uniqueString(resourceGroup().id)}'
var appInsightsName = 'appi-${resourcePrefix}'
var logAnalyticsName = 'log-${resourcePrefix}'
var keyVaultName = 'kv-${resourcePrefix}-${uniqueString(resourceGroup().id)}'
var hostingPlanName = 'plan-${resourcePrefix}'
var functionAppResourceName = 'func-${resourcePrefix}-${uniqueString(resourceGroup().id)}'

// Runtime configurations
var runtimeSettings = {
  dotnet: {
    linuxFxVersion: 'DOTNET|${runtimeVersion}'
    appSettings: [
      {
        name: 'FUNCTIONS_WORKER_RUNTIME'
        value: 'dotnet'
      }
    ]
  }
  'dotnet-isolated': {
    linuxFxVersion: 'DOTNET-ISOLATED|${runtimeVersion}'
    appSettings: [
      {
        name: 'FUNCTIONS_WORKER_RUNTIME'
        value: 'dotnet-isolated'
      }
    ]
  }
  node: {
    linuxFxVersion: 'NODE|${runtimeVersion}'
    appSettings: [
      {
        name: 'FUNCTIONS_WORKER_RUNTIME'
        value: 'node'
      }
      {
        name: 'WEBSITE_NODE_DEFAULT_VERSION'
        value: '~${runtimeVersion}'
      }
    ]
  }
  python: {
    linuxFxVersion: 'PYTHON|${runtimeVersion}'
    appSettings: [
      {
        name: 'FUNCTIONS_WORKER_RUNTIME'
        value: 'python'
      }
    ]
  }
  java: {
    linuxFxVersion: 'JAVA|${runtimeVersion}'
    appSettings: [
      {
        name: 'FUNCTIONS_WORKER_RUNTIME'
        value: 'java'
      }
    ]
  }
}

// Tags
var commonTags = {
  Environment: environment
  Application: functionAppName
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
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

// Storage Account (required for Functions)
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

// Hosting Plan
resource hostingPlanResource 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: hostingPlanName
  location: location
  tags: commonTags
  sku: {
    name: hostingPlan == 'Premium' ? 'EP1' : 'Y1'
    tier: hostingPlan == 'Premium' ? 'ElasticPremium' : 'Dynamic'
  }
  kind: 'linux'
  properties: {
    reserved: true
    maximumElasticWorkerCount: hostingPlan == 'Premium' ? 20 : null
  }
}

// Function App
resource functionApp 'Microsoft.Web/sites@2022-09-01' = {
  name: functionAppResourceName
  location: location
  tags: commonTags
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: hostingPlanResource.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: runtimeSettings[runtime].linuxFxVersion
      alwaysOn: hostingPlan == 'Premium'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      http20Enabled: true
      functionAppScaleLimit: hostingPlan == 'Premium' ? 20 : 200
      appSettings: union([
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${az.environment().suffixes.storage}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageAccount.name};AccountKey=${storageAccount.listKeys().keys[0].value};EndpointSuffix=${az.environment().suffixes.storage}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(functionAppResourceName)
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'ApplicationInsightsAgent_EXTENSION_VERSION'
          value: '~3'
        }
      ], runtimeSettings[runtime].appSettings)
    }
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
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

// RBAC: Grant Function App access to Key Vault
resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, functionApp.id, 'Key Vault Secrets User')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

// Diagnostic Settings - Send logs to Log Analytics
resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'send-to-log-analytics'
  scope: functionApp
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        category: 'FunctionAppLogs'
        enabled: true
        retentionPolicy: {
          enabled: false
          days: 0
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: false
          days: 0
        }
      }
    ]
  }
}

// Outputs
output functionAppName string = functionApp.name
output functionAppUrl string = 'https://${functionApp.properties.defaultHostName}'
output storageAccountName string = storageAccount.name
output keyVaultName string = keyVault.name
output appInsightsName string = appInsights.name
output appInsightsConnectionString string = appInsights.properties.ConnectionString
output principalId string = functionApp.identity.principalId

// Deployment Instructions:
//
// 1. Deploy the template:
//    az deployment group create \
//      --resource-group myfunc-rg \
//      --template-file function-app-template.bicep \
//      --parameters functionAppName=myfunction environment=prod hostingPlan=Premium runtime=dotnet-isolated
//
// 2. Deploy your function code:
//
//    # Using Azure Functions Core Tools
//    func azure functionapp publish <functionAppName>
//
//    # Or using zip deploy
//    az functionapp deployment source config-zip \
//      --resource-group myfunc-rg --name <functionAppName> --src ./function-app.zip
//
// 3. Add secrets to Key Vault:
//    az keyvault secret set --vault-name <keyVaultName> --name "ApiKey" --value "your-secret"
//
// 4. Reference secrets in function app settings:
//    az functionapp config appsettings set \
//      --name <functionAppName> --resource-group myfunc-rg \
//      --settings ApiKey="@Microsoft.KeyVault(SecretUri=https://<keyVaultName>.vault.azure.net/secrets/ApiKey/)"
//
// 5. Monitor your functions:
//    - View logs: az functionapp log tail --name <functionAppName> --resource-group myfunc-rg
//    - Application Insights: Check the portal for detailed telemetry
//
// Common Function Triggers:
//  - HTTP Trigger: REST APIs, webhooks
//  - Timer Trigger: Scheduled tasks (cron: "0 */5 * * * *" = every 5 minutes)
//  - Queue Trigger: Azure Storage Queue or Service Bus
//  - Blob Trigger: File upload processing
//  - Event Grid Trigger: Event-driven workflows
//  - Cosmos DB Trigger: Database change feed
//  - Event Hub Trigger: Streaming data processing
