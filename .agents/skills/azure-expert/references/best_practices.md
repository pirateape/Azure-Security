# Azure Best Practices & Architecture Patterns

Comprehensive guide to Azure best practices, architecture patterns, and common solutions.

## Well-Architected Framework Pillars

### 1. Cost Optimization
- Right-size resources (start small, scale up)
- Use Reserved Instances for predictable workloads (up to 72% savings)
- Enable autoscaling to match capacity with demand
- Use Spot VMs for fault-tolerant workloads (up to 90% savings)
- Auto-shutdown for dev/test environments
- Monitor costs with Cost Management + Billing
- Use Azure Advisor for personalized recommendations
- Delete unused resources regularly

### 2. Operational Excellence
- Infrastructure as Code (IaC): Use Bicep, ARM, or Terraform
- CI/CD pipelines: GitHub Actions, Azure DevOps
- Automated testing: Unit, integration, E2E
- Monitoring and alerting: Azure Monitor, Application Insights
- Log aggregation: Log Analytics workspace
- Deployment strategies: Blue-green, canary, rolling
- Documentation: Keep architecture diagrams updated

### 3. Performance Efficiency
- Choose the right service tier for your workload
- Use CDN for static content (Azure Front Door, CDN)
- Implement caching strategies (Redis, CDN)
- Optimize database queries and indexes
- Use read replicas for read-heavy workloads
- Enable connection pooling
- Async processing for long-running tasks
- Compression for data transfer

### 4. Reliability
- Design for failure (assume everything can fail)
- Implement retry logic with exponential backoff
- Use availability zones for HA (99.99% SLA)
- Configure geo-replication for DR
- Health checks and readiness probes
- Circuit breaker pattern
- Rate limiting and throttling
- Automated backups and tested recovery

### 5. Security
- Zero trust security model
- Managed identities instead of credentials
- Azure Key Vault for secrets
- Private endpoints for VNet integration
- Network Security Groups (NSG) and Application Security Groups
- Enable Microsoft Defender for Cloud
- Regular security assessments
- Principle of least privilege (RBAC)

## Authentication & Authorization Patterns

### Managed Identity (Recommended)
```csharp
// .NET example
var credential = new DefaultAzureCredential();
var blobClient = new BlobServiceClient(
    new Uri("https://mystorageaccount.blob.core.windows.net"),
    credential
);
```

```javascript
// Node.js example
const { DefaultAzureCredential } = require('@azure/identity');
const { BlobServiceClient } = require('@azure/storage-blob');

const credential = new DefaultAzureCredential();
const blobServiceClient = new BlobServiceClient(
  'https://mystorageaccount.blob.core.windows.net',
  credential
);
```

### Azure AD Authentication Flow
1. **User login**: User authenticates with Azure AD
2. **Token acquisition**: App gets access token
3. **API call**: Pass token in Authorization header
4. **Token validation**: API validates token with Azure AD
5. **Authorization**: Check user claims/roles

### RBAC Best Practices
- Use built-in roles when possible
- Create custom roles for specific needs
- Assign roles at appropriate scope (subscription, resource group, resource)
- Use groups instead of individual users
- Regular access reviews
- Document role assignments

## Common Architecture Patterns

### Microservices Architecture
```
┌─────────────────────────────────────────────────────┐
│              Azure Front Door (CDN/WAF)             │
└────────────────────┬────────────────────────────────┘
                     │
         ┌───────────┴───────────┐
         │   API Management      │
         └───────────┬───────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼───┐      ┌────▼────┐     ┌────▼────┐
│Service│      │Service  │     │Service  │
│   A   │      │    B    │     │    C    │
│(ACA)  │      │  (ACA)  │     │  (AKS)  │
└───┬───┘      └────┬────┘     └────┬────┘
    │               │                │
    └───────────────┼────────────────┘
                    │
         ┌──────────┴──────────┐
         │   Event Bus         │
         │  (Service Bus)      │
         └──────────┬──────────┘
                    │
    ┌───────────────┼───────────────┐
    │               │               │
┌───▼───┐     ┌────▼────┐    ┌────▼────┐
│Cosmos │     │  Redis  │    │SQL DB   │
│  DB   │     │  Cache  │    │         │
└───────┘     └─────────┘    └─────────┘
```

**Components:**
- **Azure Front Door**: Global load balancer, CDN, WAF
- **API Management**: API gateway, rate limiting, authentication
- **Container Apps/AKS**: Microservices hosting
- **Service Bus**: Async messaging, event-driven
- **Databases**: Polyglot persistence

### Event-Driven Architecture
```
┌──────────────┐
│Event Sources │
│ (App, IoT)   │
└──────┬───────┘
       │
   ┌───▼────────┐
   │Event Grid  │
   │(Event Bus) │
   └───┬────────┘
       │
    ┌──┴──┐
    │     │
┌───▼──┐ ┌▼────────┐
│Logic │ │Functions│
│ App  │ │         │
└──────┘ └─────────┘
```

**Use Cases:**
- Real-time data processing
- Microservices communication
- IoT telemetry processing
- Workflow automation

### Serverless Architecture
```
┌─────────────────┐
│  Static Web App │
│   (Frontend)    │
└────────┬────────┘
         │
    ┌────▼─────────┐
    │Azure Functions│
    │    (API)      │
    └────┬──────────┘
         │
    ┌────┴────────┐
    │   Cosmos DB │
    │   (Data)    │
    └─────────────┘
```

**Benefits:**
- Pay per execution
- Auto-scaling
- No server management
- Fast development

### N-Tier Architecture (Traditional)
```
┌────────────────────┐
│  Azure Front Door  │
└────────┬───────────┘
         │
┌────────▼───────────┐
│   App Service      │
│   (Web Tier)       │
└────────┬───────────┘
         │
┌────────▼───────────┐
│   App Service      │
│   (API Tier)       │
└────────┬───────────┘
         │
┌────────▼───────────┐
│   Azure SQL DB     │
│   (Data Tier)      │
└────────────────────┘
```

## Deployment Strategies

### Blue-Green Deployment
```bash
# Deploy to staging slot
az webapp deployment slot create \
  --name myapp --resource-group mygroup --slot staging

# Deploy app to staging
az webapp deployment source config-zip \
  --name myapp --resource-group mygroup \
  --slot staging --src ./app.zip

# Test staging slot
curl https://myapp-staging.azurewebsites.net

# Swap slots (zero downtime)
az webapp deployment slot swap \
  --name myapp --resource-group mygroup \
  --slot staging --target-slot production
```

### Canary Deployment
```bash
# Container Apps example: Route 90% to stable, 10% to canary
az containerapp ingress traffic set \
  --name myapp --resource-group mygroup \
  --revision-weight stable=90 canary=10
```

### Rolling Deployment
- Kubernetes/AKS native: `kubectl rollout`
- Gradually replace instances
- Monitor health during rollout
- Auto-rollback on failure

## Monitoring & Observability

### Application Insights Integration

**.NET**
```csharp
// Program.cs
builder.Services.AddApplicationInsightsTelemetry();

// Custom events
telemetryClient.TrackEvent("OrderPlaced", new Dictionary<string, string> {
    { "OrderId", order.Id },
    { "Amount", order.Total.ToString() }
});
```

**Node.js**
```javascript
const appInsights = require('applicationinsights');
appInsights.setup(process.env.APPLICATIONINSIGHTS_CONNECTION_STRING)
  .setAutoCollectRequests(true)
  .setAutoCollectPerformance(true)
  .setAutoCollectExceptions(true)
  .start();

const client = appInsights.defaultClient;
client.trackEvent({ name: 'OrderPlaced', properties: { orderId: '123' }});
```

### Key Metrics to Track
- **Availability**: Uptime, endpoint health
- **Performance**: Response time, throughput
- **Errors**: Exception rate, failed requests
- **Saturation**: CPU, memory, disk, network
- **Business metrics**: Orders, signups, revenue

### Alerting Best Practices
```bash
# Create action group (notification)
az monitor action-group create \
  --name criticalAlerts --resource-group mygroup \
  --short-name critical \
  --email-receiver name=admin email=admin@company.com

# Create alert rule (high CPU)
az monitor metrics alert create \
  --name highCPU --resource-group mygroup \
  --scopes /subscriptions/.../resourceGroups/mygroup/providers/Microsoft.Web/sites/myapp \
  --condition "avg Percentage CPU > 80" \
  --window-size 5m --evaluation-frequency 1m \
  --action criticalAlerts
```

## Security Best Practices

### Network Security
```
┌─────────────────────────────────────────┐
│        Internet (Public)                │
└─────────────────┬───────────────────────┘
                  │
       ┌──────────▼──────────┐
       │ Azure Front Door    │
       │ + WAF              │
       └──────────┬──────────┘
                  │
       ┌──────────▼──────────┐
       │  VNet               │
       │  ┌────────────────┐ │
       │  │ App Service    │ │
       │  │ (VNet Integrated)│
       │  └────────┬───────┘ │
       │           │         │
       │  ┌────────▼───────┐ │
       │  │ Private Endpoint│ │
       │  │  (SQL Database) │ │
       │  └────────────────┘ │
       └─────────────────────┘
```

### Key Vault Integration
```csharp
// .NET - Get secret from Key Vault
var client = new SecretClient(
    new Uri("https://myvault.vault.azure.net/"),
    new DefaultAzureCredential()
);

KeyVaultSecret secret = await client.GetSecretAsync("DatabasePassword");
string password = secret.Value;
```

```bash
# Reference Key Vault secret in App Service
az webapp config appsettings set \
  --name myapp --resource-group mygroup \
  --settings DbPassword="@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/DbPassword/)"
```

### Data Encryption
- **At rest**: TDE for databases, Storage Service Encryption
- **In transit**: HTTPS/TLS for all communications
- **Key management**: Azure Key Vault with HSM backing

## Disaster Recovery Strategies

### RTO and RPO
- **RTO (Recovery Time Objective)**: Maximum acceptable downtime
- **RPO (Recovery Point Objective)**: Maximum acceptable data loss

### DR Patterns

**Active-Passive**
```
Primary Region (Active)          Secondary Region (Passive)
┌────────────────┐              ┌────────────────┐
│  App Service   │              │  App Service   │
│   (Running)    │              │   (Stopped)    │
└────────┬───────┘              └────────────────┘
         │
┌────────▼───────┐    Geo-Replication
│  SQL Database  │────────────────────────────────►
│   (Primary)    │              │  SQL Database  │
└────────────────┘              │  (Secondary)   │
                                └────────────────┘
```

**Active-Active**
```
Region 1 (Active)                Region 2 (Active)
┌────────────────┐              ┌────────────────┐
│  App Service   │◄──Traffic────►  App Service   │
│   (Running)    │   Manager    │   (Running)    │
└────────┬───────┘              └────────┬───────┘
         │                                │
┌────────▼───────┐              ┌────────▼───────┐
│   Cosmos DB    │◄─Multi-Master─►   Cosmos DB   │
│  (Read/Write)  │  Replication │  (Read/Write)  │
└────────────────┘              └────────────────┘
```

### Backup Strategy
- **Automated backups**: Enable for all production resources
- **Retention period**: 7-35 days (compliance requirements)
- **Geo-redundant**: Store backups in different region
- **Test restores**: Regular DR drills
- **Documentation**: Runbooks for recovery procedures

## Infrastructure as Code

### Bicep Example (Recommended)
```bicep
// main.bicep
param location string = resourceGroup().location
param appName string

// App Service Plan
resource appServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: '${appName}-plan'
  location: location
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
}

// Web App
resource webApp 'Microsoft.Web/sites@2022-03-01' = {
  name: appName
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    siteConfig: {
      linuxFxVersion: 'DOTNETCORE|8.0'
      alwaysOn: true
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
    }
    httpsOnly: true
  }
  identity: {
    type: 'SystemAssigned'
  }
}

// Application Insights
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${appName}-insights'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
}

// Link App Insights
resource appSettings 'Microsoft.Web/sites/config@2022-03-01' = {
  parent: webApp
  name: 'appsettings'
  properties: {
    APPLICATIONINSIGHTS_CONNECTION_STRING: appInsights.properties.ConnectionString
  }
}

output webAppUrl string = 'https://${webApp.properties.defaultHostName}'
```

### Deployment
```bash
# Deploy Bicep template
az deployment group create \
  --resource-group mygroup \
  --template-file main.bicep \
  --parameters appName=myapp location=eastus
```

## Performance Optimization Tips

### Caching Strategy
1. **CDN**: Static content (images, JS, CSS)
2. **Redis Cache**: Session state, API responses
3. **Application cache**: In-memory caching (IMemoryCache, node-cache)
4. **Browser cache**: Cache-Control headers
5. **Database cache**: Query result cache

### Database Optimization
- Use appropriate indexes (avoid over-indexing)
- Implement connection pooling
- Use read replicas for read-heavy workloads
- Partition large tables
- Optimize queries (avoid SELECT *, use WHERE clauses)
- Use stored procedures for complex logic
- Enable query performance insights

### API Optimization
- Implement pagination for large datasets
- Use compression (gzip, brotli)
- Implement rate limiting
- Use async/await for I/O operations
- Batch requests when possible
- GraphQL for flexible data fetching

## Cost Optimization Checklist

- [ ] Right-size resources (don't over-provision)
- [ ] Use Reserved Instances for production (3-year commitment = max savings)
- [ ] Enable autoscaling for variable workloads
- [ ] Use Spot VMs for fault-tolerant workloads
- [ ] Auto-shutdown for dev/test environments
- [ ] Delete unused resources (orphaned disks, old backups)
- [ ] Use Azure Advisor recommendations
- [ ] Set up budget alerts
- [ ] Use consumption-based pricing (Functions, Container Apps)
- [ ] Optimize storage tiers (Hot/Cool/Archive)
- [ ] Review and optimize data transfer costs
- [ ] Use Azure Hybrid Benefit (if you have Windows Server/SQL licenses)
- [ ] Regular cost reviews (monthly)

## Naming Conventions

```
Resource Type          Convention                    Example
─────────────────────────────────────────────────────────────────
Resource Group         rg-{workload}-{env}-{region}  rg-myapp-prod-eastus
App Service            app-{name}-{env}-{region}     app-api-prod-eastus
Function App           func-{name}-{env}-{region}    func-processor-prod-eastus
Storage Account        st{name}{env}{region}         stmyappprodeastus
SQL Server             sql-{name}-{env}-{region}     sql-myapp-prod-eastus
SQL Database           sqldb-{name}-{env}            sqldb-customers-prod
Cosmos DB              cosmos-{name}-{env}           cosmos-myapp-prod
Key Vault              kv-{name}-{env}-{region}      kv-myapp-prod-eastus
Container Registry     cr{name}{env}                 crmyappprod
AKS Cluster            aks-{name}-{env}-{region}     aks-myapp-prod-eastus
Virtual Network        vnet-{name}-{env}-{region}    vnet-myapp-prod-eastus
Subnet                 snet-{purpose}                snet-web, snet-data
```

**Environment abbreviations**: dev, qa, stage, prod
**Region abbreviations**: eastus, westus, westeu, etc.
