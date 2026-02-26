# Azure Compute Services Reference

Comprehensive guide to Azure compute services, when to use each, and best practices.

## Service Comparison Matrix

| Service | Use Case | Deployment Time | Scaling | Pricing Model | Best For |
|---------|----------|----------------|---------|---------------|----------|
| **App Service** | Web apps, APIs, mobile backends | Minutes | Auto/Manual | Always-on or consumption | Traditional web apps, REST APIs |
| **Functions** | Event-driven, serverless | Seconds | Auto | Consumption or Premium | Microservices, event processing, scheduled tasks |
| **Container Apps** | Containerized apps | Minutes | Auto (KEDA) | Consumption-based | Modern cloud-native apps, microservices |
| **AKS** | Full Kubernetes | 10-15 min | Manual/Auto | Node-based | Complex containerized workloads, full K8s control |
| **Container Instances** | Simple containers | Seconds | Manual | Per-second billing | Batch jobs, CI/CD agents, simple containers |
| **Virtual Machines** | Full control | Minutes | Manual/VMSS | Always-on | Legacy apps, custom software, lift-and-shift |
| **Batch** | Large-scale parallel jobs | Minutes | Auto | Compute time | HPC, rendering, data processing |
| **Static Web Apps** | Static sites + APIs | Minutes | Auto | Generous free tier | JAMstack, SPAs with API backends |

## App Service

### When to Use
- Traditional web applications (MVC, WebForms, etc.)
- REST APIs and GraphQL endpoints
- Mobile app backends
- Need built-in features: deployment slots, custom domains, SSL, auth

### Supported Runtimes
```
.NET:     8.0, 7.0, 6.0
Node.js:  20-lts, 18-lts, 16-lts
Python:   3.11, 3.10, 3.9
Java:     17-java17, 11-java11, 8-jre8
PHP:      8.2, 8.1
Ruby:     2.7
```

### Pricing Tiers
- **Free (F1)**: Dev/test, 60 min/day compute, 1 GB RAM
- **Shared (D1)**: Dev/test, 240 min/day, 1 GB RAM
- **Basic (B1-B3)**: Low-traffic production, no slots, no autoscale
- **Standard (S1-S3)**: Production, 5 slots, autoscale, custom domains
- **Premium (P1v2-P3v3)**: High-performance, 20 slots, VNet integration
- **Isolated (I1-I3)**: Dedicated environment, private VNet

### Best Practices
1. **Always use deployment slots** for zero-downtime deployments (requires Standard+)
2. **Enable Application Insights** for monitoring and diagnostics
3. **Use managed identity** instead of storing credentials
4. **Configure health check** endpoint for load balancer
5. **Enable autoscaling** based on metrics (CPU, memory, HTTP queue)
6. **Use App Service Environment (ASE)** for network isolation

### Common Configuration
```bash
# Connection strings (for databases)
az webapp config connection-string set \
  --name myapp --resource-group mygroup \
  --connection-string-type SQLAzure \
  --settings DefaultConnection="Server=tcp:..."

# App settings (environment variables)
az webapp config appsettings set \
  --name myapp --resource-group mygroup \
  --settings API_KEY="xxx" NODE_ENV="production"

# Enable HTTPS only
az webapp update --name myapp --resource-group mygroup --https-only true

# Configure deployment slot
az webapp deployment slot create --name myapp --resource-group mygroup --slot staging
```

## Azure Functions

### When to Use
- Event-driven workloads (HTTP triggers, queue messages, timers)
- Serverless APIs
- Background processing
- Integration/glue code
- Scheduled tasks (cron jobs)
- Real-time file processing

### Hosting Plans
1. **Consumption Plan**: Pay per execution, auto-scale, 5 min timeout (default 10 min)
2. **Premium Plan**: Pre-warmed instances, VNet, unlimited duration
3. **Dedicated (App Service) Plan**: Predictable billing, existing App Service Plan

### Trigger Types
- HTTP: REST APIs, webhooks
- Timer: Scheduled tasks (cron)
- Queue: Azure Storage Queue, Service Bus
- Blob: File uploads/changes
- Event Grid: Event-driven architecture
- Event Hub: Streaming data
- Cosmos DB: Database changes

### Best Practices
1. **Keep functions small and focused** (single responsibility)
2. **Use Durable Functions** for stateful workflows
3. **Avoid blocking calls** in consumption plan
4. **Reuse connections** (HTTP clients, database)
5. **Use Application Insights** for distributed tracing
6. **Set appropriate timeout** based on plan

### Example Function Structure
```
MyFunctionApp/
├── host.json                 # Global configuration
├── local.settings.json       # Local development settings
├── requirements.txt          # Python dependencies (or package.json)
├── HttpTrigger/
│   ├── __init__.py
│   └── function.json
└── TimerTrigger/
    ├── __init__.py
    └── function.json
```

## Container Apps

### When to Use
- Microservices architecture
- API gateways
- Background processing
- Event-driven applications
- Jobs and scheduled tasks
- Need Dapr integration

### Key Features
- Built on Kubernetes (managed)
- Automatic HTTPS with custom domains
- Traffic splitting for A/B testing
- Dapr integration out of the box
- Scale to zero capability
- KEDA-based autoscaling

### Scaling Strategies
```yaml
# HTTP-based scaling
scale:
  minReplicas: 0
  maxReplicas: 30
  rules:
  - name: http-rule
    http:
      metadata:
        concurrentRequests: 50

# Queue-based scaling (with KEDA)
scale:
  rules:
  - name: queue-rule
    azureQueue:
      queueName: orders
      queueLength: 10
```

### Best Practices
1. **Use managed identity** for Azure service authentication
2. **Configure health probes** for reliability
3. **Use Dapr** for service-to-service communication
4. **Enable ingress** only when needed (internal vs external)
5. **Use revisions** for versioning and traffic splitting
6. **Monitor with Container Apps insights**

## AKS (Azure Kubernetes Service)

### When to Use
- Need full Kubernetes control
- Complex microservices architectures
- Multi-cloud/hybrid scenarios
- Custom controllers and operators
- Advanced networking requirements

### Node Pool Types
- **System Pool**: Required, runs system pods (CoreDNS, metrics-server)
- **User Pool**: Your applications
- **Spot Pool**: Cost savings with evictable VMs

### Best Practices
1. **Use Azure CNI** for advanced networking (or Kubenet for simple)
2. **Enable managed identity** for node pools
3. **Use Azure Policy** for cluster governance
4. **Implement pod security** policies
5. **Use Azure Key Vault** with CSI driver for secrets
6. **Configure cluster autoscaler** for efficiency
7. **Use Azure Monitor** for container insights

### Common Operations
```bash
# Create AKS cluster
az aks create --name mycluster --resource-group mygroup \
  --node-count 3 --enable-managed-identity \
  --network-plugin azure --enable-addons monitoring

# Get credentials
az aks get-credentials --name mycluster --resource-group mygroup

# Scale node pool
az aks nodepool scale --cluster-name mycluster \
  --name nodepool1 --node-count 5 --resource-group mygroup

# Upgrade cluster
az aks upgrade --name mycluster --resource-group mygroup \
  --kubernetes-version 1.28.0
```

## Virtual Machines

### When to Use
- Need full OS control
- Legacy applications
- Custom software not available in PaaS
- Specific performance requirements
- Lift-and-shift migrations

### VM Sizes Categories
- **B-series**: Burstable, low-cost, dev/test
- **D-series**: General purpose (Dv3, Dv4, Dv5)
- **E-series**: Memory-optimized (databases, caching)
- **F-series**: Compute-optimized (batch, web servers)
- **M-series**: Large memory (SAP HANA, SQL Server)
- **N-series**: GPU (ML, rendering, HPC)

### Best Practices
1. **Use managed disks** (not unmanaged)
2. **Enable Azure Backup** for production VMs
3. **Use VM Scale Sets (VMSS)** for scalability
4. **Configure auto-shutdown** for dev/test
5. **Use Spot VMs** for fault-tolerant workloads (up to 90% savings)
6. **Enable Azure Disk Encryption**
7. **Use proximity placement groups** for low latency

## Static Web Apps

### When to Use
- Static site generators (Next.js, Gatsby, Hugo, Jekyll)
- Single Page Applications (React, Vue, Angular)
- JAMstack architecture
- Documentation sites
- Landing pages with API backends

### Features
- **Free SSL** certificates
- **Custom domains**
- **Global CDN**
- **Staging environments** (preview branches)
- **Built-in API** via Azure Functions
- **Authentication** providers (GitHub, Azure AD, Twitter)

### Supported Frameworks
- React, Vue, Angular, Svelte
- Next.js, Nuxt.js, Gatsby
- Hugo, Jekyll, 11ty
- Blazor WebAssembly

### Best Practices
1. **Use GitHub Actions** or Azure DevOps for CI/CD
2. **Configure preview environments** for pull requests
3. **Use API routes** for backend logic (Functions)
4. **Enable authentication** for protected content
5. **Configure custom domains** with apex support
6. **Use SWA CLI** for local development

## Decision Tree

```
Need full Kubernetes control?
  └─ Yes → AKS
  └─ No ↓

Containerized application?
  └─ Yes → Container Apps (simple) or AKS (complex)
  └─ No ↓

Event-driven/serverless?
  └─ Yes → Functions
  └─ No ↓

Traditional web app or API?
  └─ Yes → App Service
  └─ No ↓

Static frontend only?
  └─ Yes → Static Web Apps
  └─ No ↓

Need full OS control?
  └─ Yes → Virtual Machines
  └─ No ↓

Batch processing?
  └─ Yes → Azure Batch or Functions
```

## Cost Optimization Tips

1. **Right-size your resources**: Start small, scale up as needed
2. **Use Reserved Instances**: Up to 72% savings for predictable workloads
3. **Enable autoscaling**: Match capacity to demand
4. **Use Spot VMs/Instances**: Up to 90% savings for fault-tolerant workloads
5. **Auto-shutdown**: For dev/test environments
6. **Use consumption plans**: For variable workloads (Functions, Container Apps)
7. **Delete unused resources**: Regular audits
8. **Use Azure Advisor**: Personalized recommendations
