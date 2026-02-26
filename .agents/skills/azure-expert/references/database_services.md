# Azure Database Services Reference

Comprehensive guide to Azure database services, selection criteria, and best practices.

## Database Service Comparison

| Service | Type | Use Case | HA/DR | Scaling | Best For |
|---------|------|----------|-------|---------|----------|
| **Azure SQL Database** | Relational (SQL Server) | General purpose RDBMS | Built-in | Vertical + Read replicas | SQL Server apps, OLTP |
| **Azure SQL Managed Instance** | Relational (SQL Server) | Lift-and-shift SQL Server | Built-in | Vertical only | Full SQL Server compatibility |
| **Azure Database for PostgreSQL** | Relational (PostgreSQL) | Open-source RDBMS | Built-in | Vertical + Read replicas | PostgreSQL apps, complex queries |
| **Azure Database for MySQL** | Relational (MySQL) | Open-source RDBMS | Built-in | Vertical + Read replicas | MySQL apps, web apps |
| **Cosmos DB** | NoSQL (Multi-model) | Global distribution | 99.999% SLA | Unlimited horizontal | Low-latency global apps |
| **Table Storage** | NoSQL (Key-value) | Simple key-value | Zone-redundant | Automatic | Massive scale, simple data |
| **Azure Cache for Redis** | In-memory cache | Session state, caching | Built-in | Vertical + Clustering | High-performance caching |
| **Azure Synapse Analytics** | Data warehouse | Analytics, OLAP | Built-in | Elastic | Big data analytics, DW |

## Azure SQL Database

### When to Use
- Migrating from SQL Server
- Need managed SQL database
- OLTP workloads
- Multi-tenant SaaS applications
- Modern app development with relational data

### Service Tiers

#### DTU-Based Model
- **Basic**: Dev/test, up to 2 GB, 5 DTU
- **Standard**: Small to medium workloads, up to 1 TB, 10-3000 DTU
- **Premium**: Mission-critical, up to 4 TB, 125-4000 DTU

#### vCore-Based Model (Recommended)
- **General Purpose**: Balanced compute/memory, 1-80 vCores
- **Business Critical**: High IOPS, in-memory OLTP, 1-80 vCores
- **Hyperscale**: Large databases (100+ TB), rapid scale

### Compute Tiers
- **Provisioned**: Always-on, predictable workloads
- **Serverless**: Auto-pause/resume, intermittent workloads, pay per second

### Best Practices

```bash
# Create SQL Server
az sql server create \
  --name myserver --resource-group mygroup \
  --location eastus --admin-user myadmin \
  --admin-password 'MyP@ssw0rd!' \
  --enable-public-network true

# Create database (serverless)
az sql db create \
  --resource-group mygroup --server myserver \
  --name mydb --edition GeneralPurpose \
  --compute-model Serverless \
  --family Gen5 --capacity 2 \
  --auto-pause-delay 60

# Enable Transparent Data Encryption (TDE)
az sql db tde set --database mydb --server myserver \
  --resource-group mygroup --status Enabled

# Configure firewall rule
az sql server firewall-rule create \
  --resource-group mygroup --server myserver \
  --name AllowMyIP --start-ip-address 1.2.3.4 \
  --end-ip-address 1.2.3.4

# Enable Advanced Threat Protection
az sql db threat-policy update \
  --resource-group mygroup --server myserver \
  --name mydb --state Enabled
```

### Connection Strings

**.NET**
```
Server=tcp:myserver.database.windows.net,1433;Initial Catalog=mydb;Authentication=Active Directory Default;
```

**Node.js (mssql)**
```javascript
const config = {
  server: 'myserver.database.windows.net',
  database: 'mydb',
  authentication: {
    type: 'azure-active-directory-default'
  },
  options: {
    encrypt: true,
    trustServerCertificate: false
  }
};
```

**Python (pyodbc)**
```python
conn_string = (
    'Driver={ODBC Driver 18 for SQL Server};'
    'Server=tcp:myserver.database.windows.net,1433;'
    'Database=mydb;'
    'Authentication=ActiveDirectoryDefault;'
    'Encrypt=yes;'
    'TrustServerCertificate=no;'
)
```

### Key Features
1. **Geo-replication**: Up to 4 readable secondaries
2. **Point-in-time restore**: 7-35 days retention
3. **Automatic backups**: Full, differential, transaction log
4. **Elastic pools**: Share resources across multiple databases
5. **Advanced security**: Threat detection, data masking, auditing
6. **Query Performance Insights**: Identify slow queries

## Azure Cosmos DB

### When to Use
- Global distribution with multi-region writes
- Need single-digit millisecond latency
- Flexible schema (NoSQL)
- Massive scale (petabytes)
- Multiple data models (Document, Key-value, Graph, Column-family)

### API Options
- **Core (SQL)**: Document database, SQL-like queries (recommended)
- **MongoDB**: MongoDB wire protocol compatibility
- **Cassandra**: Column-family, CQL queries
- **Gremlin**: Graph database
- **Table**: Azure Table Storage compatible

### Consistency Levels (from strongest to weakest)
1. **Strong**: Linearizability, highest latency
2. **Bounded Staleness**: Consistent prefix with lag bounds
3. **Session**: Consistent within a session (default, recommended)
4. **Consistent Prefix**: Reads never see out-of-order writes
5. **Eventual**: Lowest latency, highest availability

### Pricing Models
- **Provisioned throughput**: Reserved RU/s, predictable costs
- **Serverless**: Pay per request, variable workloads
- **Autoscale**: Dynamic scaling within limits

### Best Practices

```bash
# Create Cosmos DB account
az cosmosdb create \
  --name mycosmosdb --resource-group mygroup \
  --default-consistency-level Session \
  --locations regionName=eastus failoverPriority=0 \
  --locations regionName=westus failoverPriority=1 \
  --enable-automatic-failover true

# Create SQL API database
az cosmosdb sql database create \
  --account-name mycosmosdb --resource-group mygroup \
  --name mydb --throughput 400

# Create container with partition key
az cosmosdb sql container create \
  --account-name mycosmosdb --database-name mydb \
  --resource-group mygroup --name mycontainer \
  --partition-key-path "/userId" \
  --throughput 400
```

### Design Principles
1. **Choose partition key carefully**: Evenly distribute data and queries
2. **Avoid hot partitions**: Ensure even distribution
3. **Design for scale**: Partition key should support growth
4. **Minimize cross-partition queries**: Use partition key in WHERE clause
5. **Use composite indexes**: For complex queries
6. **Enable TTL**: Auto-delete expired documents
7. **Use change feed**: For event-driven architectures

### Connection Example (.NET)
```csharp
var client = new CosmosClient(
    accountEndpoint: "https://mycosmosdb.documents.azure.com:443/",
    authKeyOrResourceToken: new DefaultAzureCredential()
);

var database = client.GetDatabase("mydb");
var container = database.GetContainer("mycontainer");

// Query with partition key
var query = new QueryDefinition(
    "SELECT * FROM c WHERE c.userId = @userId"
).WithParameter("@userId", "user123");

var iterator = container.GetItemQueryIterator<dynamic>(
    query,
    requestOptions: new QueryRequestOptions {
        PartitionKey = new PartitionKey("user123")
    }
);
```

## Azure Database for PostgreSQL

### Deployment Options
1. **Single Server**: Legacy, being retired
2. **Flexible Server**: Recommended, more control
3. **Hyperscale (Citus)**: Distributed PostgreSQL, 100+ TB

### When to Use Flexible Server
- Full PostgreSQL compatibility (versions 11, 12, 13, 14, 15)
- Need custom extensions
- Zone-redundant HA
- Scheduled maintenance windows
- Better price/performance

### Best Practices

```bash
# Create PostgreSQL Flexible Server
az postgres flexible-server create \
  --name mypostgres --resource-group mygroup \
  --location eastus --admin-user myadmin \
  --admin-password 'MyP@ssw0rd!' \
  --sku-name Standard_D2s_v3 \
  --tier GeneralPurpose --storage-size 128 \
  --version 15 --high-availability ZoneRedundant

# Configure firewall
az postgres flexible-server firewall-rule create \
  --resource-group mygroup --name mypostgres \
  --rule-name AllowMyIP --start-ip-address 1.2.3.4 \
  --end-ip-address 1.2.3.4

# Enable extensions
az postgres flexible-server parameter set \
  --resource-group mygroup --server-name mypostgres \
  --name azure.extensions --value pgaudit,pg_stat_statements
```

### Connection String
```
postgresql://myadmin@mypostgres:MyP@ssw0rd!@mypostgres.postgres.database.azure.com:5432/postgres?sslmode=require
```

### Key Features
- **pgAdmin compatible**
- **Major version upgrades** (11→12→13→14→15)
- **Read replicas**: Up to 5 replicas
- **Zone-redundant HA**: 99.99% SLA
- **Automated backups**: 7-35 days retention
- **Extensions**: PostGIS, TimescaleDB, pgvector (vector search)

## Azure Cache for Redis

### When to Use
- Session state management
- Caching frequently accessed data
- Pub/sub messaging
- Real-time analytics
- Leaderboards and counters

### Pricing Tiers
- **Basic**: Single node, no SLA, dev/test
- **Standard**: 2 nodes (primary/replica), 99.9% SLA
- **Premium**: Clustering, persistence, VNet, geo-replication
- **Enterprise**: Redis Enterprise, active-geo replication, 99.999% SLA

### Best Practices

```bash
# Create Redis cache
az redis create \
  --name myredis --resource-group mygroup \
  --location eastus --sku Standard --vm-size C1 \
  --enable-non-ssl-port false

# Get connection info
az redis show --name myredis --resource-group mygroup \
  --query "[hostName,sslPort]" -o tsv

# List keys
az redis list-keys --name myredis --resource-group mygroup
```

### Connection Examples

**.NET (StackExchange.Redis)**
```csharp
var connection = ConnectionMultiplexer.Connect(
    "myredis.redis.cache.windows.net:6380,password=xxx,ssl=True,abortConnect=False"
);
var db = connection.GetDatabase();

// Set value
await db.StringSetAsync("key", "value", TimeSpan.FromMinutes(10));

// Get value
string value = await db.StringGetAsync("key");
```

**Node.js (ioredis)**
```javascript
const Redis = require('ioredis');
const redis = new Redis({
  port: 6380,
  host: 'myredis.redis.cache.windows.net',
  password: 'xxx',
  tls: { servername: 'myredis.redis.cache.windows.net' }
});

await redis.set('key', 'value', 'EX', 600); // 10 min TTL
const value = await redis.get('key');
```

### Caching Patterns
1. **Cache-Aside**: App checks cache, loads from DB if miss
2. **Write-Through**: Write to cache and DB simultaneously
3. **Write-Behind**: Write to cache, async write to DB
4. **Refresh-Ahead**: Proactively refresh cache before expiry

## Database Decision Tree

```
Need relational database?
├─ Yes ↓
│  SQL Server workload?
│  ├─ Yes ↓
│  │  Need instance-level features (SQL Agent, CLR)?
│  │  ├─ Yes → SQL Managed Instance
│  │  └─ No → Azure SQL Database
│  └─ No ↓
│     PostgreSQL or MySQL?
│     ├─ PostgreSQL → Azure Database for PostgreSQL
│     └─ MySQL → Azure Database for MySQL
│
└─ No (NoSQL) ↓
   Need global distribution?
   ├─ Yes → Cosmos DB
   └─ No ↓
      Simple key-value?
      ├─ Yes → Table Storage
      └─ No ↓
         Caching?
         └─ Yes → Redis Cache
```

## General Database Best Practices

### Security
1. **Use managed identity** for authentication (avoid connection strings)
2. **Enable Transparent Data Encryption (TDE)**
3. **Configure firewall rules** (allow only necessary IPs)
4. **Enable Advanced Threat Protection**
5. **Use Private Endpoints** for VNet integration
6. **Enable auditing** for compliance

### High Availability
1. **Enable geo-replication** for mission-critical data
2. **Use zone-redundant** configuration when available
3. **Configure automatic failover**
4. **Test disaster recovery** procedures regularly

### Performance
1. **Monitor with Azure Monitor** and query performance insights
2. **Use read replicas** for read-heavy workloads
3. **Implement connection pooling**
4. **Index frequently queried columns**
5. **Use caching** (Redis) for hot data
6. **Partition large tables** (Cosmos DB, PostgreSQL)

### Cost Optimization
1. **Right-size your database** (start small, scale up)
2. **Use serverless** for variable workloads
3. **Enable auto-pause** for dev/test databases
4. **Use reserved capacity** for production (save up to 65%)
5. **Delete unused databases** and backups
6. **Monitor DTU/RU usage** and adjust accordingly

### Backup and Recovery
1. **Enable automated backups** (default, but verify)
2. **Test point-in-time restore** regularly
3. **Export important data** to Blob Storage
4. **Configure long-term retention** (LTR) for compliance
5. **Document recovery procedures**

## Monitoring and Diagnostics

### Key Metrics to Monitor
- **DTU/RU percentage**: Resource utilization
- **CPU percentage**: Compute usage
- **Memory percentage**: Memory pressure
- **Storage percentage**: Disk space
- **Connection count**: Active connections
- **Deadlocks**: Database locks
- **Failed connections**: Authentication/network issues
- **Query duration**: Slow queries

### Azure Monitor Queries (KQL)

```kusto
// Top 10 slowest queries
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.SQL"
| where Category == "QueryStoreRuntimeStatistics"
| summarize avg(duration_d) by query_hash_s
| top 10 by avg_duration_d desc

// Failed connections
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.SQL"
| where Category == "SQLSecurityAuditEvents"
| where action_name_s == "DATABASE AUTHENTICATION FAILED"
| summarize count() by client_ip_s, TimeGenerated
```
