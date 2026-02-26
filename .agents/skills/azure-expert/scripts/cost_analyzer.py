#!/usr/bin/env python3
"""
Azure Cost Analyzer

Analyzes Azure costs and provides recommendations for optimization.
Helps identify expensive resources and suggests cost-saving measures.
"""

import subprocess
import json
import sys
from datetime import datetime, timedelta
from collections import defaultdict


def run_az_command(cmd: str, check=True) -> str:
    """Execute Azure CLI command"""
    try:
        result = subprocess.run(
            f"az {cmd}",
            shell=True,
            capture_output=True,
            text=True,
            check=check
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        if check:
            print(f"❌ Error: {e.stderr}")
        return ""


def get_subscription_costs(days=30):
    """Get cost data for the subscription"""
    print(f"\n💰 Analyzing costs for the last {days} days...")
    print("=" * 70)

    # Calculate date range
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)

    # Format dates for Azure Cost Management API
    start = start_date.strftime("%Y-%m-%d")
    end = end_date.strftime("%Y-%m-%d")

    # Get costs by resource group
    print("\n📊 Cost by Resource Group:")
    cost_json = run_az_command(
        f"costmanagement query "
        f"--type Usage "
        f"--timeframe Custom "
        f"--time-period from={start} to={end} "
        f"--dataset-aggregation '{{\"totalCost\":{{\"name\":\"PreTaxCost\",\"function\":\"Sum\"}}}}' "
        f"--dataset-grouping name=ResourceGroup type=Dimension",
        check=False
    )

    if cost_json:
        try:
            costs = json.loads(cost_json)
            rows = costs.get('properties', {}).get('rows', [])

            if rows:
                # Sort by cost (descending)
                sorted_costs = sorted(rows, key=lambda x: x[0], reverse=True)

                total_cost = sum(row[0] for row in sorted_costs)

                for cost, resource_group, currency in sorted_costs[:10]:  # Top 10
                    percentage = (cost / total_cost * 100) if total_cost > 0 else 0
                    print(f"  {resource_group:.<40} ${cost:>10.2f} ({percentage:>5.1f}%)")

                print(f"\n  {'Total':.>40} ${total_cost:>10.2f}")
            else:
                print("  No cost data available")
        except json.JSONDecodeError:
            print("  Unable to parse cost data")


def analyze_app_service_plans(resource_group=None):
    """Analyze App Service Plans for optimization opportunities"""
    print("\n\n🔍 App Service Plan Analysis:")
    print("=" * 70)

    cmd = "appservice plan list"
    if resource_group:
        cmd += f" --resource-group {resource_group}"

    plans_json = run_az_command(cmd, check=False)

    if not plans_json:
        print("  No App Service Plans found")
        return

    plans = json.loads(plans_json)

    recommendations = []

    for plan in plans:
        name = plan['name']
        sku = plan['sku']['name']
        tier = plan['sku']['tier']
        capacity = plan['sku']['capacity']

        # Get apps in this plan
        apps_json = run_az_command(
            f"webapp list --query \"[?appServicePlanId=='{plan['id']}']\"",
            check=False
        )

        app_count = len(json.loads(apps_json)) if apps_json else 0

        print(f"\n  📋 {name}")
        print(f"     SKU: {tier} ({sku}) x{capacity}")
        print(f"     Apps: {app_count}")

        # Recommendations
        if app_count == 0:
            recommendations.append(f"⚠️  {name}: No apps deployed - consider deleting")
        elif tier == "Premium" and app_count < 3:
            recommendations.append(f"💡 {name}: Premium tier with few apps - consider downgrading")
        elif tier == "Standard" and app_count == 1:
            recommendations.append(f"💡 {name}: Standard tier for single app - consider Basic tier")

    if recommendations:
        print("\n\n💡 Recommendations:")
        print("-" * 70)
        for rec in recommendations:
            print(f"  {rec}")


def analyze_databases(resource_group=None):
    """Analyze SQL Databases for optimization"""
    print("\n\n🗄️  SQL Database Analysis:")
    print("=" * 70)

    cmd = "sql server list"
    if resource_group:
        cmd += f" --resource-group {resource_group}"

    servers_json = run_az_command(cmd, check=False)

    if not servers_json:
        print("  No SQL Servers found")
        return

    servers = json.loads(servers_json)

    for server in servers:
        server_name = server['name']
        rg = server['resourceGroup']

        # Get databases
        dbs_json = run_az_command(
            f"sql db list --server {server_name} --resource-group {rg}",
            check=False
        )

        if not dbs_json:
            continue

        databases = json.loads(dbs_json)

        print(f"\n  🖥️  Server: {server_name}")

        for db in databases:
            if db['name'] == 'master':
                continue

            name = db['name']
            tier = db['sku']['tier']
            capacity = db.get('sku', {}).get('capacity', 'N/A')

            print(f"     └─ {name}: {tier} ({capacity} DTUs)")

            # Check for optimization opportunities
            if tier == "Premium" or tier == "BusinessCritical":
                print(f"        💡 Consider if Premium/BusinessCritical tier is necessary")


def analyze_storage_accounts(resource_group=None):
    """Analyze storage accounts"""
    print("\n\n💾 Storage Account Analysis:")
    print("=" * 70)

    cmd = "storage account list"
    if resource_group:
        cmd += f" --resource-group {resource_group}"

    accounts_json = run_az_command(cmd, check=False)

    if not accounts_json:
        print("  No Storage Accounts found")
        return

    accounts = json.loads(accounts_json)

    for account in accounts:
        name = account['name']
        sku = account['sku']['name']
        tier = account['sku']['tier']

        print(f"  📦 {name}")
        print(f"     SKU: {tier} ({sku})")

        # Recommendations
        if 'Premium' in sku:
            print(f"     💡 Premium storage - ensure it's needed for performance")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Analyze Azure costs and resources")
    parser.add_argument("--resource-group", "-g", help="Focus on specific resource group")
    parser.add_argument("--days", "-d", type=int, default=30, help="Days to analyze (default: 30)")

    args = parser.parse_args()

    print("🔍 Azure Cost Analyzer")
    print("=" * 70)

    # Get current subscription
    sub_json = run_az_command("account show", check=False)
    if sub_json:
        sub = json.loads(sub_json)
        print(f"Subscription: {sub['name']} ({sub['id']})")

    # Run analyses
    get_subscription_costs(args.days)
    analyze_app_service_plans(args.resource_group)
    analyze_databases(args.resource_group)
    analyze_storage_accounts(args.resource_group)

    print("\n" + "=" * 70)
    print("✅ Analysis complete")
    print("\n💡 General recommendations:")
    print("  • Use Azure Reserved Instances for predictable workloads (up to 72% savings)")
    print("  • Enable autoscaling to match capacity with demand")
    print("  • Use Azure Advisor for personalized recommendations")
    print("  • Consider Spot VMs for non-critical workloads")
    print("  • Review and delete unused resources regularly")


if __name__ == "__main__":
    main()
