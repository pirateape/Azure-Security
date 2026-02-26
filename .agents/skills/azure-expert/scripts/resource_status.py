#!/usr/bin/env python3
"""
Azure Resource Status Checker

Quickly check the status and health of Azure resources.
Useful for troubleshooting and monitoring.
"""

import subprocess
import json
import sys
from typing import Dict, List


def run_az_command(cmd: str) -> str:
    """Execute Azure CLI command and return JSON output"""
    try:
        result = subprocess.run(
            f"az {cmd}",
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e.stderr}")
        return ""


def check_webapp_status(resource_group: str, name: str):
    """Check Web App status and configuration"""
    print(f"\n🌐 Web App: {name}")
    print("=" * 50)

    # Get app details
    app_json = run_az_command(
        f"webapp show --name {name} --resource-group {resource_group}"
    )

    if not app_json:
        return

    app = json.loads(app_json)

    print(f"  State: {app.get('state', 'Unknown')}")
    print(f"  URL: https://{app.get('defaultHostName', 'N/A')}")
    print(f"  Location: {app.get('location', 'N/A')}")
    print(f"  Runtime: {app.get('siteConfig', {}).get('linuxFxVersion', 'N/A')}")

    # Check if running
    availability = run_az_command(
        f"webapp show --name {name} --resource-group {resource_group} "
        f"--query 'availabilityState' -o tsv"
    )
    print(f"  Availability: {availability}")

    # Get recent logs
    print(f"\n  📋 Recent logs:")
    logs = run_az_command(
        f"webapp log show --name {name} --resource-group {resource_group}",
    )
    if logs:
        log_lines = logs.split('\n')[-10:]  # Last 10 lines
        for line in log_lines:
            if line.strip():
                print(f"    {line}")


def check_function_status(resource_group: str, name: str):
    """Check Azure Function status"""
    print(f"\n⚡ Function App: {name}")
    print("=" * 50)

    func_json = run_az_command(
        f"functionapp show --name {name} --resource-group {resource_group}"
    )

    if not func_json:
        return

    func = json.loads(func_json)

    print(f"  State: {func.get('state', 'Unknown')}")
    print(f"  Runtime: {func.get('kind', 'N/A')}")
    print(f"  URL: https://{func.get('defaultHostName', 'N/A')}")

    # List functions
    functions = run_az_command(
        f"functionapp function show --resource-group {resource_group} "
        f"--name {name}"
    )
    print(f"  Functions deployed: {len(json.loads(functions)) if functions else 0}")


def check_container_app_status(resource_group: str, name: str):
    """Check Container App status"""
    print(f"\n📦 Container App: {name}")
    print("=" * 50)

    app_json = run_az_command(
        f"containerapp show --name {name} --resource-group {resource_group}"
    )

    if not app_json:
        return

    app = json.loads(app_json)

    print(f"  Provisioning State: {app.get('properties', {}).get('provisioningState', 'Unknown')}")
    print(f"  Running Status: {app.get('properties', {}).get('runningStatus', 'Unknown')}")
    print(f"  FQDN: {app.get('properties', {}).get('configuration', {}).get('ingress', {}).get('fqdn', 'N/A')}")

    # Get replicas
    replicas = app.get('properties', {}).get('template', {}).get('scale', {})
    print(f"  Replicas: {replicas.get('minReplicas', 0)} - {replicas.get('maxReplicas', 0)}")


def check_sql_database_status(resource_group: str, server: str, database: str):
    """Check SQL Database status"""
    print(f"\n🗄️  SQL Database: {server}/{database}")
    print("=" * 50)

    db_json = run_az_command(
        f"sql db show --resource-group {resource_group} "
        f"--server {server} --name {database}"
    )

    if not db_json:
        return

    db = json.loads(db_json)

    print(f"  Status: {db.get('status', 'Unknown')}")
    print(f"  Tier: {db.get('sku', {}).get('tier', 'N/A')}")
    print(f"  Size: {db.get('maxSizeBytes', 0) / (1024**3):.2f} GB")
    print(f"  Location: {db.get('location', 'N/A')}")


def list_resources_in_group(resource_group: str):
    """List all resources in a resource group"""
    print(f"\n📋 Resources in {resource_group}")
    print("=" * 50)

    resources_json = run_az_command(
        f"resource list --resource-group {resource_group}"
    )

    if not resources_json:
        return

    resources = json.loads(resources_json)

    for resource in resources:
        print(f"  • {resource['type']}: {resource['name']}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Check Azure resource status")
    parser.add_argument("--resource-group", "-g", required=True, help="Resource group name")
    parser.add_argument("--type", "-t", choices=["webapp", "function", "container", "sql", "all"],
                       default="all", help="Resource type to check")
    parser.add_argument("--name", "-n", help="Resource name")
    parser.add_argument("--server", help="SQL Server name (for SQL database)")
    parser.add_argument("--database", help="Database name (for SQL database)")

    args = parser.parse_args()

    print(f"🔍 Checking Azure resources in {args.resource_group}...")

    if args.type == "all":
        list_resources_in_group(args.resource_group)
    elif args.type == "webapp" and args.name:
        check_webapp_status(args.resource_group, args.name)
    elif args.type == "function" and args.name:
        check_function_status(args.resource_group, args.name)
    elif args.type == "container" and args.name:
        check_container_app_status(args.resource_group, args.name)
    elif args.type == "sql" and args.server and args.database:
        check_sql_database_status(args.resource_group, args.server, args.database)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
