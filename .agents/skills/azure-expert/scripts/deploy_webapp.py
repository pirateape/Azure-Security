#!/usr/bin/env python3
"""
Azure Web App Deployment Script

Deploys a web application to Azure App Service with proper configuration.
Supports multiple runtimes: .NET, Node.js, Python, Java, PHP
"""

import subprocess
import sys
import argparse
import json


def run_command(cmd, check=True):
    """Execute a shell command and return output"""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
    return result.stdout.strip()


def check_azure_cli():
    """Verify Azure CLI is installed and user is logged in"""
    try:
        run_command("az --version")
        account = run_command("az account show")
        return True
    except subprocess.CalledProcessError:
        print("❌ Azure CLI not installed or not logged in")
        print("Run: az login")
        return False


def deploy_webapp(resource_group, app_name, runtime, location="eastus", sku="B1"):
    """
    Deploy a web app to Azure App Service

    Args:
        resource_group: Name of the resource group
        app_name: Name of the web app
        runtime: Runtime stack (e.g., "DOTNET:8.0", "NODE:20-lts", "PYTHON:3.11")
        location: Azure region
        sku: App Service Plan SKU (F1, B1, B2, S1, P1V2, etc.)
    """
    print(f"🚀 Deploying {app_name} to Azure App Service...")

    # Create resource group if it doesn't exist
    print(f"📦 Creating resource group: {resource_group}")
    run_command(
        f"az group create --name {resource_group} --location {location}",
        check=False
    )

    # Create App Service Plan
    plan_name = f"{app_name}-plan"
    print(f"📋 Creating App Service Plan: {plan_name}")
    run_command(
        f"az appservice plan create --name {plan_name} "
        f"--resource-group {resource_group} --sku {sku} --is-linux"
    )

    # Create Web App
    print(f"🌐 Creating Web App: {app_name}")
    run_command(
        f"az webapp create --resource-group {resource_group} "
        f"--plan {plan_name} --name {app_name} --runtime '{runtime}'"
    )

    # Enable Application Insights (optional but recommended)
    print(f"📊 Enabling Application Insights...")
    run_command(
        f"az monitor app-insights component create "
        f"--app {app_name}-insights --location {location} "
        f"--resource-group {resource_group} --application-type web",
        check=False
    )

    # Link App Insights to Web App
    insights_key = run_command(
        f"az monitor app-insights component show "
        f"--app {app_name}-insights --resource-group {resource_group} "
        f"--query instrumentationKey -o tsv",
        check=False
    )

    if insights_key:
        run_command(
            f"az webapp config appsettings set --name {app_name} "
            f"--resource-group {resource_group} "
            f"--settings APPINSIGHTS_INSTRUMENTATIONKEY={insights_key}",
            check=False
        )

    # Get the URL
    url = run_command(
        f"az webapp show --name {app_name} --resource-group {resource_group} "
        f"--query defaultHostName -o tsv"
    )

    print(f"\n✅ Deployment complete!")
    print(f"🔗 URL: https://{url}")
    print(f"\n📝 Next steps:")
    print(f"   1. Deploy your code: az webapp up --name {app_name}")
    print(f"   2. View logs: az webapp log tail --name {app_name} --resource-group {resource_group}")
    print(f"   3. Configure settings: az webapp config appsettings set --name {app_name} --resource-group {resource_group} --settings KEY=VALUE")


def main():
    parser = argparse.ArgumentParser(description="Deploy web app to Azure App Service")
    parser.add_argument("--resource-group", "-g", required=True, help="Resource group name")
    parser.add_argument("--name", "-n", required=True, help="Web app name")
    parser.add_argument("--runtime", "-r", required=True,
                       help="Runtime (e.g., DOTNET:8.0, NODE:20-lts, PYTHON:3.11, JAVA:17-java17)")
    parser.add_argument("--location", "-l", default="eastus", help="Azure region")
    parser.add_argument("--sku", "-s", default="B1", help="App Service Plan SKU")

    args = parser.parse_args()

    if not check_azure_cli():
        sys.exit(1)

    deploy_webapp(
        args.resource_group,
        args.name,
        args.runtime,
        args.location,
        args.sku
    )


if __name__ == "__main__":
    main()
