# Security Policy for Azure Security Audit Framework

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |

## Reporting a Vulnerability

This repository contains Azure security audit scripts, detection queries, and infrastructure templates. If you discover:

- An incorrect or ineffective security detection
- A PowerShell script that fails to handle legitimate configurations safely
- A policy or playbook that could cause unintended harm
- A security vulnerability in any script or template

Please report it privately by emailing the repository owner or opening a [GitHub Security Advisory](https://github.com/pirateape/Azure-Security/security/advisories).

We aim to respond within 5 business days.

## Safe Usage

These scripts interact with Azure, Microsoft Graph, and M365 APIs. Always:

1. Review scripts before running in production
2. Test in a sandbox environment first
3. Use `-WhatIf` where available
4. Ensure your service principal or account has the minimum permissions required
5. Never store credentials or tokens in this repository

## Related

- [ApeGuard](https://github.com/pirateape/ape-guard) — Local security posture scanner
- [Unified Zero Trust Framework](https://github.com/pirateape/unified-zero-trust-framework) — 8-pillar maturity model
