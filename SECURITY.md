# Security Policy

This policy covers security vulnerabilities in NuciAPI.Middleware.Security, a security-focused ASP.NET Core middleware package. The latest maintained release is version 1.0.6, distributed through NuGet and GitHub Releases. Please report vulnerabilities privately so they can be validated and remediated before public disclosure.

## 📑 Table of Contents

- [Table of Contents](#-table-of-contents)
- [Supported Versions](#supported-versions)
- [Reporting a Vulnerability](#reporting-a-vulnerability)
- [Scope](#scope)
- [Disclosure Policy](#disclosure-policy)

## 🛡️ Supported Versions

Use this table to indicate which project versions currently receive security maintenance.

| Version | Distribution Channel | Supported |
|---------|--------------------|-----------|
| 1.0.6 | NuGet | ✅ |
| 1.0.6 | GitHub Releases | ✅ |
| Preceding versions | Any distribution channel | ❌ |

## 🚨 Reporting a Vulnerability

Please do not disclose suspected vulnerabilities publicly before maintainers have had an opportunity to validate and remediate them.

To report a vulnerability:
- [GitHub Security Advisories](https://github.com/hmlendea/nuciapi.middleware.security/security/advisories)
- Contact the maintainers directly

## 📌 Scope

The subsequent report categories are in scope for this repository:
- Request header validation and replay-protection logic
- Scanner detection, request blocking, and temporary IP-ban logic

The subsequent categories are out of scope unless explicitly stated to the contrary:
- Vulnerabilities in applications or infrastructure that consume this package
- Vulnerabilities in the .NET runtime, ASP.NET Core, or third-party dependencies

## 📢 Disclosure Policy

This project follows coordinated disclosure:
1. Vulnerabilities are investigated privately.
2. A remediation plan is prepared and validated.
3. Public disclosure is published after a fix, mitigation, or agreed risk decision is available.
4. Credit is attributed in accordance with reporter preference and project policy.
