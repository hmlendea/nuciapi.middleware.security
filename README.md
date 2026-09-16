[![Donate](https://img.shields.io/badge/-%E2%99%A5%20Donate-%23ff69b4)](https://hmlendea.go.ro/funding)
[![Latest Release](https://img.shields.io/github/v/release/hmlendea/nuciapi.middleware.security)](https://github.com/hmlendea/nuciapi.middleware.security/releases/latest)
[![Build Status](https://github.com/hmlendea/nuciapi.middleware.security/actions/workflows/dotnet.yml/badge.svg)](https://github.com/hmlendea/nuciapi.middleware.security/actions/workflows/dotnet.yml)
[![NuGet](https://img.shields.io/nuget/v/NuciAPI.Middleware.Security)](https://nuget.org/packages/NuciAPI.Middleware.Security)
[![License](https://img.shields.io/github/license/hmlendea/nuciapi.middleware.security)](https://github.com/hmlendea/nuciapi.middleware.security/blob/master/LICENSE)

# NuciAPI.Middleware.Security

Security middleware for ASP.NET Core APIs that validates request headers, rejects replayed requests, and blocks recognised scanner traffic with temporary IP bans.

## 📑 Table of Contents

- [Table of Contents](#table-of-contents)
- [Capabilities](#capabilities)
- [Usage](#usage)
- [Known Limitations](#known-limitations)
- [Installation](#installation)
  - [Package Manager Installation](#package-manager-installation)
  - [Manual Installation](#manual-installation)
- [Compatibility](#compatibility)
- [Privacy and Data](#privacy-and-data)
- [Development](#development)
  - [Requirements](#requirements)
  - [Setup](#setup)
  - [Build](#build)
  - [Test](#test)
  - [Continuous Integration](#continuous-integration)
  - [Release](#release)
  - [Dependencies](#dependencies)
- [Project Structure](#project-structure)
  - [Projects and Packages](#projects-and-packages)
  - [Directories](#directories)
- [Architecture](#architecture)
- [Data Formats and Protocols](#data-formats-and-protocols)
- [Contributing](#contributing)
- [Related Projects](#related-projects)
- [Project Engagement](#project-engagement)
- [License](#license)

## ✨ Capabilities

- Validate required client, request, and timestamp headers prior to endpoint execution.
- Reject duplicate requests and timestamps beyond the five-minute acceptance interval.
- Detect recognised scanner signatures in request paths, query strings, headers, client hints, user agents, and resolved hostnames.
- Temporarily prohibit scanner clients for ten hours and return HTTP `403 Forbidden`.
- Activate header validation, replay protection, and scanner protection independently in an ASP.NET Core pipeline.

## 🚀 Usage

Register the cache-backed protections and add the middleware to the request pipeline:

```csharp
using NuciAPI.Middleware.Security;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddNuciApiScannerProtection();
builder.Services.AddNuciApiReplayProtection();

WebApplication application = builder.Build();

application.UseNuciApiScannerProtection();
application.UseNuciApiHeaderValidation();
application.UseNuciApiReplayProtection();

application.MapControllers();
application.Run();
```

The recommended middleware order is:
1. Scanner protection, so recognised malicious traffic is rejected early.
2. Header validation, so malformed headers are rejected prior to replay evaluation.
3. Replay protection, so nonce checks operate on validated identifiers.

Header and replay validation throw `BadHttpRequestException` for invalid requests. Duplicate requests throw `RequestAlreadyProcessedException`, while scanner protection returns HTTP `403 Forbidden`. Configure the application's exception handling to map thrown exceptions to the preferred API responses.

Clients using header or replay protection must supply the headers documented in [Data Formats and Protocols](#data-formats-and-protocols).

## ⚠️ Known Limitations

- Replay nonces and scanner bans use process-local `IMemoryCache`; multiple application instances do not share this state.
- Scanner protection depends on accurate client IP resolution, so reverse proxy forwarding must be configured correctly.
- Protection intervals and scanner signatures are fixed by the package and do not expose public configuration options.

## 📦 Installation

[![Obtain it from NuGet](https://raw.githubusercontent.com/hmlendea/readme-assets/master/badges/stores/nuget.png)](https://nuget.org/packages/NuciAPI.Middleware.Security)
[![Obtain it from GitHub](https://raw.githubusercontent.com/hmlendea/readme-assets/master/badges/stores/github.png)](https://github.com/hmlendea/nuciapi.middleware.security/releases)

### Package Manager Installation

```bash
dotnet add package NuciAPI.Middleware.Security
```

Or, via the `Package Manager Console`:

```powershell
Install-Package NuciAPI.Middleware.Security
```

### Manual Installation

Each published [GitHub release](https://github.com/hmlendea/nuciapi.middleware.security/releases) includes a `.nupkg` asset and records its SHA256 checksum in the release notes. After downloading the asset, verify it with:

```bash
sha256sum NuciAPI.Middleware.Security.*.nupkg
```

Compare the calculated digest with the release notes, then reference the download directory as a local NuGet source:

```bash
dotnet add package NuciAPI.Middleware.Security --source ./downloads
```

## 🧩 Compatibility

| Component | Supported Versions | Notes |
|-----------|--------------------|-------|
| .NET | 10.0 | The package targets `net10.0`. |
| ASP.NET Core | 10.0 | The package requires the `Microsoft.AspNetCore.App` shared framework. |

## 🛡️ Privacy and Data

| Data | Purpose | Storage | Retention | Optional |
|------|---------|---------|-----------|----------|
| Client identifier, request identifier, and request path | Detect replayed requests | Process-local `IMemoryCache` | Five minutes | No, when replay protection is active |
| Client IP address | Enforce temporary scanner bans | Process-local `IMemoryCache` | Ten hours | No, when scanner protection is active |
| Selected headers and root-request body | Evaluate scanner signatures and vacant root requests | Not persisted by this package | Request lifetime | No, when scanner protection is active |

## 🛠️ Development

### Requirements

- [.NET 10.0 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- [Git](https://git-scm.com/)

### Setup

Clone the repository and restore the [solution](./NuciAPI.Middleware.Security.sln):

```bash
git clone https://github.com/hmlendea/nuciapi.middleware.security.git
cd nuciapi.middleware.security
dotnet restore NuciAPI.Middleware.Security.sln
```

### Build

Compile the solution:

```bash
dotnet build NuciAPI.Middleware.Security.sln --no-restore
```

Create a local NuGet package:

```bash
dotnet pack NuciAPI.Middleware.Security/NuciAPI.Middleware.Security.csproj -c Release --no-restore
```

### Test

Execute the unit tests:

```bash
dotnet test NuciAPI.Middleware.Security.sln
```

### Continuous Integration

The [.NET workflow](./.github/workflows/dotnet.yml) restores dependencies, compiles the solution, and executes the tests for pushes and pull requests targeting `master`.

### Release

The [GitHub Release workflow](./.github/workflows/github-release.yml) is initiated when a GitHub release is published.

To publish an asset:
1. Create a GitHub release with a tag in the form `v<version>`.
2. Publish the release.
3. Confirm that the workflow uploads `NuciAPI.Middleware.Security.<version>.nupkg` and appends its SHA256 checksum to the release notes.

The workflow derives the package version from the tag and compiles in `Release` configuration. It does not sign the package or publish it to NuGet.org.

### Dependencies

| Package | Version | Scope | Purpose |
|---------|---------|-------|---------|
| `Microsoft.AspNetCore.App` | 10.0 | Runtime | Provides the ASP.NET Core middleware and HTTP abstractions. |
| `NuciAPI.Middleware` | 2.0.2 | Runtime | Provides the base middleware contract and shared header names. |
| `NuciWeb.HTTP` | 1.7.1 | Runtime | Provides client IP and hostname network utilities. |
| `Microsoft.NET.Test.Sdk` | 18.3.0 | Test | Executes tests via the .NET test host. |
| `Moq` | 4.20.72 | Test | Provides test doubles. |
| `NUnit` | 4.5.1 | Test | Provides the unit-testing framework. |
| `NUnit3TestAdapter` | 6.2.0 | Test | Integrates NUnit discovery and execution with the .NET test host. |

## 🗂️ Project Structure

The solution separates the distributable middleware library from its NUnit test project.

### Projects and Packages

| Project | Type | Purpose |
|---------|------|---------|
| [NuciAPI.Middleware.Security](./NuciAPI.Middleware.Security/NuciAPI.Middleware.Security.csproj) | NuGet library | Implements header validation, replay protection, and scanner protection. |
| [NuciAPI.Middleware.Security.UnitTests](./NuciAPI.Middleware.Security.UnitTests/NuciAPI.Middleware.Security.UnitTests.csproj) | NUnit test project | Verifies middleware registration, validation, replay detection, and scanner filtering. |

### Directories

| Directory | Purpose |
|-----------|---------|
| [`.github/workflows`](./.github/workflows) | Contains continuous integration and GitHub Release automation. |

## 🏗️ Architecture

For more information, see [architecture documentation](./ARCHITECTURE.md).

## 🧾 Data Formats and Protocols

| Format or Protocol | Specification | Purpose |
|--------------------|---------------|---------|
| Client identifier header | `NuciApiHeaderNames.ClientId`; text longer than three characters | Identifies the client and contributes to replay nonce keys. |
| Request identifier header | `NuciApiHeaderNames.RequestId`; uppercase GUID | Uniquely identifies a request and contributes to replay nonce keys. |
| Timestamp header | `NuciApiHeaderNames.Timestamp`; valid `DateTimeOffset` within five minutes of UTC | Establishes request freshness for replay protection. |

## 🤝 Contributing

You are welcome to submit any suggestion, feedback, or modification to this project.

When doing so, please:
- Maintain cross-platform compatibility
- Preserve the existing public contract unless a breaking change is intentional
- Submit focused pull requests that conform to the existing code style
- Maintain your branch synchronised with `master`
- Revise the documentation when functionality changes
- Properly test all modifications, including edge cases and error conditions
- Add tests for additional or modified functionality
- Raise a new [issue](https://github.com/hmlendea/nuciapi.middleware.security/issues) for problems or suggestions

## 🔗 Related Projects

- [NuciAPI.Middleware](https://github.com/hmlendea/nuciapi.middleware): Base middleware package used by this library.
- [NuciAPI.Middleware.ExceptionHandling](https://github.com/hmlendea/nuciapi.middleware.exceptionhandling): Companion middleware for central exception handling.
- [NuciAPI.Middleware.Logging](https://github.com/hmlendea/nuciapi.middleware.logging): Companion middleware for API request logging.

## 💝 Project Engagement

Discovered a problem or have a suggestion? [Open an issue](https://github.com/hmlendea/nuciapi.middleware.security/issues)!

If you find this project useful, consider [funding it](https://hmlendea.go.ro/funding) or starring ⭐️ it on GitHub!

[![Donate](https://raw.githubusercontent.com/hmlendea/readme-assets/master/donate_generic.png)](https://hmlendea.go.ro/funding)

## 📄 License

This project is being distributed under the `GNU General Public License version 3` or later.
See [LICENSE](./LICENSE) for further information.
