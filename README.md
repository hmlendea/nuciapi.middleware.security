[![Donate](https://img.shields.io/badge/-%E2%99%A5%20Donate-%23ff69b4)](https://hmlendea.go.ro/fund.html)
[![Latest Release](https://img.shields.io/github/v/release/hmlendea/nuciapi.middleware.security)](https://github.com/hmlendea/nuciapi.middleware.security/releases/latest)
[![Build Status](https://github.com/hmlendea/nuciapi.middleware.security/actions/workflows/dotnet.yml/badge.svg)](https://github.com/hmlendea/nuciapi.middleware.security/actions/workflows/dotnet.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://gnu.org/licenses/gpl-3.0)

# NuciAPI.Middleware.Security

Security-focused middleware for ASP.NET Core APIs built on top of the NuciAPI middleware stack.

It provides three independent protections you can enable as needed:

- request header validation
- replay attack protection
- scanner/bot request blocking with temporary IP bans

## Installation

[![Get it from NuGet](https://raw.githubusercontent.com/hmlendea/readme-assets/master/badges/stores/nuget.png)](https://nuget.org/packages/NuciAPI.Middleware.Security)

### .NET CLI

```bash
dotnet add package NuciAPI.Middleware.Security
```

### Package Manager

```powershell
Install-Package NuciAPI.Middleware.Security
```

## Requirements

- .NET SDK/runtime with support for `net10.0`
- ASP.NET Core (`Microsoft.AspNetCore.App`)

## What This Package Includes

### 1) Header Validation Middleware

Validates required request headers before your endpoint logic runs.

Rules:

- `NuciApiHeaderNames.ClientId` must be longer than 3 characters
- `NuciApiHeaderNames.RequestId` must be an uppercase GUID
- `NuciApiHeaderNames.Timestamp` must be a valid `DateTimeOffset` value

Invalid values produce `BadHttpRequestException`.

### 2) Replay Protection Middleware

Rejects duplicate requests and timestamps outside an allowed clock skew window.

Behavior:

- accepted timestamp skew is ±5 minutes from UTC now
- a nonce key is built from client ID + request ID + request path
- seen nonces are stored in `IMemoryCache` for 5 minutes
- duplicate requests throw `RequestAlreadyProcessedException`
- expired or far-future timestamps throw `BadHttpRequestException`

### 3) Scanner Protection Middleware

Blocks suspicious probing/scanner traffic patterns.

Behavior:

- checks request path/query against known scanner signatures
- blocks known suspicious header patterns (`From`, `User-Agent`, `sec-ch-ua`)
- marks offending IPs as banned for 10 hours via `IMemoryCache`
- banned requests return HTTP `403 Forbidden`

## Quick Start

In your `Program.cs`, register required services and add middleware to the pipeline.

```csharp
using NuciAPI.Middleware.Security;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddNuciApiScannerProtection();
builder.Services.AddNuciApiReplayProtection();

WebApplication app = builder.Build();

app.UseNuciApiScannerProtection();
app.UseNuciApiHeaderValidation();
app.UseNuciApiReplayProtection();

app.MapControllers();

app.Run();
```

Recommended order:

1. Scanner protection first, so obvious malicious traffic is rejected early.
2. Header validation before replay protection, so malformed headers fail with clear 400 responses.
3. Replay protection after validation, so duplicate checks run on validated identifiers.

## Request Header Contract

Clients should always send:

- client identifier (`NuciApiHeaderNames.ClientId`)
- unique, uppercase GUID request identifier (`NuciApiHeaderNames.RequestId`)
- request timestamp (`NuciApiHeaderNames.Timestamp`)

Recommended timestamp format is round-trip (`"O"`) from .NET.

Example:

```csharp
context.Request.Headers[NuciApiHeaderNames.Timestamp] = DateTimeOffset.UtcNow.ToString("O");
```

## Error Handling Guidance

This package throws exceptions for invalid/replayed requests and sets `403` for blocked scanner traffic.

For production APIs, add a global exception handling strategy (middleware/filter) to map:

- `BadHttpRequestException` -> `400 Bad Request`
- `RequestAlreadyProcessedException` -> typically `409 Conflict` (or your API contract equivalent)

## Notes

- Replay and scanner protection rely on in-memory cache. In multi-instance deployments, each node tracks its own cache unless you adapt behavior to a distributed store.
- Scanner protection uses client IP discovery from the incoming request context; ensure your reverse proxy forwarding setup is correct.

## Usage Example

```csharp
using Microsoft.AspNetCore.Mvc;
using NuciAPI.Middleware;

[ApiController]
[Route("orders")]
public sealed class OrdersController : ControllerBase
{
	[HttpPost]
	public IActionResult CreateOrder()
	{
		string clientId = Request.Headers[NuciApiHeaderNames.ClientId]!;
		string requestId = Request.Headers[NuciApiHeaderNames.RequestId]!;

		return Ok(new
		{
			Message = "Accepted",
			ClientId = clientId,
			RequestId = requestId
		});
	}
}
```

## Development

### Build

```bash
dotnet build NuciAPI.Middleware.Security.sln
```

### Test

```bash
dotnet test
```

### Pack

```bash
dotnet pack -c Release
```

## Contributing

Contributions are welcome.

Please:

- keep the changes cross-platform
- keep the pull requests focused and consistent with the existing style
- update the documentation when the behaviour changes
- add or update the tests for any new behaviour

## Related Projects

- [NuciAPI.Middleware](https://github.com/hmlendea/nuciapi.middleware)
- [NuciAPI.Middleware.ExceptionHandling](https://github.com/hmlendea/nuciapi.middleware.exceptionhandling)
- [NuciAPI.Middleware.Logging](https://github.com/hmlendea/nuciapi.middleware.logging)
- [NuciAPI.Middleware.Security](https://github.com/hmlendea/nuciapi.middleware.security)

## License

Licensed under the GNU General Public License v3.0 or later.
See [LICENSE](./LICENSE) for details.
