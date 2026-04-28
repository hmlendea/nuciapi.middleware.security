using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;

namespace NuciAPI.Middleware.Security
{
    internal sealed class ScannerProtectionMiddleware(
        RequestDelegate next,
        IMemoryCache memoryCache)
        : NuciApiMiddleware(next)
    {
        private static readonly TimeSpan BanDuration = TimeSpan.FromHours(10);

        private static readonly string[] SafeVerbs = ["POST", "GET", "PUT", "DELETE", "PATCH"];

        private static readonly string[] ForbiddenUserAgentKeywords =
        [
            "Chrome/143.0.0.0",
            "InternetMeasurement",
            "OAI-SearchBot",
            "SecurityScanner",
        ];

        private static readonly string[] ForbiddenClientHintsKeywords =
        [
            ".Not/A)Brand"
        ];

        private static readonly string[] ForbiddenFromHeaders =
        [
            "oai-searchbot(at)openai.com",
        ];

        private static readonly Regex[] ForbiddenResourcePatterns =
        [
            CreateExactPathRegex("/_ignition/execute-solution"),
            CreateExactPathRegex("/.aws/config"),
            CreateExactPathRegex("/.aws/credentials"),
            CreateExactPathRegex("/.boto"),
            CreateExactPathRegex("/.composer/auth.json"),
            CreateExactPathRegex("/.DS_Store"),
            CreateExactPathRegex("/.htpasswd"),
            CreateExactPathRegex("/.netrc"),
            CreateExactPathRegex("/.npmrc"),
            CreateExactPathRegex("/.pgpass"),
            CreateExactPathRegex("/.streamlit/secrets.toml"),
            CreateExactPathRegex("/.travis.yml"),
            CreateExactPathRegex("/.well-known/security.txt"),
            CreateExactPathRegex("/@vite/env"),
            CreateExactPathRegex("/actuator/beans"),
            CreateExactPathRegex("/actuator/configprops"),
            CreateExactPathRegex("/actuator/env"),
            CreateExactPathRegex("/actuator/health"),
            CreateExactPathRegex("/actuator/heapdump"),
            CreateExactPathRegex("/api/gql"),
            CreateExactPathRegex("/api/graphql"),
            CreateExactPathRegex("/app.config"),
            CreateExactPathRegex("/app.toml"),
            CreateExactPathRegex("/app/"),
            CreateExactPathRegex("/app/etc/local.xml"),
            CreateExactPathRegex("/application.properties"),
            CreateExactPathRegex("/application.yml"),
            CreateExactPathRegex("/appsettings.json"),
            CreateExactPathRegex("/assets/js/auth.js"),
            CreateExactPathRegex("/assets/js/message.js"),
            CreateExactPathRegex("/assets/js/qr_modal.js"),
            CreateExactPathRegex("/autodiscover/autodiscover.json"),
            CreateExactPathRegex("/aws.env"),
            CreateExactPathRegex("/aws.json"),
            CreateExactPathRegex("/bot-connect.js"),
            CreateExactPathRegex("/config.json"),
            CreateExactPathRegex("/config/default.json"),
            CreateExactPathRegex("/config/server.js"),
            CreateExactPathRegex("/connectionstrings.config"),
            CreateExactPathRegex("/credentials.json"),
            CreateExactPathRegex("/credentials.yml.enc"),
            CreateExactPathRegex("/credentials"),
            CreateExactPathRegex("/css/support_parent.css"),
            CreateExactPathRegex("/currentsetting.htm"),
            CreateExactPathRegex("/debug/default/view"),
            CreateExactPathRegex("/developmentserver/metadatauploader"),
            CreateExactPathRegex("/ecosystem.config.js"),
            CreateExactPathRegex("/ecp/Current/exporttool/microsoft.exchange.ediscovery.exporttool.application"),
            CreateExactPathRegex("/env"),
            CreateExactPathRegex("/error_log"),
            CreateExactPathRegex("/geoserver/web/"),
            CreateExactPathRegex("/go"),
            CreateExactPathRegex("/graphql"),
            CreateExactPathRegex("/graphql/api"),
            CreateExactPathRegex("/hibernate.cfg.xml"),
            CreateExactPathRegex("/icons/ubuntu-logo.png"),
            CreateExactPathRegex("/js/config.js"),
            CreateExactPathRegex("/js/lkk_ch.js"),
            CreateExactPathRegex("/js/twint_ch.js"),
            CreateExactPathRegex("/local_settings.py"),
            CreateExactPathRegex("/login.action"),
            CreateExactPathRegex("/mcp"),
            CreateExactPathRegex("/next"),
            CreateExactPathRegex("/owa/auth/logon.aspx"),
            CreateExactPathRegex("/owa/auth/x.js"),
            CreateExactPathRegex("/profiler/_phpinfo"),
            CreateExactPathRegex("/r"),
            CreateExactPathRegex("/redirect-to"),
            CreateExactPathRegex("/redirect/"),
            CreateExactPathRegex("/redirect/testdomain.com"),
            CreateExactPathRegex("/remote/login"),
            CreateExactPathRegex("/robots.txt"),
            CreateExactPathRegex("/package.json"),
            CreateExactPathRegex("/SDK/webLanguage"),
            CreateExactPathRegex("/security.txt"),
            CreateExactPathRegex("/serverless.yml"),
            CreateExactPathRegex("/sitemap.xml"),
            CreateExactPathRegex("/api-keys.txt"),
            CreateExactPathRegex("/sse"),
            CreateExactPathRegex("/telescope/requests"),
            CreateExactPathRegex("/terraform.tfstate"),
            CreateExactPathRegex("/terraform.tfvars"),
            CreateExactPathRegex("/trace.axd"),
            CreateExactPathRegex("/.vercel/.env.production.local"),
            CreateExactPathRegex("/.pypirc"),
            CreateExactPathRegex("/_profiler"),
            CreateExactPathRegex("/url"),
            CreateExactPathRegex("/v2/_catalog"),
            CreateExactPathRegex("/web.config"),
            CreateRawRegex("/docker-compose\\.y[a]?ml"),
            CreateRawRegex("^.*::\\$DATA$"),
            CreateRawRegex("^.*/_environment$"),
            CreateRawRegex("^.*/(database|db)\\.(js|json|properties|sql|y[a]?ml|zip)$"),
            CreateRawRegex("^.*/(error)\\.log$"),
            CreateRawRegex("^.*/(secrets|settings)\\.(json|py|yml)$"),
            CreateRawRegex("^.*/application-(prod|production)\\.(json|y[a]?ml)$"),
            CreateRawRegex("^.*/appsettings\\.(Development|Production)\\.json$"),
            CreateRawRegex("^.*/pom.properties$"),
            CreateRawRegex("^.*\\.env;.*$"),
            CreateRawRegex("^.*\\.env[~]?$"),
            CreateRawRegex("^.*\\.env\\.[a-z]+?$"),
            CreateRawRegex("^.*\\.php\\.(backup|bak|old|save|swap|swp|txt)$"),
            CreateRawRegex("^.*\\.php~$"),
            CreateRawRegex("^.*\\.php$"),
            CreateRawRegex("^.*\\.sql$"),
            CreateRawRegex("^.*\\debug.log$"),
            CreateRawRegex("^.*backup\\.(gz|sql|tar\\.gz|zip)$"),
            CreateRawRegex("^.*config\\.(go|ini|json|properties|py|rb|xml|y[a]?ml)$"),
            CreateRawRegex("^.*phpinfo$"),
            CreateRawRegex("^.*prodtest$"),
            CreateRawRegex("^/_next/.*$"),
            CreateRawRegex("^/_profiler/.*$"),
            CreateRawRegex("^/\\.git.*$"),
            CreateRawRegex("^/\\.vscode/.*$"),
            CreateRawRegex("^/config/(local|production)\\.json$"),
            CreateRawRegex("^/console(?:/.*)?$"),
            CreateRawRegex("^/lander/.*$"),
            CreateRawRegex("^/logs/[a-z]+\\.log$"),
            CreateRawRegex("^/static/style/[^/]*/index.js$"),
            CreateRawRegex("^/storage/logs/.*\\.log$"),
            CreateRawRegex("^/var/log/.*$"),
            CreateRawRegex("^/wp-(content|json)/.*$"),
        ];

        private static readonly Regex[] ForbiddenQueryPatterns =
        [
            CreateRawRegex("(?:^|&)XDEBUG_SESSION_START=phpstorm(?:&|$)"),
            CreateRawRegex("(?:^|&)rest_route=/wp/v2/users/?(?:&|$)"),
        ];

        private readonly IMemoryCache memoryCache = memoryCache ??
            throw new ArgumentNullException(nameof(memoryCache));

        public override async Task InvokeAsync(HttpContext context)
        {
            string clientIpAddress = GetClientIpAddress(context);

            if (IsIpAddressBanned(clientIpAddress))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;

                return;
            }

            if (await ShouldBanRequestAsync(context.Request))
            {
                BanIpAddress(clientIpAddress);
                context.Response.StatusCode = StatusCodes.Status403Forbidden;

                return;
            }

            await Next(context);
        }

        private bool IsIpAddressBanned(string clientIpAddress)
            => !string.IsNullOrWhiteSpace(clientIpAddress) &&
               memoryCache.TryGetValue(GetBannedIpAddressCacheKey(clientIpAddress), out bool _);

        private async Task<bool> ShouldBanRequestAsync(HttpRequest request)
        {
            string path = UrlDecode(request.Path.ToString());

            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            string fromHeader = TryGetHeaderValue(request, "From");

            if (!string.IsNullOrWhiteSpace(fromHeader) &&
                ForbiddenFromHeaders.Contains(fromHeader, StringComparer.OrdinalIgnoreCase))
            {
                return true;
            }

            foreach (Regex forbiddenResourcePattern in ForbiddenResourcePatterns)
            {
                if (forbiddenResourcePattern.IsMatch(path))
                {
                    return true;
                }
            }

            string queryString = request.QueryString.ToString().TrimStart('?');

            if (!string.IsNullOrWhiteSpace(queryString))
            {
                foreach (Regex forbiddenQueryPattern in ForbiddenQueryPatterns)
                {
                    if (forbiddenQueryPattern.IsMatch(queryString))
                    {
                        return true;
                    }
                }
            }

            if (path.Equals("/", StringComparison.OrdinalIgnoreCase))
            {
                if (!SafeVerbs.Contains(request.Method, StringComparer.OrdinalIgnoreCase))
                {
                    return true;
                }

                string body = await ReadRequestBodyAsStringAsync(request);

                if (string.IsNullOrWhiteSpace(queryString) &&
                    string.IsNullOrWhiteSpace(body))
                {
                    return true;
                }
            }

            string userAgent = TryGetHeaderValue(request, "User-Agent");

            if (!string.IsNullOrWhiteSpace(userAgent) &&
                ForbiddenUserAgentKeywords.Any(keyword => userAgent.Contains(keyword, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            string clientHints = TryGetHeaderValue(request, "sec-ch-ua");

            if (!string.IsNullOrWhiteSpace(clientHints) &&
                ForbiddenClientHintsKeywords.Any(keyword => clientHints.Contains(keyword, StringComparison.OrdinalIgnoreCase)))
            {
                return true;
            }

            return false;
        }

        private static async Task<string> ReadRequestBodyAsStringAsync(HttpRequest request)
        {
            if (request.Body is null)
            {
                return null;
            }

            if (request.ContentLength == 0)
            {
                return null;
            }

            request.EnableBuffering();
            request.Body.Position = 0;

            using StreamReader reader = new(
                request.Body,
                Encoding.UTF8,
                detectEncodingFromByteOrderMarks: true,
                bufferSize: 1024,
                leaveOpen: true);

            string body = await reader.ReadToEndAsync();
            request.Body.Position = 0;

            return body;
        }

        private void BanIpAddress(string clientIpAddress)
        {
            if (string.IsNullOrWhiteSpace(clientIpAddress))
            {
                return;
            }

            memoryCache.Set(
                GetBannedIpAddressCacheKey(clientIpAddress),
                true,
                BanDuration);
        }

        private static string GetBannedIpAddressCacheKey(string clientIpAddress)
            => $"nuciapi.middleware.banned-ip:{clientIpAddress}";

        private static Regex CreateExactPathRegex(string path)
            => CreateRawRegex($"^{Regex.Escape(path)}$");

        private static Regex CreateRawRegex(string pattern)
            => new(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled, TimeSpan.FromSeconds(1));
    }
}