using System.IO;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using NUnit.Framework;

namespace NuciAPI.Middleware.Security.UnitTests
{
    [TestFixture]
    public sealed class ScannerProtectionMiddlewareTests
    {
        [Test]
        [TestCase("/.%65%6Ev")]
        [TestCase("/.%67%69%74/%63%6F%6E%66%69%67")]
        [TestCase("/%77%70%2D%63%6F%6E%66%69%67.%70%68%70.%62%61%6B")]
        [TestCase("/actuator/beans")]
        [TestCase("/actuator/configprops")]
        [TestCase("/actuator/env")]
        [TestCase("/admin/config.php")]
        [TestCase("/admin/.env")]
        [TestCase("/administrator/.env")]
        [TestCase("/admin/phpinfo.php")]
        [TestCase("/api/.env")]
        [TestCase("/api/v1/.env")]
        [TestCase("/api/v2/.env")]
        [TestCase("/app/.env")]
        [TestCase("/app/etc/env.php")]
        [TestCase("/app/etc/local.xml")]
        [TestCase("/application.properties")]
        [TestCase("/application.yml")]
        [TestCase("/apps/.env")]
        [TestCase("/appsettings.Development.json")]
        [TestCase("/appsettings.json")]
        [TestCase("/appsettings.Production.json")]
        [TestCase("/assets/.env")]
        [TestCase("/.aws/config")]
        [TestCase("/.aws/credentials")]
        [TestCase("/backend/.env")]
        [TestCase("/backup/.env")]
        [TestCase("/backups/.env")]
        [TestCase("/backup/wp-config.php")]
        [TestCase("/.boto")]
        [TestCase("/brevo/.env")]
        [TestCase("/build/.env")]
        [TestCase("/bulk/.env")]
        [TestCase("/campaign/.env")]
        [TestCase("/client/.env")]
        [TestCase("/cms/.env")]
        [TestCase("/.composer/auth.json")]
        [TestCase("/config/database.js")]
        [TestCase("/config/database.php")]
        [TestCase("/config/database.php::$DATA")]
        [TestCase("/config/database.yml")]
        [TestCase("/config/default.json")]
        [TestCase("/config/.env")]
        [TestCase("/config.json")]
        [TestCase("/config/mail.php")]
        [TestCase("/config.php.bak")]
        [TestCase("/config.php.old")]
        [TestCase("/config/secrets.yml")]
        [TestCase("/config/server.js")]
        [TestCase("/config/services.php")]
        [TestCase("/config/services.php::$DATA")]
        [TestCase("/config/settings.inc.php")]
        [TestCase("/configuration.php~")]
        [TestCase("/configuration.php.bak")]
        [TestCase("/configuration.php.old")]
        [TestCase("/connectionstrings.config")]
        [TestCase("/core/app/.env")]
        [TestCase("/core/Database/.env")]
        [TestCase("/core/.env")]
        [TestCase("/cpanel/phpinfo.php")]
        [TestCase("/credentials.json")]
        [TestCase("/crm/.env")]
        [TestCase("/cron/.env")]
        [TestCase("/cronlab/.env")]
        [TestCase("/current/.env")]
        [TestCase("/dashboard/.env")]
        [TestCase("/database/.env")]
        [TestCase("/debug.php")]
        [TestCase("/deploy/.env")]
        [TestCase("/dev/.env")]
        [TestCase("/dev/phpinfo.php")]
        [TestCase("/dist/.env")]
        [TestCase("/.docker/config.json")]
        [TestCase("/drupal/.env")]
        [TestCase("/ecosystem.config.js")]
        [TestCase("/email/.env")]
        [TestCase("/en/.env")]
        [TestCase("/.env")]
        [TestCase("/.env~")]
        [TestCase("/env")]
        [TestCase("/.env::$DATA")]
        [TestCase("/.env.backup")]
        [TestCase("/.env.bak")]
        [TestCase("/.env.ci")]
        [TestCase("/.env;.css")]
        [TestCase("/.env.dev")]
        [TestCase("/.env.development")]
        [TestCase("/.env.dist")]
        [TestCase("/.env.docker")]
        [TestCase("/.env.example")]
        [TestCase("/_environment")]
        [TestCase("/.env;.jpg")]
        [TestCase("/.env.live")]
        [TestCase("/.env.local")]
        [TestCase("/.env.old")]
        [TestCase("/.env.preprod")]
        [TestCase("/.env.prod")]
        [TestCase("/.env.production")]
        [TestCase("/.env.remote")]
        [TestCase("/.env.sample")]
        [TestCase("/.env.save")]
        [TestCase("/.env.stage")]
        [TestCase("/.env.staging")]
        [TestCase("/.env.swp")]
        [TestCase("/.env.test")]
        [TestCase("/.env.uat")]
        [TestCase("/erp/.env")]
        [TestCase("/error.log")]
        [TestCase("/exapi/.env")]
        [TestCase("/express/.env")]
        [TestCase("/frontend/.env")]
        [TestCase("/gateway/.env")]
        [TestCase("/.git/config")]
        [TestCase("/.git-credentials")]
        [TestCase("/.git/HEAD")]
        [TestCase("/graphql/.env")]
        [TestCase("/hosting/phpinfo.php")]
        [TestCase("/htdocs/.env")]
        [TestCase("/html/.env")]
        [TestCase("/.htpasswd")]
        [TestCase("/info.php")]
        [TestCase("/internal/.env")]
        [TestCase("/i.php")]
        [TestCase("/joomla/.env")]
        [TestCase("/lab/.env")]
        [TestCase("/laravel/.env")]
        [TestCase("/lib/.env")]
        [TestCase("/live/.env")]
        [TestCase("/magento/.env")]
        [TestCase("/mail/.env")]
        [TestCase("/mailer/.env")]
        [TestCase("/mailgun/.env")]
        [TestCase("/mailing/.env")]
        [TestCase("/mailjet/.env")]
        [TestCase("/mail/phpinfo.php")]
        [TestCase("/mandrill/.env")]
        [TestCase("/microservice/.env")]
        [TestCase("/nest/.env")]
        [TestCase("/newsletter/.env")]
        [TestCase("/next/.env")]
        [TestCase("/node/.env")]
        [TestCase("/notifications/.env")]
        [TestCase("/notify/.env")]
        [TestCase("/nuxt/.env")]
        [TestCase("/old/.env")]
        [TestCase("/old/phpinfo.php")]
        [TestCase("/old_phpinfo.php")]
        [TestCase("/panel/.env")]
        [TestCase("/phpinfo")]
        [TestCase("/_phpinfo.php")]
        [TestCase("/php-info.php")]
        [TestCase("/phpinfo.php")]
        [TestCase("/php.php")]
        [TestCase("/phptest.php")]
        [TestCase("/phpversion.php")]
        [TestCase("/pinfo.php")]
        [TestCase("/pi.php")]
        [TestCase("/portal/.env")]
        [TestCase("/postmark/.env")]
        [TestCase("/p.php")]
        [TestCase("/prestashop/.env")]
        [TestCase("/private/.env")]
        [TestCase("/probe.php")]
        [TestCase("/prod/.env")]
        [TestCase("/_profiler/phpinfo")]
        [TestCase("/project/.env")]
        [TestCase("/psnlink/.env")]
        [TestCase("/public/.env")]
        [TestCase("/public_html/.env")]
        [TestCase("/public/phpinfo.php")]
        [TestCase("/release/.env")]
        [TestCase("/releases/.env")]
        [TestCase("/resources/.env")]
        [TestCase("/rest/.env")]
        [TestCase("/robots.txt")]
        [TestCase("/saas/.env")]
        [TestCase("/scripts/.env")]
        [TestCase("/secrets.json")]
        [TestCase("/secrets.yml")]
        [TestCase("/sender/.env")]
        [TestCase("/sendgrid/.env")]
        [TestCase("/server/.env")]
        [TestCase("/server-info.php")]
        [TestCase("/serverless.yml")]
        [TestCase("/server-status.php")]
        [TestCase("/service/.env")]
        [TestCase("/ses/.env")]
        [TestCase("/shared/.env")]
        [TestCase("/shop/.env")]
        [TestCase("/shopify/.env")]
        [TestCase("/site/.env")]
        [TestCase("/sitemaps/.env")]
        [TestCase("/sites/default/settings.php")]
        [TestCase("/sites/default/settings.php.bak")]
        [TestCase("/smtp/.env")]
        [TestCase("/smtp/phpinfo.php")]
        [TestCase("/sparkpost/.env")]
        [TestCase("/src/.env")]
        [TestCase("/staging/.env")]
        [TestCase("/status.php")]
        [TestCase("/storage/.env")]
        [TestCase("/storage/logs/laravel.log")]
        [TestCase("/store/.env")]
        [TestCase("/symfony/.env")]
        [TestCase("/temp/.env")]
        [TestCase("/terraform.tfstate")]
        [TestCase("/terraform.tfvars")]
        [TestCase("/test.php")]
        [TestCase("/test/phpinfo.php")]
        [TestCase("/tmp/.env")]
        [TestCase("/tmp/phpinfo.php")]
        [TestCase("/tools/.env")]
        [TestCase("/transactional/.env")]
        [TestCase("/uploads/.env")]
        [TestCase("/v1/.env")]
        [TestCase("/v2/.env")]
        [TestCase("/v3/.env")]
        [TestCase("/vendor/.env")]
        [TestCase("/.vscode/launch.json")]
        [TestCase("/.vscode/settings.json")]
        [TestCase("/web.config")]
        [TestCase("/web/.env")]
        [TestCase("/webmail/phpinfo.php")]
        [TestCase("/webroot/index.php/_environment")]
        [TestCase("/wordpress/.env")]
        [TestCase("/wp-config-backup.php")]
        [TestCase("/wp-config.php~")]
        [TestCase("/wp-config.php::$DATA")]
        [TestCase("/wp-config.php.bak")]
        [TestCase("/wp-config.php.old")]
        [TestCase("/wp-config.php.save")]
        [TestCase("/wp-config.php.swp")]
        [TestCase("/wp-config.php.txt")]
        [TestCase("/wp-content/debug.log")]
        [TestCase("/wp/.env")]
        [TestCase("/wp-json/")]
        [TestCase("/www/.env")]
        public async Task Given_ForbiddenPath_When_InvokeAsync_Then_BansClientAndBlocksSubsequentRequest(
            string path)
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            ScannerProtectionMiddleware middleware = new(_ => Task.CompletedTask, memoryCache);

            DefaultHttpContext firstContext = CreateContext("198.51.100.10", path);

            await middleware.InvokeAsync(firstContext);

            Assert.That(firstContext.Response.StatusCode, Is.EqualTo(StatusCodes.Status403Forbidden));
        }

        [Test]
        public async Task Given_ForbiddenFromHeader_When_InvokeAsync_Then_BlocksRequest()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            ScannerProtectionMiddleware middleware = new(_ => Task.CompletedTask, memoryCache);
            DefaultHttpContext context = CreateContext("198.51.100.11", "/health");
            context.Request.Headers["From"] = "oai-searchbot(at)openai.com";

            await middleware.InvokeAsync(context);

            Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status403Forbidden));
        }

        [Test]
        public async Task Given_RootRequestWithUnsupportedVerb_When_InvokeAsync_Then_BlocksRequest()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            ScannerProtectionMiddleware middleware = new(_ => Task.CompletedTask, memoryCache);
            DefaultHttpContext context = CreateContext("198.51.100.12", "/", method: HttpMethods.Head);

            await middleware.InvokeAsync(context);

            Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status403Forbidden));
        }

        [Test]
        public async Task Given_RootRequestWithoutBodyOrQuery_When_InvokeAsync_Then_BlocksRequest()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            ScannerProtectionMiddleware middleware = new(_ => Task.CompletedTask, memoryCache);
            DefaultHttpContext context = CreateContext("198.51.100.13", "/", method: HttpMethods.Get);

            await middleware.InvokeAsync(context);

            Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status403Forbidden));
        }

        [Test]
        public async Task Given_RootPostRequestWithBody_When_InvokeAsync_Then_InvokesNextDelegate()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            bool wasInvoked = false;
            ScannerProtectionMiddleware middleware = new(_ =>
            {
                wasInvoked = true;
                return Task.CompletedTask;
            }, memoryCache);
            DefaultHttpContext context = CreateContext(
                "198.51.100.14",
                "/",
                method: HttpMethods.Post,
                body: "{\"ok\":true}");

            await middleware.InvokeAsync(context);

            Assert.Multiple(() =>
            {
                Assert.That(wasInvoked, Is.True);
                Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status200OK));
            });
        }

        [Test]
        public async Task Given_ForbiddenQueryPattern_When_InvokeAsync_Then_BlocksRequest()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            ScannerProtectionMiddleware middleware = new(_ => Task.CompletedTask, memoryCache);
            DefaultHttpContext context = CreateContext(
                "198.51.100.15",
                "/search",
                queryString: new QueryString("?XDEBUG_SESSION_START=phpstorm"));

            await middleware.InvokeAsync(context);

            Assert.That(context.Response.StatusCode, Is.EqualTo(StatusCodes.Status403Forbidden));
        }

        [Test]
        public void Given_NullMemoryCache_When_ConstructingMiddleware_Then_ThrowsArgumentNullException()
            => Assert.That(
                () => new ScannerProtectionMiddleware(_ => Task.CompletedTask, null!),
                Throws.ArgumentNullException);

        private static DefaultHttpContext CreateContext(
            string ipAddress,
            string path,
            string method = "GET",
            QueryString queryString = default,
            string? body = null)
        {
            DefaultHttpContext context = new();
            context.Request.Method = method;
            context.Request.Path = path;
            context.Request.QueryString = queryString;
            context.Request.Headers["X-Forwarded-For"] = ipAddress;

            if (body is not null)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(body);
                context.Request.Body = new MemoryStream(bytes);
                context.Request.ContentLength = bytes.Length;
            }

            return context;
        }
    }
}