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
        [TestCase("/_environment")]
        [TestCase("/_next/static/env.js")]
        [TestCase("/_phpinfo.php")]
        [TestCase("/_profiler")]
        [TestCase("/_profiler/phpinfo")]
        [TestCase("/.%65%6Ev")]
        [TestCase("/.%67%69%74/%63%6F%6E%66%69%67")]
        [TestCase("/.aws/config")]
        [TestCase("/.aws/credentials")]
        [TestCase("/.boto")]
        [TestCase("/.composer/auth.json")]
        [TestCase("/.docker/config.json")]
        [TestCase("/.env;.css")]
        [TestCase("/.env;.jpg")]
        [TestCase("/.env::$DATA")]
        [TestCase("/.env.backup")]
        [TestCase("/.env.bak")]
        [TestCase("/.env.ci")]
        [TestCase("/.env.dev")]
        [TestCase("/.env.development")]
        [TestCase("/.env.dist")]
        [TestCase("/.env.docker")]
        [TestCase("/.env.example")]
        [TestCase("/.env.live")]
        [TestCase("/.env.local")]
        [TestCase("/.env.old")]
        [TestCase("/.env.preprod")]
        [TestCase("/.env.prod")]
        [TestCase("/.env.production")]
        [TestCase("/.env.py")]
        [TestCase("/.env.remote")]
        [TestCase("/.env.sample")]
        [TestCase("/.env.save")]
        [TestCase("/.env.stage")]
        [TestCase("/.env.staging")]
        [TestCase("/.env.swp")]
        [TestCase("/.env.test")]
        [TestCase("/.env.uat")]
        [TestCase("/.env")]
        [TestCase("/.env~")]
        [TestCase("/.git-credentials")]
        [TestCase("/.git/config")]
        [TestCase("/.git/HEAD")]
        [TestCase("/.git/index")]
        [TestCase("/.gitconfig")]
        [TestCase("/.github/workflows/main.yml")]
        [TestCase("/.gitlab-ci.yml")]
        [TestCase("/.htpasswd")]
        [TestCase("/.netrc")]
        [TestCase("/.npmrc")]
        [TestCase("/.pgpass")]
        [TestCase("/.pypirc")]
        [TestCase("/.vercel/.env.production.local")]
        [TestCase("/.vscode/launch.json")]
        [TestCase("/.vscode/settings.json")]
        [TestCase("/%77%70%2D%63%6F%6E%66%69%67.%70%68%70.%62%61%6B")]
        [TestCase("/actuator/beans")]
        [TestCase("/actuator/configprops")]
        [TestCase("/actuator/env")]
        [TestCase("/actuator/heapdump")]
        [TestCase("/admin/.env")]
        [TestCase("/admin/config.php")]
        [TestCase("/admin/phpinfo.php")]
        [TestCase("/administrator/.env")]
        [TestCase("/api-keys.txt")]
        [TestCase("/api/.env")]
        [TestCase("/api/v1/.env")]
        [TestCase("/api/v2/.env")]
        [TestCase("/apis/.env")]
        [TestCase("/app_dev.php/_profiler/phpinfo")]
        [TestCase("/app/.env")]
        [TestCase("/app/etc/env.php")]
        [TestCase("/app/etc/local.xml")]
        [TestCase("/application-prod.yml")]
        [TestCase("/application-production.yml")]
        [TestCase("/application.properties")]
        [TestCase("/application.yml")]
        [TestCase("/apps/.env")]
        [TestCase("/appsettings.Development.json")]
        [TestCase("/appsettings.json")]
        [TestCase("/appsettings.Production.json")]
        [TestCase("/assets/.env")]
        [TestCase("/assets/js/auth.js")]
        [TestCase("/assets/js/message.js")]
        [TestCase("/assets/js/qr_modal.js")]
        [TestCase("/backend/.env")]
        [TestCase("/backup.sql")]
        [TestCase("/backup/.env")]
        [TestCase("/backup/wp-config.php")]
        [TestCase("/backups/.env")]
        [TestCase("/bot-connect.js")]
        [TestCase("/brevo/.env")]
        [TestCase("/build/.env")]
        [TestCase("/bulk/.env")]
        [TestCase("/campaign/.env")]
        [TestCase("/client/.env")]
        [TestCase("/cms/.env")]
        [TestCase("/config.json")]
        [TestCase("/config.php.bak")]
        [TestCase("/config.php.old")]
        [TestCase("/config.php")]
        [TestCase("/config.py")]
        [TestCase("/config.rb")]
        [TestCase("/config.yaml")]
        [TestCase("/config.yml")]
        [TestCase("/config/.env")]
        [TestCase("/config/database.js")]
        [TestCase("/config/database.php::$DATA")]
        [TestCase("/config/database.php")]
        [TestCase("/config/database.yml")]
        [TestCase("/config/default.json")]
        [TestCase("/config/local.json")]
        [TestCase("/config/mail.php")]
        [TestCase("/config/production.json")]
        [TestCase("/config/secrets.yml")]
        [TestCase("/config/server.js")]
        [TestCase("/config/services.php::$DATA")]
        [TestCase("/config/services.php")]
        [TestCase("/config/settings.inc.php")]
        [TestCase("/configuration.php.bak")]
        [TestCase("/configuration.php.old")]
        [TestCase("/configuration.php")]
        [TestCase("/configuration.php~")]
        [TestCase("/connectionstrings.config")]
        [TestCase("/core/.env")]
        [TestCase("/core/app/.env")]
        [TestCase("/core/Database/.env")]
        [TestCase("/cpanel/phpinfo.php")]
        [TestCase("/credentials.json")]
        [TestCase("/crm/.env")]
        [TestCase("/cron/.env")]
        [TestCase("/cronlab/.env")]
        [TestCase("/css/support_parent.css")]
        [TestCase("/current/.env")]
        [TestCase("/dashboard/.env")]
        [TestCase("/database.sql")]
        [TestCase("/database.yml")]
        [TestCase("/database/.env")]
        [TestCase("/db.sql")]
        [TestCase("/debug.php")]
        [TestCase("/debug/default/view")]
        [TestCase("/deploy/.env")]
        [TestCase("/dev/.env")]
        [TestCase("/dev/phpinfo.php")]
        [TestCase("/dist/.env")]
        [TestCase("/docker-compose.yaml")]
        [TestCase("/docker-compose.yml")]
        [TestCase("/drupal/.env")]
        [TestCase("/dump.sql")]
        [TestCase("/ecosystem.config.js")]
        [TestCase("/email/.env")]
        [TestCase("/en/.env")]
        [TestCase("/env")]
        [TestCase("/erp/.env")]
        [TestCase("/error_log")]
        [TestCase("/error.log")]
        [TestCase("/exapi/.env")]
        [TestCase("/express/.env")]
        [TestCase("/frontend/.env")]
        [TestCase("/gateway/.env")]
        [TestCase("/graphql/.env")]
        [TestCase("/hosting/phpinfo.php")]
        [TestCase("/htdocs/.env")]
        [TestCase("/html/.env")]
        [TestCase("/i.php")]
        [TestCase("/icons/ubuntu-logo.png")]
        [TestCase("/info.php")]
        [TestCase("/info")]
        [TestCase("/internal/.env")]
        [TestCase("/joomla/.env")]
        [TestCase("/js/config.js")]
        [TestCase("/js/lkk_ch.js")]
        [TestCase("/js/twint_ch.js")]
        [TestCase("/lab/.env")]
        [TestCase("/laravel/.env")]
        [TestCase("/lib/.env")]
        [TestCase("/live/.env")]
        [TestCase("/local_settings.py")]
        [TestCase("/logs/app.log")]
        [TestCase("/logs/error.log")]
        [TestCase("/magento/.env")]
        [TestCase("/mail/.env")]
        [TestCase("/mail/phpinfo.php")]
        [TestCase("/mailer/.env")]
        [TestCase("/mailgun/.env")]
        [TestCase("/mailing/.env")]
        [TestCase("/mailjet/.env")]
        [TestCase("/mandrill/.env")]
        [TestCase("/microservice/.env")]
        [TestCase("/nest/.env")]
        [TestCase("/newsletter/.env")]
        [TestCase("/next/.env")]
        [TestCase("/node/.env")]
        [TestCase("/notifications/.env")]
        [TestCase("/notify/.env")]
        [TestCase("/nuxt/.env")]
        [TestCase("/old_phpinfo.php")]
        [TestCase("/old/.env")]
        [TestCase("/old/phpinfo.php")]
        [TestCase("/p.php")]
        [TestCase("/package.json")]
        [TestCase("/panel/.env")]
        [TestCase("/php_info")]
        [TestCase("/php-info.php")]
        [TestCase("/php.php")]
        [TestCase("/phpinfo.php")]
        [TestCase("/phpinfo")]
        [TestCase("/phptest.php")]
        [TestCase("/phpversion.php")]
        [TestCase("/pi.php")]
        [TestCase("/pinfo.php")]
        [TestCase("/portal/.env")]
        [TestCase("/postmark/.env")]
        [TestCase("/prestashop/.env")]
        [TestCase("/private/.env")]
        [TestCase("/probe.php")]
        [TestCase("/prod/.env")]
        [TestCase("/project/.env")]
        [TestCase("/psnlink/.env")]
        [TestCase("/public_html/.env")]
        [TestCase("/public/.env")]
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
        [TestCase("/server-info.php")]
        [TestCase("/server-status.php")]
        [TestCase("/server/.env")]
        [TestCase("/serverless.yml")]
        [TestCase("/service/.env")]
        [TestCase("/ses/.env")]
        [TestCase("/settings.php")]
        [TestCase("/settings.py")]
        [TestCase("/shared/.env")]
        [TestCase("/shop/.env")]
        [TestCase("/shopify/.env")]
        [TestCase("/site/.env")]
        [TestCase("/sitemap.xml")]
        [TestCase("/sitemaps/.env")]
        [TestCase("/sites/default/settings.php.bak")]
        [TestCase("/sites/default/settings.php")]
        [TestCase("/smtp/.env")]
        [TestCase("/smtp/phpinfo.php")]
        [TestCase("/sparkpost/.env")]
        [TestCase("/src/.env")]
        [TestCase("/staging/.env")]
        [TestCase("/static/style/protect/index.js")]
        [TestCase("/static/style/sys_files/index.js")]
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
        [TestCase("/var/log/system.log")]
        [TestCase("/vendor/.env")]
        [TestCase("/web.config")]
        [TestCase("/web/.env")]
        [TestCase("/webmail/phpinfo.php")]
        [TestCase("/webroot/index.php/_environment")]
        [TestCase("/wordpress/.env")]
        [TestCase("/wp-config-backup.php")]
        [TestCase("/wp-config.php::$DATA")]
        [TestCase("/wp-config.php.bak")]
        [TestCase("/wp-config.php.old")]
        [TestCase("/wp-config.php.save")]
        [TestCase("/wp-config.php.swp")]
        [TestCase("/wp-config.php.txt")]
        [TestCase("/wp-config.php")]
        [TestCase("/wp-config.php~")]
        [TestCase("/wp-content/debug.log")]
        [TestCase("/wp-json/")]
        [TestCase("/wp-json/gravitysmtp/v1/tests/mock-data")]
        [TestCase("/wp-login.php")]
        [TestCase("/wp/.env")]
        [TestCase("/www/.env")]
        [TestCase("/xmlrpc.php")]
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