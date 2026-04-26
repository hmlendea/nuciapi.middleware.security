using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace NuciAPI.Middleware.Security
{
    public static class NuciApiMiddlewareSecurityExtensions
    {
        public static IServiceCollection AddNuciApiScannerProtection(
            this IServiceCollection services)
        {
            services.AddMemoryCache();

            return services;
        }

        public static IServiceCollection AddNuciApiReplayProtection(
            this IServiceCollection services)
        {
            services.AddMemoryCache();

            return services;
        }

        public static IApplicationBuilder UseNuciApiHeaderValidation(
            this IApplicationBuilder app)
            => app.UseMiddleware<HeaderValidationMiddleware>();

        public static IApplicationBuilder UseNuciApiScannerProtection(
            this IApplicationBuilder app)
            => app.UseMiddleware<ScannerProtectionMiddleware>();

        public static IApplicationBuilder UseNuciApiReplayProtection(
            this IApplicationBuilder app)
            => app.UseMiddleware<ReplayProtectionMiddleware>();
    }
}