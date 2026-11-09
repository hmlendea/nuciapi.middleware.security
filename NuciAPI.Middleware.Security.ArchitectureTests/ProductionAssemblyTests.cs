using System;
using System.Linq;
using System.Reflection;
using NUnit.Framework;

namespace NuciAPI.Middleware.Security.ArchitectureTests
{
    [TestFixture]
    public sealed class ProductionAssemblyTests
    {
        private static readonly Assembly ProductionAssembly = typeof(NuciApiMiddlewareSecurityExtensions).Assembly;

        [Test]
        public void ProductionAssembly_ShouldContainExpectedMiddlewareTypes()
        {
            string[] expectedTypes =
            {
                "NuciAPI.Middleware.Security.HeaderValidationMiddleware",
                "NuciAPI.Middleware.Security.ReplayProtectionMiddleware",
                "NuciAPI.Middleware.Security.ScannerProtectionMiddleware"
            };

            string[] actualTypes = ProductionAssembly.GetTypes()
                .Where(type => type.Namespace == "NuciAPI.Middleware.Security")
                .Select(type => type.FullName!)
                .Where(name => name.EndsWith("Middleware", StringComparison.Ordinal))
                .OrderBy(name => name, StringComparer.Ordinal)
                .ToArray();

            Assert.That(actualTypes, Is.EqualTo(expectedTypes.OrderBy(name => name, StringComparer.Ordinal).ToArray()));
        }

        [Test]
        public void ProductionAssembly_ShouldContainPublicExtensionType()
        {
            Type? extensionType = ProductionAssembly.GetType(
                "NuciAPI.Middleware.Security.NuciApiMiddlewareSecurityExtensions");

            Assert.That(extensionType, Is.Not.Null);
            Assert.That(extensionType!.IsPublic, Is.True);
            Assert.That(extensionType.IsAbstract, Is.True);
            Assert.That(extensionType.IsSealed, Is.True);
        }

        [Test]
        public void ProductionAssembly_ShouldContainPublicRequestAlreadyProcessedException()
        {
            Type? exceptionType = ProductionAssembly.GetType(
                "NuciAPI.Middleware.Security.RequestAlreadyProcessedException");

            Assert.That(exceptionType, Is.Not.Null);
            Assert.That(exceptionType!.IsPublic, Is.True);
            Assert.That(exceptionType.IsSubclassOf(typeof(Exception)), Is.True);
        }

        [Test]
        public void MiddlewareTypes_ShouldBeNonPublicSealedClasses()
        {
            Type[] middlewareTypes = ProductionAssembly.GetTypes()
                .Where(type => type.Namespace == "NuciAPI.Middleware.Security")
                .Where(type => type.Name.EndsWith("Middleware", StringComparison.Ordinal))
                .ToArray();

            Assert.That(middlewareTypes, Is.Not.Empty);

            foreach (Type middlewareType in middlewareTypes)
            {
                Assert.That(middlewareType.IsClass, Is.True, middlewareType.FullName);
                Assert.That(middlewareType.IsNotPublic, Is.True, middlewareType.FullName);
                Assert.That(middlewareType.IsSealed, Is.True, middlewareType.FullName);
            }
        }

        [Test]
        public void MiddlewareTypes_ShouldInheritFromNuciApiMiddleware()
        {
            Type middlewareBaseType = typeof(NuciAPI.Middleware.NuciApiMiddleware);
            Type[] middlewareTypes = ProductionAssembly.GetTypes()
                .Where(type => type.Namespace == "NuciAPI.Middleware.Security")
                .Where(type => type.Name.EndsWith("Middleware", StringComparison.Ordinal))
                .ToArray();

            Assert.That(middlewareTypes, Is.Not.Empty);

            foreach (Type middlewareType in middlewareTypes)
            {
                Assert.That(middlewareBaseType.IsAssignableFrom(middlewareType), Is.True, middlewareType.FullName);
            }
        }
    }
}
