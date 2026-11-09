using System.Reflection;
using ArchUnitNET.Domain;
using ArchUnitNET.Fluent;
using ArchUnitNET.Fluent.Slices;
using ArchUnitNET.Fluent.Syntax.Elements.Types;
using ArchUnitNET.Loader;
using ArchUnitNET.NUnit;
using NUnit.Framework;
using static ArchUnitNET.Fluent.ArchRuleDefinition;
using static ArchUnitNET.Fluent.Slices.SliceRuleDefinition;

namespace NuciAPI.Middleware.Security.ArchitectureTests
{
    [TestFixture]
    public sealed class DependencyTests
    {
        private static readonly Architecture Architecture = new ArchLoader()
            .LoadAssemblies(typeof(NuciApiMiddlewareSecurityExtensions).Assembly)
            .Build();

        [Test]
        public void ProductionCode_ShouldNotReferenceTestAssemblies()
        {
            var rule = Types(true)
                .That().ResideInNamespace("NuciAPI.Middleware.Security")
                .Should().NotDependOnAny(Types(true).That().ResideInAssembly(typeof(DependencyTests).Assembly));

            rule.Check(Architecture);
        }

        [Test]
        public void ProductionCode_ShouldNotHaveInternalsVisibleTo()
        {
            System.Reflection.Assembly productionAssembly = typeof(NuciApiMiddlewareSecurityExtensions).Assembly;
            object[] attributes = productionAssembly.GetCustomAttributes(typeof(System.Runtime.CompilerServices.InternalsVisibleToAttribute), false);

            Assert.That(attributes, Is.Empty, "Production assembly must not declare InternalsVisibleTo");
        }

        [Test]
        public void MiddlewareClasses_ShouldBeInternal()
        {
            IArchRule rule = Types(true)
                .That().ResideInNamespace("NuciAPI.Middleware.Security")
                .And().HaveNameEndingWith("Middleware")
                .Should().BeInternal();

            rule.Check(Architecture);
        }

        [Test]
        public void ExceptionClasses_ShouldBePublic()
        {
            IArchRule rule = Types(true)
                .That().ResideInNamespace("NuciAPI.Middleware.Security")
                .And().HaveNameEndingWith("Exception")
                .Should().BePublic();

            rule.Check(Architecture);
        }

        [Test]
        public void ExtensionClasses_ShouldBePublic()
        {
            IArchRule rule = Types(true)
                .That().ResideInNamespace("NuciAPI.Middleware.Security")
                .And().HaveNameEndingWith("Extensions")
                .Should().BePublic();

            rule.Check(Architecture);
        }

        [Test]
        public void MiddlewareClasses_ShouldInheritFromNuciApiMiddleware()
        {
            IArchRule rule = Types(true)
                .That().ResideInNamespace("NuciAPI.Middleware.Security")
                .And().HaveNameEndingWith("Middleware")
                .Should().BeAssignableTo(typeof(NuciAPI.Middleware.NuciApiMiddleware));

            rule.Check(Architecture);
        }

        [Test]
        public void NoCyclesInProductionCode()
        {
            IArchRule rule = Slices()
                .Matching("NuciAPI.Middleware.Security.(**)")
                .Should().BeFreeOfCycles();

            rule.Check(Architecture);
        }
    }
}