using System;
using System.IO;
using System.Linq;
using System.Xml.Linq;
using NUnit.Framework;

namespace NuciAPI.Middleware.Security.ArchitectureTests
{
    [TestFixture]
    public sealed class ProjectConventionTests
    {
        private static readonly string RepositoryRoot = Path.GetFullPath(Path.Combine(
            typeof(ProjectConventionTests).Assembly.Location,
            "..", "..", "..", "..", ".."));

        private static readonly string ProductionProjectPath = Path.Combine(
            RepositoryRoot, "NuciAPI.Middleware.Security", "NuciAPI.Middleware.Security.csproj");

        private static readonly string TestProjectPath = Path.Combine(
            RepositoryRoot, "NuciAPI.Middleware.Security.ArchitectureTests",
            "NuciAPI.Middleware.Security.ArchitectureTests.csproj");

        [Test]
        public void ProductionProject_ShouldTargetNet10()
        {
            XElement project = LoadProject(ProductionProjectPath);

            Assert.That(GetProperty(project, "TargetFramework"), Is.EqualTo("net10.0"));
        }

        [Test]
        public void ProductionProject_ShouldDisableImplicitUsings()
        {
            XElement project = LoadProject(ProductionProjectPath);

            Assert.That(GetProperty(project, "ImplicitUsings"), Is.EqualTo("disable"));
        }

        [Test]
        public void ProductionProject_ShouldDeclareRequiredFrameworkReference()
        {
            XElement project = LoadProject(ProductionProjectPath);
            string[] frameworkReferences = project.Descendants("FrameworkReference")
                .Select(element => (string)element.Attribute("Include"))
                .Where(include => include is not null)
                .OrderBy(include => include, StringComparer.Ordinal)
                .ToArray();

            Assert.That(frameworkReferences, Does.Contain("Microsoft.AspNetCore.App"));
        }

        [Test]
        public void ProductionProject_ShouldReferenceRequiredPackages()
        {
            XElement project = LoadProject(ProductionProjectPath);
            string[] packages = project.Descendants("PackageReference")
                .Select(element => (string)element.Attribute("Include"))
                .Where(include => include is not null)
                .OrderBy(include => include, StringComparer.Ordinal)
                .ToArray();

            Assert.That(packages, Does.Contain("NuciAPI.Middleware"));
            Assert.That(packages, Does.Contain("NuciWeb.HTTP"));
        }

        [Test]
        public void ArchitectureTestProject_ShouldBeExplicitlyMarkedAsTestProject()
        {
            XElement project = LoadProject(TestProjectPath);

            Assert.That(GetProperty(project, "IsTestProject"), Is.EqualTo("true"));
            Assert.That(GetProperty(project, "ExcludeFromCodeCoverage"), Is.EqualTo("true"));
            Assert.That(GetProperty(project, "ImplicitUsings"), Is.EqualTo("disable"));
        }

        [Test]
        public void ArchitectureTestProject_ShouldReferenceProductionProject()
        {
            XElement project = LoadProject(TestProjectPath);
            string[] references = project.Descendants("ProjectReference")
                .Select(element => (string)element.Attribute("Include"))
                .Where(include => include is not null)
                .ToArray();

            Assert.That(references, Has.Some.EqualTo("..\\NuciAPI.Middleware.Security\\NuciAPI.Middleware.Security.csproj"));
        }

        [Test]
        public void ArchitectureTestProject_ShouldReferenceRequiredTestingPackages()
        {
            XElement project = LoadProject(TestProjectPath);
            string[] packages = project.Descendants("PackageReference")
                .Select(element => (string)element.Attribute("Include"))
                .Where(include => include is not null)
                .ToArray();

            Assert.That(packages, Does.Contain("NUnit"));
            Assert.That(packages, Does.Contain("TngTech.ArchUnitNET"));
            Assert.That(packages, Does.Contain("TngTech.ArchUnitNET.NUnit"));
            Assert.That(packages, Does.Contain("Microsoft.CodeAnalysis.CSharp"));
        }

        private static XElement LoadProject(string path)
        {
            Assert.That(File.Exists(path), Is.True, $"Required project file was not found: {path}");
            return XDocument.Load(path).Root!;
        }

        private static string GetProperty(XElement project, string propertyName)
        {
            XElement? property = project.Descendants(propertyName).FirstOrDefault();
            Assert.That(property, Is.Not.Null, $"Required project property was not found: {propertyName}");
            return property!.Value;
        }
    }
}
