using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using NUnit.Framework;

namespace NuciAPI.Middleware.Security.ArchitectureTests
{
    [TestFixture]
    public sealed class SourceFileConventionTests
    {
        private static readonly string ProductionProjectPath = Path.GetFullPath(Path.Combine(
            typeof(SourceFileConventionTests).Assembly.Location,
            "..", "..", "..", "..", "..", "NuciAPI.Middleware.Security"));

        [Test]
        public void ProductionFiles_ShouldHaveExactlyOneTypePerFile()
        {
            string[] csFiles = Directory.GetFiles(ProductionProjectPath, "*.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && !f.EndsWith(".g.cs"))
                .ToArray();

            Assert.That(csFiles, Is.Not.Empty, "No production C# files found");

            foreach (string file in csFiles)
            {
                string source = File.ReadAllText(file);
                SyntaxTree tree = CSharpSyntaxTree.ParseText(source);
                CompilationUnitSyntax root = tree.GetCompilationUnitRoot();

                var typeDeclarations = root.DescendantNodes()
                    .OfType<TypeDeclarationSyntax>()
                    .Where(t => !t.Modifiers.Any(m => m.IsKind(SyntaxKind.PartialKeyword)))
                    .ToArray();

                Assert.That(typeDeclarations.Length, Is.EqualTo(1),
                    $"File {file} must contain exactly one non-partial type declaration. Found: {typeDeclarations.Length}");
            }
        }

        [Test]
        public void ProductionFiles_FileNameMustMatchTypeName()
        {
            string[] csFiles = Directory.GetFiles(ProductionProjectPath, "*.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && !f.EndsWith(".g.cs"))
                .ToArray();

            Assert.That(csFiles, Is.Not.Empty, "No production C# files found");

            foreach (string file in csFiles)
            {
                string source = File.ReadAllText(file);
                SyntaxTree tree = CSharpSyntaxTree.ParseText(source);
                CompilationUnitSyntax root = tree.GetCompilationUnitRoot();

                var typeDeclarations = root.DescendantNodes()
                    .OfType<TypeDeclarationSyntax>()
                    .Where(t => !t.Modifiers.Any(m => m.IsKind(SyntaxKind.PartialKeyword)))
                    .ToArray();

                if (typeDeclarations.Length == 1)
                {
                    string expectedFileName = typeDeclarations[0].Identifier.Text + ".cs";
                    string actualFileName = Path.GetFileName(file);

                    Assert.That(actualFileName, Is.EqualTo(expectedFileName),
                        $"File name {actualFileName} must match type name {expectedFileName}");
                }
            }
        }

        [Test]
        public void ProductionFiles_ShouldUseBlockNamespaces()
        {
            string[] csFiles = Directory.GetFiles(ProductionProjectPath, "*.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && !f.EndsWith(".g.cs"))
                .ToArray();

            Assert.That(csFiles, Is.Not.Empty, "No production C# files found");

            foreach (string file in csFiles)
            {
                string source = File.ReadAllText(file);
                SyntaxTree tree = CSharpSyntaxTree.ParseText(source);
                CompilationUnitSyntax root = tree.GetCompilationUnitRoot();

                var namespaceDeclarations = root.Members
                    .OfType<NamespaceDeclarationSyntax>()
                    .ToArray();

                Assert.That(namespaceDeclarations.Length, Is.EqualTo(1),
                    $"File {file} must contain exactly one block namespace declaration");

                Assert.That(namespaceDeclarations[0].Name.ToString(), Does.StartWith("NuciAPI.Middleware.Security"),
                    $"Namespace in {file} must start with 'NuciAPI.Middleware.Security'");
            }
        }

        [Test]
        public void ProductionFiles_ShouldNotHaveFileScopedNamespaces()
        {
            string[] csFiles = Directory.GetFiles(ProductionProjectPath, "*.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && !f.EndsWith(".g.cs"))
                .ToArray();

            Assert.That(csFiles, Is.Not.Empty, "No production C# files found");

            foreach (string file in csFiles)
            {
                string source = File.ReadAllText(file);
                SyntaxTree tree = CSharpSyntaxTree.ParseText(source);
                CompilationUnitSyntax root = tree.GetCompilationUnitRoot();

                var fileScopedNamespaces = root.Members
                    .OfType<FileScopedNamespaceDeclarationSyntax>()
                    .ToArray();

                Assert.That(fileScopedNamespaces.Length, Is.EqualTo(0),
                    $"File {file} must not use file-scoped namespace syntax");
            }
        }

        [Test]
        public void ProductionFiles_ShouldNotHaveRegions()
        {
            string[] csFiles = Directory.GetFiles(ProductionProjectPath, "*.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && !f.EndsWith(".g.cs"))
                .ToArray();

            Assert.That(csFiles, Is.Not.Empty, "No production C# files found");

            foreach (string file in csFiles)
            {
                string source = File.ReadAllText(file);
                SyntaxTree tree = CSharpSyntaxTree.ParseText(source);
                CompilationUnitSyntax root = tree.GetCompilationUnitRoot();

                var regionDirectives = root.DescendantTrivia()
                    .Where(t => t.IsKind(SyntaxKind.RegionDirectiveTrivia) || t.IsKind(SyntaxKind.EndRegionDirectiveTrivia))
                    .ToArray();

                Assert.That(regionDirectives.Length, Is.EqualTo(0),
                    $"File {file} must not contain #region or #endregion directives");
            }
        }

        [Test]
        public void ProductionFiles_ShouldNotHaveNullableEnableDirective()
        {
            string[] csFiles = Directory.GetFiles(ProductionProjectPath, "*.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && !f.EndsWith(".g.cs"))
                .ToArray();

            Assert.That(csFiles, Is.Not.Empty, "No production C# files found");

            foreach (string file in csFiles)
            {
                string source = File.ReadAllText(file);
                SyntaxTree tree = CSharpSyntaxTree.ParseText(source);
                CompilationUnitSyntax root = tree.GetCompilationUnitRoot();

                var nullableDirectives = root.DescendantTrivia()
                    .Where(t => t.IsKind(SyntaxKind.NullableDirectiveTrivia))
                    .ToArray();

                Assert.That(nullableDirectives.Length, Is.EqualTo(0),
                    $"File {file} must not contain #nullable enable directive");
            }
        }

        [Test]
        public void ProductionFiles_ShouldHaveUsingDirectivesOutsideNamespace()
        {
            string[] csFiles = Directory.GetFiles(ProductionProjectPath, "*.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && !f.EndsWith(".g.cs"))
                .ToArray();

            Assert.That(csFiles, Is.Not.Empty, "No production C# files found");

            foreach (string file in csFiles)
            {
                string source = File.ReadAllText(file);
                SyntaxTree tree = CSharpSyntaxTree.ParseText(source);
                CompilationUnitSyntax root = tree.GetCompilationUnitRoot();

                var usingDirectives = root.Usings.ToArray();

                foreach (var usingDirective in usingDirectives)
                {
                    Assert.That(usingDirective.Parent, Is.TypeOf<CompilationUnitSyntax>(),
                        $"Using directive '{usingDirective.Name}' in {file} must be outside namespace");
                }
            }
        }

        [Test]
        public void ProductionFiles_ShouldNotHaveInlineFullyQualifiedTypes()
        {
            string[] csFiles = Directory.GetFiles(ProductionProjectPath, "*.cs", SearchOption.AllDirectories)
                .Where(f => !f.Contains("/bin/") && !f.Contains("/obj/") && !f.EndsWith(".g.cs"))
                .ToArray();

            Assert.That(csFiles, Is.Not.Empty, "No production C# files found");

            foreach (string file in csFiles)
            {
                string source = File.ReadAllText(file);
                SyntaxTree tree = CSharpSyntaxTree.ParseText(source);
                CompilationUnitSyntax root = tree.GetCompilationUnitRoot();

                var qualifiedNames = root.DescendantNodes()
                    .OfType<QualifiedNameSyntax>()
                    .Where(q => q.Left.ToString().StartsWith("System.") || q.Left.ToString().StartsWith("Microsoft."))
                    .ToArray();

                Assert.That(qualifiedNames.Length, Is.EqualTo(0),
                    $"File {file} must not contain inline fully qualified BCL types (use using directives instead)");
            }
        }
    }
}