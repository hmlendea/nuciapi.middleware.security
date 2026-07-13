using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using NuciAPI.Middleware.Security;
using NUnit.Framework;

namespace NuciAPI.Middleware.UnitTests.Security
{
    [TestFixture]
    public sealed class ReplayProtectionMiddlewareTests
    {
        [Test]
        public async Task Given_FirstValidRequest_When_InvokeAsync_Then_InvokesNextDelegate()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            bool wasInvoked = false;
            ReplayProtectionMiddleware middleware = new(_ =>
            {
                wasInvoked = true;
                return Task.CompletedTask;
            }, memoryCache);

            await middleware.InvokeAsync(CreateValidContext());

            Assert.That(wasInvoked, Is.True);
        }

        [Test]
        public async Task Given_TimestampWithOffsetAndFractionalSecondsAcrossHeaderValidationAndReplay_When_InvokeAsync_Then_InvokesNextDelegate()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            bool wasInvoked = false;
            ReplayProtectionMiddleware replayProtectionMiddleware = new(_ =>
            {
                wasInvoked = true;
                return Task.CompletedTask;
            }, memoryCache);
            HeaderValidationMiddleware headerValidationMiddleware = new(replayProtectionMiddleware.InvokeAsync);
            DefaultHttpContext context = CreateValidContext(
                timestampHeaderValue: DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(3)).ToString("O"));

            await headerValidationMiddleware.InvokeAsync(context);

            Assert.That(wasInvoked, Is.True);
        }

        [Test]
        public async Task Given_UtcTimestampWithFractionalSecondsAcrossHeaderValidationAndReplay_When_InvokeAsync_Then_InvokesNextDelegate()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            bool wasInvoked = false;
            ReplayProtectionMiddleware replayProtectionMiddleware = new(_ =>
            {
                wasInvoked = true;
                return Task.CompletedTask;
            }, memoryCache);
            HeaderValidationMiddleware headerValidationMiddleware = new(replayProtectionMiddleware.InvokeAsync);
            DefaultHttpContext context = CreateValidContext(
                timestampHeaderValue: DateTime.UtcNow.ToString("O"));

            await headerValidationMiddleware.InvokeAsync(context);

            Assert.That(wasInvoked, Is.True);
        }

        [Test]
        public async Task Given_TimestampWithOffsetAndFractionalSecondsWithinAllowedSkew_When_InvokeAsync_Then_InvokesNextDelegate()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            bool wasInvoked = false;
            ReplayProtectionMiddleware middleware = new(_ =>
            {
                wasInvoked = true;
                return Task.CompletedTask;
            }, memoryCache);
            DefaultHttpContext context = CreateValidContext(
                timestampHeaderValue: DateTimeOffset.UtcNow.ToOffset(TimeSpan.FromHours(3)).ToString("O"));

            await middleware.InvokeAsync(context);

            Assert.That(wasInvoked, Is.True);
        }

        [Test]
        public async Task Given_UtcTimestampWithFractionalSecondsWithinAllowedSkew_When_InvokeAsync_Then_InvokesNextDelegate()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            bool wasInvoked = false;
            ReplayProtectionMiddleware middleware = new(_ =>
            {
                wasInvoked = true;
                return Task.CompletedTask;
            }, memoryCache);
            DefaultHttpContext context = CreateValidContext(
                timestampHeaderValue: DateTime.UtcNow.ToString("O"));

            await middleware.InvokeAsync(context);

            Assert.That(wasInvoked, Is.True);
        }

        [Test]
        public async Task Given_DuplicateRequest_When_InvokeAsync_Then_ThrowsRequestAlreadyProcessedException()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            ReplayProtectionMiddleware middleware = new(_ => Task.CompletedTask, memoryCache);
            DefaultHttpContext firstContext = CreateValidContext();
            DefaultHttpContext secondContext = CreateValidContext(firstContext.Request.Headers[NuciApiHeaderNames.RequestId]!);

            await middleware.InvokeAsync(firstContext);

        Assert.ThrowsAsync<RequestAlreadyProcessedException>(async () => await middleware.InvokeAsync(secondContext));
        }

        [Test]
        public void Given_ExpiredRequest_When_InvokeAsync_Then_ThrowsBadHttpRequestException()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            ReplayProtectionMiddleware middleware = new(_ => Task.CompletedTask, memoryCache);
            DefaultHttpContext context = CreateValidContext(timestamp: DateTimeOffset.UtcNow.AddMinutes(-6));

            Assert.ThrowsAsync<BadHttpRequestException>(async () => await middleware.InvokeAsync(context));
        }

        [Test]
        public void Given_RequestTooFarInFuture_When_InvokeAsync_Then_ThrowsBadHttpRequestException()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            ReplayProtectionMiddleware middleware = new(_ => Task.CompletedTask, memoryCache);
            DefaultHttpContext context = CreateValidContext(timestamp: DateTimeOffset.UtcNow.AddMinutes(6));

            Assert.ThrowsAsync<BadHttpRequestException>(async () => await middleware.InvokeAsync(context));
        }

        [Test]
        public void Given_NullMemoryCache_When_ConstructingMiddleware_Then_ThrowsArgumentNullException()
        {
            Assert.That(
                () => new ReplayProtectionMiddleware(_ => Task.CompletedTask, null!),
                Throws.ArgumentNullException);
        }

        [Test]
        public void Given_NullNextDelegate_When_ConstructingMiddleware_Then_ThrowsArgumentNullException()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());

            Assert.That(
                () => new ReplayProtectionMiddleware(null!, memoryCache),
                Throws.ArgumentNullException);
        }

        [Test]
        public async Task Given_SameRequestIdButDifferentPaths_When_InvokeAsync_Then_AllowsBothRequests()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            int invocationCount = 0;
            ReplayProtectionMiddleware middleware = new(_ =>
            {
                invocationCount += 1;
                return Task.CompletedTask;
            }, memoryCache);

            string requestId = Guid.NewGuid().ToString().ToUpperInvariant();
            DefaultHttpContext firstContext = CreateValidContext(requestId: requestId);
            firstContext.Request.Path = "/resource-alpha";
            DefaultHttpContext secondContext = CreateValidContext(requestId: requestId);
            secondContext.Request.Path = "/resource-beta";

            await middleware.InvokeAsync(firstContext);
            await middleware.InvokeAsync(secondContext);

            Assert.That(invocationCount, Is.EqualTo(2));
        }

        [Test]
        public async Task Given_SameRequestIdButDifferentClientIds_When_InvokeAsync_Then_AllowsBothRequests()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            int invocationCount = 0;
            ReplayProtectionMiddleware middleware = new(_ =>
            {
                invocationCount += 1;
                return Task.CompletedTask;
            }, memoryCache);

            string requestId = Guid.NewGuid().ToString().ToUpperInvariant();
            DefaultHttpContext firstContext = CreateValidContext(requestId: requestId);
            firstContext.Request.Headers[NuciApiHeaderNames.ClientId] = "IlarionPintilie";
            DefaultHttpContext secondContext = CreateValidContext(requestId: requestId);
            secondContext.Request.Headers[NuciApiHeaderNames.ClientId] = "solaire_of_astora";

            await middleware.InvokeAsync(firstContext);
            await middleware.InvokeAsync(secondContext);

            Assert.That(invocationCount, Is.EqualTo(2));
        }

        [Test]
        public async Task Given_DifferentRequestIdsOnSamePath_When_InvokeAsync_Then_AllowsBothRequests()
        {
            using MemoryCache memoryCache = new(new MemoryCacheOptions());
            int invocationCount = 0;
            ReplayProtectionMiddleware middleware = new(_ =>
            {
                invocationCount += 1;
                return Task.CompletedTask;
            }, memoryCache);

            DefaultHttpContext firstContext = CreateValidContext();
            DefaultHttpContext secondContext = CreateValidContext();

            await middleware.InvokeAsync(firstContext);
            await middleware.InvokeAsync(secondContext);

            Assert.That(invocationCount, Is.EqualTo(2));
        }

        private static DefaultHttpContext CreateValidContext(
            string? requestId = null,
            DateTimeOffset? timestamp = null,
            string? timestampHeaderValue = null)
        {
            DefaultHttpContext context = new();
            context.Request.Path = "/resource";
            context.Request.Headers[NuciApiHeaderNames.ClientId] = "client-123";
            context.Request.Headers[NuciApiHeaderNames.RequestId] = requestId ?? Guid.NewGuid().ToString().ToUpperInvariant();
            context.Request.Headers[NuciApiHeaderNames.Timestamp] = timestampHeaderValue ?? (timestamp ?? DateTimeOffset.UtcNow).ToString("O");
            return context;
        }
    }
}