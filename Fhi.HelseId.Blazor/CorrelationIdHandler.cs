﻿namespace Fhi.HelseId.Blazor;

public class CorrelationIdHandler : DelegatingHandler
{
    public const string CorrelationIdHeaderName = "X-Correlation-ID";

    private IServiceProvider _provider;
    private HelseidRefitBuilderForBlazorOptions _options;

    public CorrelationIdHandler(IServiceProvider provider, HelseidRefitBuilderForBlazorOptions options)
    {
        _provider = provider;
        _options = options;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var correlationId = _options.CustomCorrelationIdFunc?.Invoke(_provider) ?? Guid.NewGuid().ToString();

        if (request.Headers.TryGetValues(CorrelationIdHeaderName, out var values))
        {
            correlationId = values!.First();
        }
        else
        {
            request.Headers.Add(CorrelationIdHeaderName, correlationId);
        }

        var response = await base.SendAsync(request, cancellationToken);

        if (!response.Headers.TryGetValues(CorrelationIdHeaderName, out _))
        {
            response.Headers.Add(CorrelationIdHeaderName, correlationId);
        }

        return response;
    }
}
