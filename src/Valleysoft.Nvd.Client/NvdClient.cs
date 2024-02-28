using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace Valleysoft.Nvd.Client;

public class NvdClient(HttpClient httpClient, string? apiKey = null)
{
    private readonly HttpClient _httpClient = httpClient;
    private readonly string? _apiKey = apiKey;

    public async Task<CveQueryResult> GetCves(CveQueryFilter filter, CancellationToken cancellationToken = default)
    {
        StringBuilder uriParams = new();
        if (filter.CveId is not null)
        {
            uriParams.Append($"&cveId={filter.CveId}");
        }

        string url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?{uriParams}";
        HttpRequestMessage request = new(HttpMethod.Get, url);
        if (_apiKey is not null)
        {
            request.Headers.Add("apiKey", _apiKey);
        }
        HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        CveQueryResult? result = await response.Content.ReadFromJsonAsync<CveQueryResult>(Converter.Settings, cancellationToken: cancellationToken);
        return result ?? throw new InvalidOperationException("Unable to deserialize the CVE query result.");
    }

    private static class Converter
    {
        public static readonly JsonSerializerOptions Settings = new(JsonSerializerDefaults.General)
        {
            Converters =
            {
                ScoreTypeConverter.Singleton,
                OperatorConverter.Singleton,
                CvssVersionConverter.Singleton,
                CvssV2.AccessComplexityTypeConverter.Singleton,
                CvssV2.AccessVectorTypeConverter.Singleton,
                CvssV2.AuthenticationTypeConverter.Singleton,
                CvssV2.CiaTypeConverter.Singleton,
                CiaRequirementTypeConverter.Singleton,
                CvssV2.CollateralDamagePotentialTypeConverter.Singleton,
                CvssV2.ExploitabilityTypeConverter.Singleton,
                RemediationLevelTypeConverter.Singleton,
                CvssV2.ReportConfidenceTypeConverter.Singleton,
                CvssV2.TargetDistributionTypeConverter.Singleton,
                new DateOnlyConverter(),
                new TimeOnlyConverter(),
                IsoDateTimeOffsetConverter.Singleton,
                AttackComplexityTypeConverter.Singleton,
                AttackVectorTypeConverter.Singleton,
                AvailabilityImpactEnumConverter.Singleton,
                SeverityTypeConverter.Singleton,
                ExploitCodeMaturityTypeConverter.Singleton,
                ModifiedAttackComplexityTypeConverter.Singleton,
                ModifiedAttackVectorTypeConverter.Singleton,
                ModifiedTypeConverter.Singleton,
                ModifiedScopeTypeConverter.Singleton,
                ModifiedUserInteractionTypeConverter.Singleton,
                ConfidenceTypeConverter.Singleton,
                ScopeTypeConverter.Singleton,
                UserInteractionTypeConverter.Singleton
            }
        };
    }
}
