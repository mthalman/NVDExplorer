using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;

namespace Valleysoft.Nvd.Client;

public class NvdClient(HttpClient httpClient, string? apiKey = null)
{
    private readonly HttpClient _httpClient = httpClient;
    private readonly string? _apiKey = apiKey;

    public async Task<CpeQueryResult> GetCpesAsync(CpeQueryFilter filter, CancellationToken cancellationToken = default)
    {
        List<string> uriParams = [];

        if (filter.ResultsPerPage is not null)
        {
            uriParams.Add($"resultsPerPage={filter.ResultsPerPage}");
        }

        if (filter.StartIndex is not null)
        {
            uriParams.Add($"startIndex={filter.StartIndex}");
        }

        if (filter.Keywords is not null)
        {
            uriParams.Add($"keywordSearch={filter.Keywords}");
        }

        string uriParamsStr = string.Join('&', uriParams);

        string url = $"https://services.nvd.nist.gov/rest/json/cpes/2.0?{uriParamsStr}";
        HttpRequestMessage request = new(HttpMethod.Get, url);
        if (_apiKey is not null)
        {
            request.Headers.Add("apiKey", _apiKey);
        }
        HttpResponseMessage response = await _httpClient.SendAsync(request, cancellationToken);
        response.EnsureSuccessStatusCode();
        CpeQueryResult? result = await response.Content.ReadFromJsonAsync<CpeQueryResult>(Converter.Settings, cancellationToken: cancellationToken);
        return result ?? throw new InvalidOperationException("Unable to deserialize the CVE query result.");
    }

    public async Task<CveQueryResult> GetCvesAsync(CveQueryFilter filter, CancellationToken cancellationToken = default)
    {
        List<string> uriParams = [];

        if (filter.CpeName is not null)
        {
            uriParams.Add($"cpeName={filter.CpeName}");
        }

        if (filter.CveId is not null)
        {
            uriParams.Add($"cveId={filter.CveId}");
        }

        if (filter.CveTag is not null)
        {
            uriParams.Add($"cveTag={filter.CveTag}");
        }

        if (filter.CvssV2Metrics is not null)
        {
            uriParams.Add($"cvssV2Metrics={filter.CvssV2Metrics}");
        }

        if (filter.CvssV2Severity is not null)
        {
            uriParams.Add($"cvssV2Severity={GetEnumName(filter.CvssV2Severity.Value)}");
        }

        if (filter.CvssV3Metrics is not null)
        {
            uriParams.Add($"cvssV3Metrics={filter.CvssV3Metrics}");
        }

        if (filter.CvssV3Severity is not null)
        {
            uriParams.Add($"cvssV3Severity={GetEnumName(filter.CvssV3Severity.Value)}");
        }

        if (filter.CvssV4Metrics is not null)
        {
            uriParams.Add($"cvssV4Metrics={filter.CvssV4Metrics}");
        }

        if (filter.CvssV4Severity is not null)
        {
            uriParams.Add($"cvssV4Severity={GetEnumName(filter.CvssV4Severity.Value)}");
        }

        if (filter.CweId is not null)
        {
            uriParams.Add($"cweId={filter.CweId}");
        }

        if (filter.HasCertAlerts)
        {
            uriParams.Add("hasCertAlerts");
        }

        if (filter.HasCertNotes)
        {
            uriParams.Add("hasCertNotes");
        }

        if (filter.HasKev)
        {
            uriParams.Add("hasKev");
        }

        if (filter.IsVulnerable)
        {
            uriParams.Add("isVulnerable");
        }

        if (filter.IsKeywordExactMatch)
        {
            uriParams.Add("isKeywordExactMatch");
        }

        if (filter.Keywords.Length != 0)
        {
            uriParams.Add($"keywords={string.Join(' ', filter.Keywords)}");
        }

        if (filter.LastModified is not null)
        {
            uriParams.Add($"lastModStartDate={FormatAsIso8601(filter.LastModified.Value.Start)}");
            uriParams.Add($"lastModEndDate={FormatAsIso8601(filter.LastModified.Value.End)}");
        }

        if (filter.ExcludeRejected)
        {
            uriParams.Add("noRejected");
        }

        if (filter.Published is not null)
        {
            uriParams.Add($"pubStartDate={FormatAsIso8601(filter.Published.Value.Start)}");
            uriParams.Add($"pubEndDate={FormatAsIso8601(filter.Published.Value.End)}");
        }

        if (filter.ResultsPerPage is not null)
        {
            uriParams.Add($"resultsPerPage={filter.ResultsPerPage}");
        }

        if (filter.StartIndex is not null)
        {
            uriParams.Add($"startIndex={filter.StartIndex}");
        }

        if (filter.SourceIdentifier is not null)
        {
            uriParams.Add($"sourceIdentifier={filter.SourceIdentifier}");
        }

        if (filter.VirtualMatch is not null)
        {
            uriParams.Add($"virtualMatchString={filter.VirtualMatch.MatchValue}");
            if (filter.VirtualMatch.StartVersion is not null)
            {
                uriParams.Add($"versionStart={filter.VirtualMatch.StartVersion.Version}");
                uriParams.Add($"versionStartType={GetEnumName(filter.VirtualMatch.StartVersion.Type)}");
            }
            if (filter.VirtualMatch.EndVersion is not null)
            {
                uriParams.Add($"versionEnd={filter.VirtualMatch.EndVersion.Version}");
                uriParams.Add($"versionEndType={GetEnumName(filter.VirtualMatch.EndVersion.Type)}");
            }
        }

        string uriParamsStr = string.Join('&', uriParams);

        string url = $"https://services.nvd.nist.gov/rest/json/cves/2.0?{uriParamsStr}";
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

    private static string GetEnumName<T>(T enumValue) where T : struct, Enum
    {
        string enumName = Enum.GetName(enumValue) ??
            throw new InvalidOperationException($"Unable to get enum name for value {enumValue} on enum {typeof(T)}.");
        NvdNameAttribute attrib = typeof(T).GetField(enumName)?.GetCustomAttribute<NvdNameAttribute>() ??
            throw new InvalidOperationException($"Missing {nameof(NvdNameAttribute)} for value {enumValue} on enum {typeof(T)}.");
        return attrib.Name;
    }

    private static string FormatAsIso8601(DateTimeOffset dateTime) => dateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");

    private static class Converter
    {
        public static readonly JsonSerializerOptions Settings = new(JsonSerializerDefaults.General)
        {
            Converters =
            {
                AutomatableTypeConverter.Singleton,
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
                AttackRequirementsTypeConverter.Singleton,
                AttackVectorTypeConverter.Singleton,
                AvailabilityImpactEnumConverter.Singleton,
                SeverityTypeConverter.Singleton,
                ExploitCodeMaturityTypeConverter.Singleton,
                ExploitMaturityTypeConverter.Singleton,
                ModifiedAttackComplexityTypeConverter.Singleton,
                ModifiedAttackVectorTypeConverter.Singleton,
                ModifiedAttackRequirementsTypeConverter.Singleton,
                ModifiedTypeConverter.Singleton,
                ModifiedScopeTypeConverter.Singleton,
                ModifiedSubCiaTypeConverter.Singleton,
                ModifiedSubIaTypeConverter.Singleton,
                ModifiedUserInteractionTypeConverter.Singleton,
                ModifiedVulnerabilityCiaTypeConverter.Singleton,
                ProviderUrgencyTypeConverter.Singleton,
                ConfidenceTypeConverter.Singleton,
                RecoveryTypeConverter.Singleton,
                SafetyTypeConverter.Singleton,
                ScopeTypeConverter.Singleton,
                SubCiaTypeConverter.Singleton,
                UserInteractionTypeConverter.Singleton,
                ValueDensityTypeConverter.Singleton,
                VulnerabilityCiaTypeConverter.Singleton,
                VulnerabilityResponseEffortTypeConverter.Singleton,
            }
        };
    }
}
