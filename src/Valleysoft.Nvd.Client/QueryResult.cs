using System.Text.Json.Serialization;

namespace Valleysoft.Nvd.Client;

public abstract class QueryResult
{
    [JsonPropertyName("resultsPerPage")]
    public required int ResultsPerPage { get; set; }

    [JsonPropertyName("startIndex")]
    public required int StartIndex { get; set; }

    [JsonPropertyName("totalResults")]
    public required int TotalResults { get; set; }

    [JsonPropertyName("format")]
    public required string Format { get; set; }

    [JsonPropertyName("version")]
    public required string Version { get; set; }

    [JsonPropertyName("timestamp")]
    public required DateTimeOffset Timestamp { get; set; }
}
