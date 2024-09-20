using System.Text.Json.Serialization;

namespace Valleysoft.Nvd.Client;

public class CpeQueryResult : QueryResult
{
    [JsonPropertyName("products")]
    public Product[] Products { get; set; } = [];
}

public class Product
{
    [JsonPropertyName("cpe")]
    public required Cpe Cpe { get; set; }
}

public class Cpe
{
    [JsonPropertyName("deprecated")]
    public bool IsDeprecated { get; set; }

    [JsonPropertyName("cpeName")]
    public required string CpeName { get; set; }

    [JsonPropertyName("cpeNameId")]
    public required string CpeNameId { get; set; }

    [JsonPropertyName("lastModified")]
    public required DateTimeOffset LastModified { get; set; }

    [JsonPropertyName("created")]
    public required DateTimeOffset Created { get; set; }

    [JsonPropertyName("titles")]
    public CpeTitle[] Titles { get; set; } = [];
}

public class CpeTitle : ILanguageValue
{
    [JsonPropertyName("title")]
    public required string Title { get; set; }

    [JsonPropertyName("lang")]
    public required string Language { get; set; }

    string ILanguageValue.Value => Title;
}
