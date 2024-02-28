using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Valleysoft.Nvd.Client.CvssV2;
using Valleysoft.Nvd.Client.CvssV30;
using Valleysoft.Nvd.Client.CvssV31;

namespace Valleysoft.Nvd.Client;

public class CveQueryResult
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

    [JsonPropertyName("vulnerabilities")]
    public required Vulnerability[] Vulnerabilities { get; set; } = [];
}

public class Vulnerability
{
    [JsonPropertyName("cve")]
    public required Cve Cve { get; set; }
}

public class Cve
{
    [JsonPropertyName("id")]
    public required string Id { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("sourceIdentifier")]
    public string? SourceIdentifier { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("vulnStatus")]
    public string? VulnerabilityStatus { get; set; }

    [JsonPropertyName("published")]
    public required DateTimeOffset Published { get; set; }

    [JsonPropertyName("lastModified")]
    public required DateTimeOffset LastModified { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("evaluatorComment")]
    public string? EvaluatorComment { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("evaluatorSolution")]
    public string? EvaluatorSolution { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("evaluatorImpact")]
    public string? EvaluatorImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("cisaExploitAdd")]
    public DateTimeOffset? CisaExploitAdd { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("cisaActionDue")]
    public DateTimeOffset? CisaActionDue { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("cisaRequiredAction")]
    public string? CisaRequiredAction { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("cisaVulnerabilityName")]
    public string? CisaVulnerabilityName { get; set; }

    [JsonPropertyName("descriptions")]
    public required LanguageString[] Descriptions { get; set; } = [];

    [JsonPropertyName("references")]
    public required Reference[] References { get; set; } = [];

    [JsonPropertyName("metrics")]
    public Metrics? Metrics { get; set; }

    [JsonPropertyName("weaknesses")]
    public Weakness[] Weaknesses { get; set; } = [];

    [JsonPropertyName("configurations")]
    public Configuration[] Configurations { get; set; } = [];

    [JsonPropertyName("vendorComments")]
    public VendorComment[] VendorComments { get; set; } = [];
}

public class VendorComment
{
    [JsonPropertyName("organization")]
    public required string Organization { get; set; }

    [JsonPropertyName("comment")]
    public required string Comment { get; set; }

    [JsonPropertyName("lastModified")]
    public required DateTimeOffset LastModified { get; set; }
}

public class Configuration
{
    [JsonPropertyName("operator")]
    public Operator Operator { get; set; }

    [JsonPropertyName("negate")]
    public bool Negate { get; set; }

    [JsonPropertyName("nodes")]
    public required Node[] Nodes { get; set; } = [];
}

public class Node
{
    [JsonPropertyName("operator")]
    public required Operator Operator { get; set; }

    [JsonPropertyName("negate")]
    public bool Negate { get; set; }

    [JsonPropertyName("cpeMatch")]
    public required CpeMatch[] CpeMatches { get; set; } = [];
}

public class CpeMatch
{
    [JsonPropertyName("vulnerable")]
    public bool IsVulnerable { get; set; }

    [JsonPropertyName("criteria")]
    public required string Criteria { get; set; }

    [JsonPropertyName("matchCriteriaId")]
    public required Guid MatchCriteriaId { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("versionStartExcluding")]
    public string? VersionStartExcluding { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("versionStartIncluding")]
    public string? VersionStartIncluding { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("versionEndExcluding")]
    public string? VersionEndExcluding { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("versionEndIncluding")]
    public string? VersionEndIncluding { get; set; }
}

public enum Operator
{
    And,
    Or
}

public class Weakness
{
    [JsonPropertyName("source")]
    public required string Source { get; set; }

    [JsonPropertyName("type")]
    public required string Type { get; set; }

    [JsonPropertyName("description")]
    public required LanguageString[] Description { get; set; } = [];
}

public class LanguageString
{
    [JsonPropertyName("lang")]
    public required string Language { get; set; }

    [JsonPropertyName("value")]
    public required string Value { get; set; }
}

public class Reference
{
    [JsonPropertyName("url")]
    public required Uri Url { get; set; } = null!;

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("source")]
    public string? Source { get; set; }

    [JsonPropertyName("tags")]
    public string[] Tags { get; set; } = [];
}

public class Metrics
{
    [JsonPropertyName("cvssMetricV31")]
    public CvssV31Score[] CvssMetricV31 { get; set; } = [];

    [JsonPropertyName("cvssMetricV30")]
    public CvssV30Score[] CvssMetricV30 { get; set; } = [];

    [JsonPropertyName("cvssMetricV2")]
    public CvssV2Score[] CvssMetricV2 { get; set; } = [];
}

public class CvssV2Score
{
    [JsonPropertyName("source")]
    public required string Source { get; set; }

    [JsonPropertyName("type")]
    public required ScoreType Type { get; set; }

    [JsonPropertyName("cvssData")]
    public required CvssV2ScoreData CvssData { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("baseSeverity")]
    public string? BaseSeverity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("exploitabilityScore")]
    public double? ExploitabilityScore { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("impactScore")]
    public double? ImpactScore { get; set; }

    [JsonPropertyName("acInsufInfo")]
    public bool AccessComplexityInsufficientInfo { get; set; }

    [JsonPropertyName("obtainAllPrivilege")]
    public bool ObtainAllPrivilege { get; set; }

    [JsonPropertyName("obtainUserPrivilege")]
    public bool ObtainUserPrivilege { get; set; }

    [JsonPropertyName("obtainOtherPrivilege")]
    public bool ObtainOtherPrivilege { get; set; }

    [JsonPropertyName("userInteractionRequired")]
    public bool UserInteractionRequired { get; set; }

}

public class CvssV31Score
{
    [JsonPropertyName("source")]
    public required string Source { get; set; }

    [JsonPropertyName("type")]
    public required ScoreType Type { get; set; }

    [JsonPropertyName("cvssData")]
    public required CvssV31ScoreData CvssData { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("exploitabilityScore")]
    public double? ExploitabilityScore { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("impactScore")]
    public double? ImpactScore { get; set; }
}

public class CvssV30Score
{
    [JsonPropertyName("source")]
    public required string Source { get; set; }

    [JsonPropertyName("type")]
    public required ScoreType Type { get; set; }

    [JsonPropertyName("cvssData")]
    public required CvssV30ScoreData CvssData { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("exploitabilityScore")]
    public double ExploitabilityScore { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)]
    [JsonPropertyName("impactScore")]
    public double ImpactScore { get; set; }
}

public enum ScoreType
{
    Primary,
    Secondary
}

internal class ScoreTypeConverter : JsonConverter<ScoreType>
{
    public override bool CanConvert(Type t) => t == typeof(ScoreType);

    public override ScoreType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "Primary" => ScoreType.Primary,
            "Secondary" => ScoreType.Secondary,
            _ => throw new Exception("Cannot unmarshal type ScoreType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ScoreType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ScoreType.Primary:
                JsonSerializer.Serialize(writer, "Primary", options);
                return;
            case ScoreType.Secondary:
                JsonSerializer.Serialize(writer, "Secondary", options);
                return;
            default:
                throw new Exception("Cannot marshal type ScoreType");
        }
    }

    public static readonly ScoreTypeConverter Singleton = new();
}

internal class OperatorConverter : JsonConverter<Operator>
{
    public override bool CanConvert(Type t) => t == typeof(Operator);

    public override Operator Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "AND" => Operator.And,
            "OR" => Operator.Or,
            _ => throw new Exception("Cannot unmarshal type Operator"),
        };
    }

    public override void Write(Utf8JsonWriter writer, Operator value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case Operator.And:
                JsonSerializer.Serialize(writer, "AND", options);
                return;
            case Operator.Or:
                JsonSerializer.Serialize(writer, "OR", options);
                return;
            default:
                throw new Exception("Cannot marshal type Operator");
        }
    }

    public static readonly OperatorConverter Singleton = new();
}


internal class CvssVersionConverter : JsonConverter<CvssVersion>
{
    public override bool CanConvert(Type t) => t == typeof(CvssVersion);

    public override CvssVersion Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "2.0" => CvssVersion.Version20,
            "3.0" => CvssVersion.Version30,
            "3.1" => CvssVersion.Version31,
            _ => throw new Exception("Cannot unmarshal type Version"),
        };
    }

    public override void Write(Utf8JsonWriter writer, CvssVersion value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case CvssVersion.Version20:
                JsonSerializer.Serialize(writer, "2.0", options);
                return;
            case CvssVersion.Version30:
                JsonSerializer.Serialize(writer, "3.0", options);
                return;
            case CvssVersion.Version31:
                JsonSerializer.Serialize(writer, "3.1", options);
                return;
            default:
                throw new Exception("Cannot marshal type Version");
        }
    }

    public static readonly CvssVersionConverter Singleton = new();
}


/// <summary>
/// CVSS Version
/// </summary>
public enum CvssVersion
{
    Version20,
    Version30,
    Version31
}

public enum CiaRequirementType { High, Low, Medium, NotDefined };

internal class CiaRequirementTypeConverter : JsonConverter<CiaRequirementType>
{
    public override bool CanConvert(Type t) => t == typeof(CiaRequirementType);

    public override CiaRequirementType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "HIGH" => CiaRequirementType.High,
            "LOW" => CiaRequirementType.Low,
            "MEDIUM" => CiaRequirementType.Medium,
            "NOT_DEFINED" => CiaRequirementType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type CiaRequirementType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, CiaRequirementType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case CiaRequirementType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case CiaRequirementType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case CiaRequirementType.Medium:
                JsonSerializer.Serialize(writer, "MEDIUM", options);
                return;
            case CiaRequirementType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type CiaRequirementType");
        }
    }

    public static readonly CiaRequirementTypeConverter Singleton = new();
}

public enum RemediationLevelType { NotDefined, OfficialFix, TemporaryFix, Unavailable, Workaround };

internal class RemediationLevelTypeConverter : JsonConverter<RemediationLevelType>
{
    public override bool CanConvert(Type t) => t == typeof(RemediationLevelType);

    public override RemediationLevelType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NOT_DEFINED" => RemediationLevelType.NotDefined,
            "OFFICIAL_FIX" => RemediationLevelType.OfficialFix,
            "TEMPORARY_FIX" => RemediationLevelType.TemporaryFix,
            "UNAVAILABLE" => RemediationLevelType.Unavailable,
            "WORKAROUND" => RemediationLevelType.Workaround,
            _ => throw new Exception("Cannot unmarshal type RemediationLevelType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, RemediationLevelType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case RemediationLevelType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            case RemediationLevelType.OfficialFix:
                JsonSerializer.Serialize(writer, "OFFICIAL_FIX", options);
                return;
            case RemediationLevelType.TemporaryFix:
                JsonSerializer.Serialize(writer, "TEMPORARY_FIX", options);
                return;
            case RemediationLevelType.Unavailable:
                JsonSerializer.Serialize(writer, "UNAVAILABLE", options);
                return;
            case RemediationLevelType.Workaround:
                JsonSerializer.Serialize(writer, "WORKAROUND", options);
                return;
            default:
                throw new Exception("Cannot marshal type RemediationLevelType");
        }
    }

    public static readonly RemediationLevelTypeConverter Singleton = new();
}

public class DateOnlyConverter(string? serializationFormat) : JsonConverter<DateOnly>
{
    private readonly string _serializationFormat = serializationFormat ?? "yyyy-MM-dd";
    public DateOnlyConverter() : this(null) { }

    public override DateOnly Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return DateOnly.Parse(value!);
    }

    public override void Write(Utf8JsonWriter writer, DateOnly value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.ToString(_serializationFormat));
}

public class TimeOnlyConverter(string? serializationFormat) : JsonConverter<TimeOnly>
{
    private readonly string _serializationFormat = serializationFormat ?? "HH:mm:ss.fff";

    public TimeOnlyConverter() : this(null) { }

    public override TimeOnly Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return TimeOnly.Parse(value!);
    }

    public override void Write(Utf8JsonWriter writer, TimeOnly value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.ToString(_serializationFormat));
}

internal class IsoDateTimeOffsetConverter : JsonConverter<DateTimeOffset>
{
    public override bool CanConvert(Type t) => t == typeof(DateTimeOffset);

    private const string DefaultDateTimeFormat = "yyyy'-'MM'-'dd'T'HH':'mm':'ss.FFFFFFFK";
    private string? _dateTimeFormat;
    private CultureInfo? _culture;

    public DateTimeStyles DateTimeStyles { get; set; } = DateTimeStyles.RoundtripKind;

    public string? DateTimeFormat
    {
        get => _dateTimeFormat ?? string.Empty;
        set => _dateTimeFormat = (string.IsNullOrEmpty(value)) ? null : value;
    }

    public CultureInfo Culture
    {
        get => _culture ?? CultureInfo.CurrentCulture;
        set => _culture = value;
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        string text;


        if ((DateTimeStyles & DateTimeStyles.AdjustToUniversal) == DateTimeStyles.AdjustToUniversal
            || (DateTimeStyles & DateTimeStyles.AssumeUniversal) == DateTimeStyles.AssumeUniversal)
        {
            value = value.ToUniversalTime();
        }

        text = value.ToString(_dateTimeFormat ?? DefaultDateTimeFormat, Culture);

        writer.WriteStringValue(text);
    }

    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? dateText = reader.GetString();

        if (string.IsNullOrEmpty(dateText) == false)
        {
            if (!string.IsNullOrEmpty(_dateTimeFormat))
            {
                return DateTimeOffset.ParseExact(dateText, _dateTimeFormat, Culture, DateTimeStyles);
            }
            else
            {
                return DateTimeOffset.Parse(dateText, Culture, DateTimeStyles);
            }
        }
        else
        {
            return default;
        }
    }

    public static readonly IsoDateTimeOffsetConverter Singleton = new();
}

public enum AttackComplexityType { High, Low };

internal class AttackComplexityTypeConverter : JsonConverter<AttackComplexityType>
{
    public override bool CanConvert(Type t) => t == typeof(AttackComplexityType);

    public override AttackComplexityType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "HIGH" => AttackComplexityType.High,
            "LOW" => AttackComplexityType.Low,
            _ => throw new Exception("Cannot unmarshal type AttackComplexityType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, AttackComplexityType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case AttackComplexityType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case AttackComplexityType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            default:
                throw new Exception("Cannot marshal type AttackComplexityType");
        }
    }

    public static readonly AttackComplexityTypeConverter Singleton = new();
}

public enum AttackVectorType { AdjacentNetwork, Local, Network, Physical };

internal class AttackVectorTypeConverter : JsonConverter<AttackVectorType>
{
    public override bool CanConvert(Type t) => t == typeof(AttackVectorType);

    public override AttackVectorType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "ADJACENT_NETWORK" => AttackVectorType.AdjacentNetwork,
            "LOCAL" => AttackVectorType.Local,
            "NETWORK" => AttackVectorType.Network,
            "PHYSICAL" => AttackVectorType.Physical,
            _ => throw new Exception("Cannot unmarshal type AttackVectorType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, AttackVectorType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case AttackVectorType.AdjacentNetwork:
                JsonSerializer.Serialize(writer, "ADJACENT_NETWORK", options);
                return;
            case AttackVectorType.Local:
                JsonSerializer.Serialize(writer, "LOCAL", options);
                return;
            case AttackVectorType.Network:
                JsonSerializer.Serialize(writer, "NETWORK", options);
                return;
            case AttackVectorType.Physical:
                JsonSerializer.Serialize(writer, "PHYSICAL", options);
                return;
            default:
                throw new Exception("Cannot marshal type AttackVectorType");
        }
    }

    public static readonly AttackVectorTypeConverter Singleton = new();
}

public enum AvailabilityImpactEnum { High, Low, None };

internal class AvailabilityImpactEnumConverter : JsonConverter<AvailabilityImpactEnum>
{
    public override bool CanConvert(Type t) => t == typeof(AvailabilityImpactEnum);

    public override AvailabilityImpactEnum Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "HIGH" => AvailabilityImpactEnum.High,
            "LOW" => AvailabilityImpactEnum.Low,
            "NONE" => AvailabilityImpactEnum.None,
            _ => throw new Exception("Cannot unmarshal type AvailabilityImpactEnum"),
        };
    }

    public override void Write(Utf8JsonWriter writer, AvailabilityImpactEnum value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case AvailabilityImpactEnum.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case AvailabilityImpactEnum.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case AvailabilityImpactEnum.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            default:
                throw new Exception("Cannot marshal type AvailabilityImpactEnum");
        }
    }

    public static readonly AvailabilityImpactEnumConverter Singleton = new();
}

public enum SeverityType { Critical, High, Low, Medium, None };

internal class SeverityTypeConverter : JsonConverter<SeverityType>
{
    public override bool CanConvert(Type t) => t == typeof(SeverityType);

    public override SeverityType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "CRITICAL" => SeverityType.Critical,
            "HIGH" => SeverityType.High,
            "LOW" => SeverityType.Low,
            "MEDIUM" => SeverityType.Medium,
            "NONE" => SeverityType.None,
            _ => throw new Exception("Cannot unmarshal type SeverityType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, SeverityType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case SeverityType.Critical:
                JsonSerializer.Serialize(writer, "CRITICAL", options);
                return;
            case SeverityType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case SeverityType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case SeverityType.Medium:
                JsonSerializer.Serialize(writer, "MEDIUM", options);
                return;
            case SeverityType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            default:
                throw new Exception("Cannot marshal type SeverityType");
        }
    }

    public static readonly SeverityTypeConverter Singleton = new();
}

public enum ExploitCodeMaturityType { Functional, High, NotDefined, ProofOfConcept, Unproven };

internal class ExploitCodeMaturityTypeConverter : JsonConverter<ExploitCodeMaturityType>
{
    public override bool CanConvert(Type t) => t == typeof(ExploitCodeMaturityType);

    public override ExploitCodeMaturityType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "FUNCTIONAL" => ExploitCodeMaturityType.Functional,
            "HIGH" => ExploitCodeMaturityType.High,
            "NOT_DEFINED" => ExploitCodeMaturityType.NotDefined,
            "PROOF_OF_CONCEPT" => ExploitCodeMaturityType.ProofOfConcept,
            "UNPROVEN" => ExploitCodeMaturityType.Unproven,
            _ => throw new Exception("Cannot unmarshal type ExploitCodeMaturityType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ExploitCodeMaturityType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ExploitCodeMaturityType.Functional:
                JsonSerializer.Serialize(writer, "FUNCTIONAL", options);
                return;
            case ExploitCodeMaturityType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case ExploitCodeMaturityType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            case ExploitCodeMaturityType.ProofOfConcept:
                JsonSerializer.Serialize(writer, "PROOF_OF_CONCEPT", options);
                return;
            case ExploitCodeMaturityType.Unproven:
                JsonSerializer.Serialize(writer, "UNPROVEN", options);
                return;
            default:
                throw new Exception("Cannot marshal type ExploitCodeMaturityType");
        }
    }

    public static readonly ExploitCodeMaturityTypeConverter Singleton = new();
}


public enum ModifiedAttackComplexityType { High, Low, NotDefined };

internal class ModifiedAttackComplexityTypeConverter : JsonConverter<ModifiedAttackComplexityType>
{
    public override bool CanConvert(Type t) => t == typeof(ModifiedAttackComplexityType);

    public override ModifiedAttackComplexityType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "HIGH" => ModifiedAttackComplexityType.High,
            "LOW" => ModifiedAttackComplexityType.Low,
            "NOT_DEFINED" => ModifiedAttackComplexityType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type ModifiedAttackComplexityType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ModifiedAttackComplexityType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ModifiedAttackComplexityType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case ModifiedAttackComplexityType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case ModifiedAttackComplexityType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ModifiedAttackComplexityType");
        }
    }

    public static readonly ModifiedAttackComplexityTypeConverter Singleton = new();
}

public enum ModifiedAttackVectorType { AdjacentNetwork, Local, Network, NotDefined, Physical };

internal class ModifiedAttackVectorTypeConverter : JsonConverter<ModifiedAttackVectorType>
{
    public override bool CanConvert(Type t) => t == typeof(ModifiedAttackVectorType);

    public override ModifiedAttackVectorType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "ADJACENT_NETWORK" => ModifiedAttackVectorType.AdjacentNetwork,
            "LOCAL" => ModifiedAttackVectorType.Local,
            "NETWORK" => ModifiedAttackVectorType.Network,
            "NOT_DEFINED" => ModifiedAttackVectorType.NotDefined,
            "PHYSICAL" => ModifiedAttackVectorType.Physical,
            _ => throw new Exception("Cannot unmarshal type ModifiedAttackVectorType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ModifiedAttackVectorType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ModifiedAttackVectorType.AdjacentNetwork:
                JsonSerializer.Serialize(writer, "ADJACENT_NETWORK", options);
                return;
            case ModifiedAttackVectorType.Local:
                JsonSerializer.Serialize(writer, "LOCAL", options);
                return;
            case ModifiedAttackVectorType.Network:
                JsonSerializer.Serialize(writer, "NETWORK", options);
                return;
            case ModifiedAttackVectorType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            case ModifiedAttackVectorType.Physical:
                JsonSerializer.Serialize(writer, "PHYSICAL", options);
                return;
            default:
                throw new Exception("Cannot marshal type ModifiedAttackVectorType");
        }
    }

    public static readonly ModifiedAttackVectorTypeConverter Singleton = new();
}

public enum ModifiedType { High, Low, None, NotDefined };

internal class ModifiedTypeConverter : JsonConverter<ModifiedType>
{
    public override bool CanConvert(Type t) => t == typeof(ModifiedType);

    public override ModifiedType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "HIGH" => ModifiedType.High,
            "LOW" => ModifiedType.Low,
            "NONE" => ModifiedType.None,
            "NOT_DEFINED" => ModifiedType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type ModifiedType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ModifiedType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ModifiedType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case ModifiedType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case ModifiedType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case ModifiedType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ModifiedType");
        }
    }

    public static readonly ModifiedTypeConverter Singleton = new();
}

public enum ModifiedScopeType { Changed, NotDefined, Unchanged };

internal class ModifiedScopeTypeConverter : JsonConverter<ModifiedScopeType>
{
    public override bool CanConvert(Type t) => t == typeof(ModifiedScopeType);

    public override ModifiedScopeType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "CHANGED" => ModifiedScopeType.Changed,
            "NOT_DEFINED" => ModifiedScopeType.NotDefined,
            "UNCHANGED" => ModifiedScopeType.Unchanged,
            _ => throw new Exception("Cannot unmarshal type ModifiedScopeType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ModifiedScopeType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ModifiedScopeType.Changed:
                JsonSerializer.Serialize(writer, "CHANGED", options);
                return;
            case ModifiedScopeType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            case ModifiedScopeType.Unchanged:
                JsonSerializer.Serialize(writer, "UNCHANGED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ModifiedScopeType");
        }
    }

    public static readonly ModifiedScopeTypeConverter Singleton = new();
}

public enum ModifiedUserInteractionType { None, NotDefined, Required };

internal class ModifiedUserInteractionTypeConverter : JsonConverter<ModifiedUserInteractionType>
{
    public override bool CanConvert(Type t) => t == typeof(ModifiedUserInteractionType);

    public override ModifiedUserInteractionType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NONE" => ModifiedUserInteractionType.None,
            "NOT_DEFINED" => ModifiedUserInteractionType.NotDefined,
            "REQUIRED" => ModifiedUserInteractionType.Required,
            _ => throw new Exception("Cannot unmarshal type ModifiedUserInteractionType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ModifiedUserInteractionType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ModifiedUserInteractionType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case ModifiedUserInteractionType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            case ModifiedUserInteractionType.Required:
                JsonSerializer.Serialize(writer, "REQUIRED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ModifiedUserInteractionType");
        }
    }

    public static readonly ModifiedUserInteractionTypeConverter Singleton = new();
}

public enum ConfidenceType { Confirmed, NotDefined, Reasonable, Unknown };

internal class ConfidenceTypeConverter : JsonConverter<ConfidenceType>
{
    public override bool CanConvert(Type t) => t == typeof(ConfidenceType);

    public override ConfidenceType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "CONFIRMED" => ConfidenceType.Confirmed,
            "NOT_DEFINED" => ConfidenceType.NotDefined,
            "REASONABLE" => ConfidenceType.Reasonable,
            "UNKNOWN" => ConfidenceType.Unknown,
            _ => throw new Exception("Cannot unmarshal type ConfidenceType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ConfidenceType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ConfidenceType.Confirmed:
                JsonSerializer.Serialize(writer, "CONFIRMED", options);
                return;
            case ConfidenceType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            case ConfidenceType.Reasonable:
                JsonSerializer.Serialize(writer, "REASONABLE", options);
                return;
            case ConfidenceType.Unknown:
                JsonSerializer.Serialize(writer, "UNKNOWN", options);
                return;
            default:
                throw new Exception("Cannot marshal type ConfidenceType");
        }
    }

    public static readonly ConfidenceTypeConverter Singleton = new();
}

public enum ScopeType { Changed, Unchanged };

internal class ScopeTypeConverter : JsonConverter<ScopeType>
{
    public override bool CanConvert(Type t) => t == typeof(ScopeType);

    public override ScopeType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "CHANGED" => ScopeType.Changed,
            "UNCHANGED" => ScopeType.Unchanged,
            _ => throw new Exception("Cannot unmarshal type ScopeType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ScopeType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ScopeType.Changed:
                JsonSerializer.Serialize(writer, "CHANGED", options);
                return;
            case ScopeType.Unchanged:
                JsonSerializer.Serialize(writer, "UNCHANGED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ScopeType");
        }
    }

    public static readonly ScopeTypeConverter Singleton = new();
}

public enum UserInteractionType { None, Required };

internal class UserInteractionTypeConverter : JsonConverter<UserInteractionType>
{
    public override bool CanConvert(Type t) => t == typeof(UserInteractionType);

    public override UserInteractionType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NONE" => UserInteractionType.None,
            "REQUIRED" => UserInteractionType.Required,
            _ => throw new Exception("Cannot unmarshal type UserInteractionType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, UserInteractionType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case UserInteractionType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case UserInteractionType.Required:
                JsonSerializer.Serialize(writer, "REQUIRED", options);
                return;
            default:
                throw new Exception("Cannot marshal type UserInteractionType");
        }
    }

    public static readonly UserInteractionTypeConverter Singleton = new();
}
