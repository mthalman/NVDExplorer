using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using Valleysoft.Nvd.Client.CvssV2;
using Valleysoft.Nvd.Client.CvssV30;
using Valleysoft.Nvd.Client.CvssV31;

namespace Valleysoft.Nvd.Client;

public class CveQueryResult : QueryResult
{
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

    [JsonPropertyName("cveTags")]
    public CveTag[] Tags { get; set; } = [];

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
    public required LanguageValue[] Descriptions { get; set; } = [];

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

public class CveTag
{
    [JsonPropertyName("sourceIdentifier")]
    public required string Source { get; set; }

    [JsonPropertyName("tags")]
    public string[] Tags { get; set; } = [];
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
    public required LanguageValue[] Description { get; set; } = [];
}

public class LanguageValue : ILanguageValue
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
    public required CvssV40ScoreData CvssData { get; set; }

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

public enum AttackRequirementsType { None, Present };

internal class AttackRequirementsTypeConverter : JsonConverter<AttackRequirementsType>
{
    public override bool CanConvert(Type t) => t == typeof(AttackRequirementsType);

    public override AttackRequirementsType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NONE" => AttackRequirementsType.None,
            "PRESENT" => AttackRequirementsType.Present,
            _ => throw new Exception("Cannot unmarshal type AttackRequirementsType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, AttackRequirementsType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case AttackRequirementsType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case AttackRequirementsType.Present:
                JsonSerializer.Serialize(writer, "PRESENT", options);
                return;
            default:
                throw new Exception("Cannot marshal type AttackRequirementsType");
        }
    }

    public static readonly AttackRequirementsTypeConverter Singleton = new();
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

public enum AvailabilityImpactType { High, Low, None };

internal class AvailabilityImpactEnumConverter : JsonConverter<AvailabilityImpactType>
{
    public override bool CanConvert(Type t) => t == typeof(AvailabilityImpactType);

    public override AvailabilityImpactType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "HIGH" => AvailabilityImpactType.High,
            "LOW" => AvailabilityImpactType.Low,
            "NONE" => AvailabilityImpactType.None,
            _ => throw new Exception("Cannot unmarshal type AvailabilityImpactEnum"),
        };
    }

    public override void Write(Utf8JsonWriter writer, AvailabilityImpactType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case AvailabilityImpactType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case AvailabilityImpactType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case AvailabilityImpactType.None:
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

public enum ModifiedAttackRequirementsType { None, Present, NotDefined };

internal class ModifiedAttackRequirementsTypeConverter : JsonConverter<ModifiedAttackRequirementsType>
{
    public override bool CanConvert(Type t) => t == typeof(ModifiedAttackRequirementsType);

    public override ModifiedAttackRequirementsType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NONE" => ModifiedAttackRequirementsType.None,
            "PRESENT" => ModifiedAttackRequirementsType.Present,
            "NOT_DEFINED" => ModifiedAttackRequirementsType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type ModifiedAttackRequirementsType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ModifiedAttackRequirementsType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ModifiedAttackRequirementsType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case ModifiedAttackRequirementsType.Present:
                JsonSerializer.Serialize(writer, "PRESENT", options);
                return;
            case ModifiedAttackRequirementsType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ModifiedAttackRequirementsType");
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

public enum VulnerabilityCiaType { None, Low, High };

internal class VulnerabilityCiaTypeConverter : JsonConverter<VulnerabilityCiaType>
{
    public override bool CanConvert(Type t) => t == typeof(VulnerabilityCiaType);

    public override VulnerabilityCiaType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NONE" => VulnerabilityCiaType.None,
            "LOW" => VulnerabilityCiaType.Low,
            "HIGH" => VulnerabilityCiaType.High,
            _ => throw new Exception("Cannot unmarshal type VulnerabilityCiaType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, VulnerabilityCiaType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case VulnerabilityCiaType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case VulnerabilityCiaType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case VulnerabilityCiaType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            default:
                throw new Exception("Cannot marshal type VulnerabilityCiaType");
        }
    }

    public static readonly VulnerabilityCiaTypeConverter Singleton = new();
}

public enum ModifiedVulnerabilityCiaType { None, Low, High, NotDefined };

internal class ModifiedVulnerabilityCiaTypeConverter : JsonConverter<ModifiedVulnerabilityCiaType>
{
    public override bool CanConvert(Type t) => t == typeof(ModifiedVulnerabilityCiaType);

    public override ModifiedVulnerabilityCiaType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NONE" => ModifiedVulnerabilityCiaType.None,
            "LOW" => ModifiedVulnerabilityCiaType.Low,
            "HIGH" => ModifiedVulnerabilityCiaType.High,
            "NOT_DEFINED" => ModifiedVulnerabilityCiaType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type ModifiedVulnerabilityCiaType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ModifiedVulnerabilityCiaType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ModifiedVulnerabilityCiaType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case ModifiedVulnerabilityCiaType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case ModifiedVulnerabilityCiaType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case ModifiedVulnerabilityCiaType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ModifiedVulnerabilityCiaType");
        }
    }

    public static readonly ModifiedVulnerabilityCiaTypeConverter Singleton = new();
}

public enum SubCiaType { None, Low, High };

internal class SubCiaTypeConverter : JsonConverter<SubCiaType>
{
    public override bool CanConvert(Type t) => t == typeof(SubCiaType);

    public override SubCiaType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NONE" => SubCiaType.None,
            "LOW" => SubCiaType.Low,
            "HIGH" => SubCiaType.High,
            _ => throw new Exception("Cannot unmarshal type SubCiaType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, SubCiaType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case SubCiaType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case SubCiaType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case SubCiaType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            default:
                throw new Exception("Cannot marshal type SubCiaType");
        }
    }

    public static readonly SubCiaTypeConverter Singleton = new();
}

public enum ModifiedSubCiaType { Negligible, Low, High, NotDefined };

internal class ModifiedSubCiaTypeConverter : JsonConverter<ModifiedSubCiaType>
{
    public override bool CanConvert(Type t) => t == typeof(ModifiedSubCiaType);

    public override ModifiedSubCiaType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NEGLIGIBLE" => ModifiedSubCiaType.Negligible,
            "LOW" => ModifiedSubCiaType.Low,
            "HIGH" => ModifiedSubCiaType.High,
            "NOT_DEFINED" => ModifiedSubCiaType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type ModifiedSubCiaType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ModifiedSubCiaType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ModifiedSubCiaType.Negligible:
                JsonSerializer.Serialize(writer, "NEGLIGIBLE", options);
                return;
            case ModifiedSubCiaType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case ModifiedSubCiaType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case ModifiedSubCiaType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ModifiedSubCiaType");
        }
    }

    public static readonly ModifiedSubCiaTypeConverter Singleton = new();
}

public enum ModifiedSubIaType { Negligible, Low, High, Safety, NotDefined };

internal class ModifiedSubIaTypeConverter : JsonConverter<ModifiedSubIaType>
{
    public override bool CanConvert(Type t) => t == typeof(ModifiedSubIaType);

    public override ModifiedSubIaType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NEGLIGIBLE" => ModifiedSubIaType.Negligible,
            "LOW" => ModifiedSubIaType.Low,
            "HIGH" => ModifiedSubIaType.High,
            "SAFETY" => ModifiedSubIaType.Safety,
            "NOT_DEFINED" => ModifiedSubIaType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type ModifiedSubIaType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ModifiedSubIaType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ModifiedSubIaType.Negligible:
                JsonSerializer.Serialize(writer, "NEGLIGIBLE", options);
                return;
            case ModifiedSubIaType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case ModifiedSubIaType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case ModifiedSubIaType.Safety:
                JsonSerializer.Serialize(writer, "SAFETY", options);
                return;
            case ModifiedSubIaType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ModifiedSubIaType");
        }
    }

    public static readonly ModifiedSubIaTypeConverter Singleton = new();
}

public enum ExploitMaturityType { Unreported, ProofOfConcept, Attacked, NotDefined };

internal class ExploitMaturityTypeConverter : JsonConverter<ExploitMaturityType>
{
    public override bool CanConvert(Type t) => t == typeof(ExploitMaturityType);

    public override ExploitMaturityType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "UNREPORTED" => ExploitMaturityType.Unreported,
            "PROOF_OF_CONCEPT" => ExploitMaturityType.ProofOfConcept,
            "ATTACKED" => ExploitMaturityType.Attacked,
            "NOT_DEFINED" => ExploitMaturityType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type ExploitMaturityType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ExploitMaturityType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ExploitMaturityType.Unreported:
                JsonSerializer.Serialize(writer, "UNREPORTED", options);
                return;
            case ExploitMaturityType.ProofOfConcept:
                JsonSerializer.Serialize(writer, "PROOF_OF_CONCEPT", options);
                return;
            case ExploitMaturityType.Attacked:
                JsonSerializer.Serialize(writer, "ATTACKED", options);
                return;
            case ExploitMaturityType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ExploitMaturityType");
        }
    }

    public static readonly ExploitMaturityTypeConverter Singleton = new();
}

public enum SafetyType { Negligible, Present, NotDefined };

internal class SafetyTypeConverter : JsonConverter<SafetyType>
{
    public override bool CanConvert(Type t) => t == typeof(SafetyType);

    public override SafetyType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NEGLIGIBLE" => SafetyType.Negligible,
            "PRESENT" => SafetyType.Present,
            "NOT_DEFINED" => SafetyType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type SafetyType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, SafetyType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case SafetyType.Negligible:
                JsonSerializer.Serialize(writer, "NEGLIGIBLE", options);
                return;
            case SafetyType.Present:
                JsonSerializer.Serialize(writer, "PRESENT", options);
                return;
            case SafetyType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type SafetyType");
        }
    }

    public static readonly SafetyTypeConverter Singleton = new();
}

public enum AutomatableType { NotDefined, No, Yes};

internal class AutomatableTypeConverter : JsonConverter<AutomatableType>
{
    public override bool CanConvert(Type t) => t == typeof(AutomatableType);

    public override AutomatableType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "NO" => AutomatableType.No,
            "YES" => AutomatableType.Yes,
            "NOT_DEFINED" => AutomatableType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type AutomatableType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, AutomatableType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case AutomatableType.No:
                JsonSerializer.Serialize(writer, "NO", options);
                return;
            case AutomatableType.Yes:
                JsonSerializer.Serialize(writer, "YES", options);
                return;
            case AutomatableType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type AutomatableType");
        }
    }

    public static readonly AutomatableTypeConverter Singleton = new();
}

public enum RecoveryType { NotDefined, Automatic, User, Irrecoverable };

internal class RecoveryTypeConverter : JsonConverter<RecoveryType>
{
    public override bool CanConvert(Type t) => t == typeof(RecoveryType);

    public override RecoveryType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "AUTOMATIC" => RecoveryType.Automatic,
            "USER" => RecoveryType.User,
            "IRRECOVERABLE" => RecoveryType.Irrecoverable,
            "NOT_DEFINED" => RecoveryType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type RecoveryType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, RecoveryType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case RecoveryType.Automatic:
                JsonSerializer.Serialize(writer, "AUTOMATIC", options);
                return;
            case RecoveryType.User:
                JsonSerializer.Serialize(writer, "USER", options);
                return;
            case RecoveryType.Irrecoverable:
                JsonSerializer.Serialize(writer, "IRRECOVERABLE", options);
                return;
            case RecoveryType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type RecoveryType");
        }
    }

    public static readonly RecoveryTypeConverter Singleton = new();
}

public enum ValueDensityType { NotDefined, Diffuse, Concentrated };

internal class ValueDensityTypeConverter : JsonConverter<ValueDensityType>
{
    public override bool CanConvert(Type t) => t == typeof(ValueDensityType);

    public override ValueDensityType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "DIFFUSE" => ValueDensityType.Diffuse,
            "CONCENTRATED" => ValueDensityType.Concentrated,
            "NOT_DEFINED" => ValueDensityType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type ValueDensityType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ValueDensityType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ValueDensityType.Diffuse:
                JsonSerializer.Serialize(writer, "DIFFUSE", options);
                return;
            case ValueDensityType.Concentrated:
                JsonSerializer.Serialize(writer, "CONCENTRATED", options);
                return;
            case ValueDensityType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ValueDensityType");
        }
    }

    public static readonly ValueDensityTypeConverter Singleton = new();
}

public enum VulnerabilityResponseEffortType { NotDefined, Low, Moderate, High };

internal class VulnerabilityResponseEffortTypeConverter : JsonConverter<VulnerabilityResponseEffortType>
{
    public override bool CanConvert(Type t) => t == typeof(VulnerabilityResponseEffortType);

    public override VulnerabilityResponseEffortType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "LOW" => VulnerabilityResponseEffortType.Low,
            "MODERATE" => VulnerabilityResponseEffortType.Moderate,
            "HIGH" => VulnerabilityResponseEffortType.High,
            "NOT_DEFINED" => VulnerabilityResponseEffortType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type VulnerabilityResponseEffortType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, VulnerabilityResponseEffortType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case VulnerabilityResponseEffortType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case VulnerabilityResponseEffortType.Moderate:
                JsonSerializer.Serialize(writer, "MODERATE", options);
                return;
            case VulnerabilityResponseEffortType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case VulnerabilityResponseEffortType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type VulnerabilityResponseEffortType");
        }
    }

    public static readonly VulnerabilityResponseEffortTypeConverter Singleton = new();
}

public enum ProviderUrgencyType { NotDefined, Clear, Green, Amber, Red };

internal class ProviderUrgencyTypeConverter : JsonConverter<ProviderUrgencyType>
{
    public override bool CanConvert(Type t) => t == typeof(ProviderUrgencyType);

    public override ProviderUrgencyType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "CLEAR" => ProviderUrgencyType.Clear,
            "GREEN" => ProviderUrgencyType.Green,
            "AMBER" => ProviderUrgencyType.Amber,
            "RED" => ProviderUrgencyType.Red,
            "NOT_DEFINED" => ProviderUrgencyType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type ProviderUrgencyType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ProviderUrgencyType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ProviderUrgencyType.Clear:
                JsonSerializer.Serialize(writer, "CLEAR", options);
                return;
            case ProviderUrgencyType.Green:
                JsonSerializer.Serialize(writer, "GREEN", options);
                return;
            case ProviderUrgencyType.Amber:
                JsonSerializer.Serialize(writer, "AMBER", options);
                return;
            case ProviderUrgencyType.Red:
                JsonSerializer.Serialize(writer, "RED", options);
                return;
            case ProviderUrgencyType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ProviderUrgencyType");
        }
    }

    public static readonly ProviderUrgencyTypeConverter Singleton = new();
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
