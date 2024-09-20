using System.Text.Json;
using System.Text.Json.Serialization;

namespace Valleysoft.Nvd.Client.CvssV2;

public class CvssV2ScoreData
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("accessComplexity")]
    public AccessComplexityType? AccessComplexity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("accessVector")]
    public AccessVectorType? AccessVector { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("authentication")]
    public AuthenticationType? Authentication { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("availabilityImpact")]
    public CiaType? AvailabilityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("availabilityRequirement")]
    public CiaRequirementType? AvailabilityRequirement { get; set; }

    [JsonPropertyName("baseScore")]
    [JsonConverter(typeof(MinMaxValueCheckConverter))]
    public double BaseScore { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("collateralDamagePotential")]
    public CollateralDamagePotentialType? CollateralDamagePotential { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("confidentialityImpact")]
    public CiaType? ConfidentialityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("confidentialityRequirement")]
    public CiaRequirementType? ConfidentialityRequirement { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("environmentalScore")]
    [JsonConverter(typeof(MinMaxValueCheckConverter))]
    public double? EnvironmentalScore { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("exploitability")]
    public ExploitabilityType? Exploitability { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("integrityImpact")]
    public CiaType? IntegrityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("integrityRequirement")]
    public CiaRequirementType? IntegrityRequirement { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("remediationLevel")]
    public RemediationLevelType? RemediationLevel { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("reportConfidence")]
    public ReportConfidenceType? ReportConfidence { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("targetDistribution")]
    public TargetDistributionType? TargetDistribution { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("temporalScore")]
    [JsonConverter(typeof(MinMaxValueCheckConverter))]
    public double? TemporalScore { get; set; }

    [JsonPropertyName("vectorString")]
    public required string VectorString { get; set; }

    /// <summary>
    /// CVSS Version
    /// </summary>
    [JsonPropertyName("version")]
    public CvssVersion Version { get; set; }
}

public enum AccessComplexityType { High, Low, Medium };

public enum AccessVectorType { AdjacentNetwork, Local, Network };

public enum AuthenticationType { Multiple, None, Single };

public enum CiaType { Complete, None, Partial };

public enum CollateralDamagePotentialType { High, Low, LowMedium, MediumHigh, None, NotDefined };

public enum ExploitabilityType { Functional, High, NotDefined, ProofOfConcept, Unproven };

public enum ReportConfidenceType { Confirmed, NotDefined, Unconfirmed, Uncorroborated };

public enum TargetDistributionType { High, Low, Medium, None, NotDefined };

internal class AccessComplexityTypeConverter : JsonConverter<AccessComplexityType>
{
    public override bool CanConvert(Type t) => t == typeof(AccessComplexityType);

    public override AccessComplexityType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "HIGH" => AccessComplexityType.High,
            "LOW" => AccessComplexityType.Low,
            "MEDIUM" => AccessComplexityType.Medium,
            _ => throw new Exception("Cannot unmarshal type AccessComplexityType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, AccessComplexityType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case AccessComplexityType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case AccessComplexityType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case AccessComplexityType.Medium:
                JsonSerializer.Serialize(writer, "MEDIUM", options);
                return;
            default:
                throw new Exception("Cannot marshal type AccessComplexityType");
        }
    }

    public static readonly AccessComplexityTypeConverter Singleton = new();
}

internal class AccessVectorTypeConverter : JsonConverter<AccessVectorType>
{
    public override bool CanConvert(Type t) => t == typeof(AccessVectorType);

    public override AccessVectorType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "ADJACENT_NETWORK" => AccessVectorType.AdjacentNetwork,
            "LOCAL" => AccessVectorType.Local,
            "NETWORK" => AccessVectorType.Network,
            _ => throw new Exception("Cannot unmarshal type AccessVectorType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, AccessVectorType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case AccessVectorType.AdjacentNetwork:
                JsonSerializer.Serialize(writer, "ADJACENT_NETWORK", options);
                return;
            case AccessVectorType.Local:
                JsonSerializer.Serialize(writer, "LOCAL", options);
                return;
            case AccessVectorType.Network:
                JsonSerializer.Serialize(writer, "NETWORK", options);
                return;
            default:
                throw new Exception("Cannot marshal type AccessVectorType");
        }
    }

    public static readonly AccessVectorTypeConverter Singleton = new();
}

internal class AuthenticationTypeConverter : JsonConverter<AuthenticationType>
{
    public override bool CanConvert(Type t) => t == typeof(AuthenticationType);

    public override AuthenticationType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "MULTIPLE" => AuthenticationType.Multiple,
            "NONE" => AuthenticationType.None,
            "SINGLE" => AuthenticationType.Single,
            _ => throw new Exception("Cannot unmarshal type AuthenticationType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, AuthenticationType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case AuthenticationType.Multiple:
                JsonSerializer.Serialize(writer, "MULTIPLE", options);
                return;
            case AuthenticationType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case AuthenticationType.Single:
                JsonSerializer.Serialize(writer, "SINGLE", options);
                return;
            default:
                throw new Exception("Cannot marshal type AuthenticationType");
        }
    }

    public static readonly AuthenticationTypeConverter Singleton = new();
}

internal class CiaTypeConverter : JsonConverter<CiaType>
{
    public override bool CanConvert(Type t) => t == typeof(CiaType);

    public override CiaType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "COMPLETE" => CiaType.Complete,
            "NONE" => CiaType.None,
            "PARTIAL" => CiaType.Partial,
            _ => throw new Exception("Cannot unmarshal type CiaType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, CiaType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case CiaType.Complete:
                JsonSerializer.Serialize(writer, "COMPLETE", options);
                return;
            case CiaType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case CiaType.Partial:
                JsonSerializer.Serialize(writer, "PARTIAL", options);
                return;
            default:
                throw new Exception("Cannot marshal type CiaType");
        }
    }

    public static readonly CiaTypeConverter Singleton = new();
}

internal class MinMaxValueCheckConverter : JsonConverter<double>
{
    public override bool CanConvert(Type t) => t == typeof(double);

    public override double Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        double value = reader.GetDouble();
        if (value >= 0 && value <= 10)
        {
            return value;
        }
        throw new Exception("Cannot unmarshal type double");
    }

    public override void Write(Utf8JsonWriter writer, double value, JsonSerializerOptions options)
    {
        if (value >= 0 && value <= 10)
        {
            JsonSerializer.Serialize(writer, value, options);
            return;
        }
        throw new Exception("Cannot marshal type double");
    }

    public static readonly MinMaxValueCheckConverter Singleton = new();
}

internal class CollateralDamagePotentialTypeConverter : JsonConverter<CollateralDamagePotentialType>
{
    public override bool CanConvert(Type t) => t == typeof(CollateralDamagePotentialType);

    public override CollateralDamagePotentialType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "HIGH" => CollateralDamagePotentialType.High,
            "LOW" => CollateralDamagePotentialType.Low,
            "LOW_MEDIUM" => CollateralDamagePotentialType.LowMedium,
            "MEDIUM_HIGH" => CollateralDamagePotentialType.MediumHigh,
            "NONE" => CollateralDamagePotentialType.None,
            "NOT_DEFINED" => CollateralDamagePotentialType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type CollateralDamagePotentialType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, CollateralDamagePotentialType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case CollateralDamagePotentialType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case CollateralDamagePotentialType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case CollateralDamagePotentialType.LowMedium:
                JsonSerializer.Serialize(writer, "LOW_MEDIUM", options);
                return;
            case CollateralDamagePotentialType.MediumHigh:
                JsonSerializer.Serialize(writer, "MEDIUM_HIGH", options);
                return;
            case CollateralDamagePotentialType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case CollateralDamagePotentialType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type CollateralDamagePotentialType");
        }
    }

    public static readonly CollateralDamagePotentialTypeConverter Singleton = new();
}

internal class ExploitabilityTypeConverter : JsonConverter<ExploitabilityType>
{
    public override bool CanConvert(Type t) => t == typeof(ExploitabilityType);

    public override ExploitabilityType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "FUNCTIONAL" => ExploitabilityType.Functional,
            "HIGH" => ExploitabilityType.High,
            "NOT_DEFINED" => ExploitabilityType.NotDefined,
            "PROOF_OF_CONCEPT" => ExploitabilityType.ProofOfConcept,
            "UNPROVEN" => ExploitabilityType.Unproven,
            _ => throw new Exception("Cannot unmarshal type ExploitabilityType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ExploitabilityType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ExploitabilityType.Functional:
                JsonSerializer.Serialize(writer, "FUNCTIONAL", options);
                return;
            case ExploitabilityType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case ExploitabilityType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            case ExploitabilityType.ProofOfConcept:
                JsonSerializer.Serialize(writer, "PROOF_OF_CONCEPT", options);
                return;
            case ExploitabilityType.Unproven:
                JsonSerializer.Serialize(writer, "UNPROVEN", options);
                return;
            default:
                throw new Exception("Cannot marshal type ExploitabilityType");
        }
    }

    public static readonly ExploitabilityTypeConverter Singleton = new();
}

internal class ReportConfidenceTypeConverter : JsonConverter<ReportConfidenceType>
{
    public override bool CanConvert(Type t) => t == typeof(ReportConfidenceType);

    public override ReportConfidenceType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "CONFIRMED" => ReportConfidenceType.Confirmed,
            "NOT_DEFINED" => ReportConfidenceType.NotDefined,
            "UNCONFIRMED" => ReportConfidenceType.Unconfirmed,
            "UNCORROBORATED" => ReportConfidenceType.Uncorroborated,
            _ => throw new Exception("Cannot unmarshal type ReportConfidenceType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, ReportConfidenceType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case ReportConfidenceType.Confirmed:
                JsonSerializer.Serialize(writer, "CONFIRMED", options);
                return;
            case ReportConfidenceType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            case ReportConfidenceType.Unconfirmed:
                JsonSerializer.Serialize(writer, "UNCONFIRMED", options);
                return;
            case ReportConfidenceType.Uncorroborated:
                JsonSerializer.Serialize(writer, "UNCORROBORATED", options);
                return;
            default:
                throw new Exception("Cannot marshal type ReportConfidenceType");
        }
    }

    public static readonly ReportConfidenceTypeConverter Singleton = new();
}

internal class TargetDistributionTypeConverter : JsonConverter<TargetDistributionType>
{
    public override bool CanConvert(Type t) => t == typeof(TargetDistributionType);

    public override TargetDistributionType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? value = reader.GetString();
        return value switch
        {
            "HIGH" => TargetDistributionType.High,
            "LOW" => TargetDistributionType.Low,
            "MEDIUM" => TargetDistributionType.Medium,
            "NONE" => TargetDistributionType.None,
            "NOT_DEFINED" => TargetDistributionType.NotDefined,
            _ => throw new Exception("Cannot unmarshal type TargetDistributionType"),
        };
    }

    public override void Write(Utf8JsonWriter writer, TargetDistributionType value, JsonSerializerOptions options)
    {
        switch (value)
        {
            case TargetDistributionType.High:
                JsonSerializer.Serialize(writer, "HIGH", options);
                return;
            case TargetDistributionType.Low:
                JsonSerializer.Serialize(writer, "LOW", options);
                return;
            case TargetDistributionType.Medium:
                JsonSerializer.Serialize(writer, "MEDIUM", options);
                return;
            case TargetDistributionType.None:
                JsonSerializer.Serialize(writer, "NONE", options);
                return;
            case TargetDistributionType.NotDefined:
                JsonSerializer.Serialize(writer, "NOT_DEFINED", options);
                return;
            default:
                throw new Exception("Cannot marshal type TargetDistributionType");
        }
    }

    public static readonly TargetDistributionTypeConverter Singleton = new();
}

