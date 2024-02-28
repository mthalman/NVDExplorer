using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Valleysoft.Nvd.Client.CvssV31;

public partial class CvssV31ScoreData
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("attackComplexity")]
    public AttackComplexityType? AttackComplexity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("attackVector")]
    public AttackVectorType? AttackVector { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("availabilityImpact")]
    public AvailabilityImpactEnum? AvailabilityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("availabilityRequirement")]
    public CiaRequirementType? AvailabilityRequirement { get; set; }

    [JsonPropertyName("baseScore")]
    [JsonConverter(typeof(MinMaxValueCheckConverter))]
    public double BaseScore { get; set; }

    [JsonPropertyName("baseSeverity")]
    public SeverityType BaseSeverity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("confidentialityImpact")]
    public AvailabilityImpactEnum? ConfidentialityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("confidentialityRequirement")]
    public CiaRequirementType? ConfidentialityRequirement { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("environmentalScore")]
    [JsonConverter(typeof(MinMaxValueCheckConverter))]
    public double? EnvironmentalScore { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("environmentalSeverity")]
    public SeverityType? EnvironmentalSeverity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("exploitCodeMaturity")]
    public ExploitCodeMaturityType? ExploitCodeMaturity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("integrityImpact")]
    public AvailabilityImpactEnum? IntegrityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("integrityRequirement")]
    public CiaRequirementType? IntegrityRequirement { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedAttackComplexity")]
    public ModifiedAttackComplexityType? ModifiedAttackComplexity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedAttackVector")]
    public ModifiedAttackVectorType? ModifiedAttackVector { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedAvailabilityImpact")]
    public ModifiedType? ModifiedAvailabilityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedConfidentialityImpact")]
    public ModifiedType? ModifiedConfidentialityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedIntegrityImpact")]
    public ModifiedType? ModifiedIntegrityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedPrivilegesRequired")]
    public ModifiedType? ModifiedPrivilegesRequired { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedScope")]
    public ModifiedScopeType? ModifiedScope { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedUserInteraction")]
    public ModifiedUserInteractionType? ModifiedUserInteraction { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("privilegesRequired")]
    public AvailabilityImpactEnum? PrivilegesRequired { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("remediationLevel")]
    public RemediationLevelType? RemediationLevel { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("reportConfidence")]
    public ConfidenceType? ReportConfidence { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("scope")]
    public ScopeType? Scope { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("temporalScore")]
    [JsonConverter(typeof(MinMaxValueCheckConverter))]
    public double? TemporalScore { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("temporalSeverity")]
    public SeverityType? TemporalSeverity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("userInteraction")]
    public UserInteractionType? UserInteraction { get; set; }

    [JsonPropertyName("vectorString")]
    public required string VectorString { get; set; }

    /// <summary>
    /// CVSS Version
    /// </summary>
    [JsonPropertyName("version")]
    public CvssVersion Version { get; set; }
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
