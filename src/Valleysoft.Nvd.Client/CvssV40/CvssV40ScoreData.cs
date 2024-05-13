using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Valleysoft.Nvd.Client.CvssV40;

public class CvssV40ScoreData
{
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("attackComplexity")]
    public AttackComplexityType? AttackComplexity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("attackRequirements")]
    public AttackRequirementsType? AttackRequirements { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("attackVector")]
    public AttackVectorType? AttackVector { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("availabilityRequirement")]
    public CiaRequirementType? AvailabilityRequirement { get; set; }

    [JsonPropertyName("baseScore")]
    [JsonConverter(typeof(MinMaxValueCheckConverter))]
    public double BaseScore { get; set; }

    [JsonPropertyName("baseSeverity")]
    public SeverityType BaseSeverity { get; set; }

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
    [JsonPropertyName("integrityRequirement")]
    public CiaRequirementType? IntegrityRequirement { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedAttackComplexity")]
    public ModifiedAttackComplexityType? ModifiedAttackComplexity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedAttackRequirements")]
    public ModifiedAttackRequirementsType? ModifiedAttackRequirements { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedAttackVector")]
    public ModifiedAttackVectorType? ModifiedAttackVector { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedPrivilegesRequired")]
    public ModifiedType? ModifiedPrivilegesRequired { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedUserInteraction")]
    public ModifiedUserInteractionType? ModifiedUserInteraction { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedVulnConfidentialityImpact")]
    public ModifiedVulnerabilityCiaType? ModifiedVulnerabilityConfidentialityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedVulnIntegrityImpact")]
    public ModifiedVulnerabilityCiaType? ModifiedVulnerabilityIntegrityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedVulnAvailabilityImpact")]
    public ModifiedVulnerabilityCiaType? ModifiedVulnerabilityAvailabilityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedSubConfidentialityImpact")]
    public ModifiedSubCiaType? ModifiedSubConfidentialityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedSubIntegrityImpact")]
    public ModifiedSubIaType? ModifiedSubIntegrityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("modifiedSubAvailabilityImpact")]
    public ModifiedSubIaType? ModifiedSubAvailabilityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("privilegesRequired")]
    public AvailabilityImpactType? PrivilegesRequired { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("userInteraction")]
    public UserInteractionType? UserInteraction { get; set; }

    [JsonPropertyName("vectorString")]
    public required string VectorString { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("vulnConfidentialityImpact")]
    public VulnerabilityCiaType? VulnerabilityConfidentialityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("vulnIntegrityImpact")]
    public VulnerabilityCiaType? VulnerabilityIntegrityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("vulnAvailabilityImpact")]
    public VulnerabilityCiaType? VulnerabilityAvailabilityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("subConfidentialityImpact")]
    public SubCiaType? SubConfidentialityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("subIntegrityImpact")]
    public SubCiaType? SubIntegrityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("subAvailabilityImpact")]
    public SubCiaType? SubAvailabilityImpact { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("exploitMaturity")]
    public ExploitMaturityType? ExploitMaturity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("Safety")]
    public SafetyType? Safety { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("Automatable")]
    public AutomatableType? Automatable { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("Recovery")]
    public RecoveryType? Recovery { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("valueDensity")]
    public ValueDensityType? ValueDensity { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("vulnerabilityResponseEffort")]
    public VulnerabilityResponseEffortType? VulnerabilityResponseEffort { get; set; }

    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [JsonPropertyName("providerUrgency")]
    public ProviderUrgencyType? ProviderUrgency { get; set; }

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
