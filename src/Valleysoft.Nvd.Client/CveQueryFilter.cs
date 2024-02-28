namespace Valleysoft.Nvd.Client;

public class CveQueryFilter
{
    public string? CpeName { get; set; }
    public string? CveId { get; set; }
    public string? CweId { get; set; }
    public string? CvssV2Metrics { get; set; }
    public string? CvssV3Metrics { get; set; }
    public CvssV2Severity? CvssV2Severity { get; set; }
    public CvssV3Severity? CvssV3Severity { get; set; }
    public bool HasCertAlerts { get; set; }
    public bool HasCertNotes { get; set; }
    public bool HasKev { get; set; }
    public bool HasOval { get; set; }
    public bool IsVulnerable { get; set; }
    public bool IsKeywordExactMatch { get; set; }
    public string[] Keywords { get; set; } = [];
    public bool ExcludeRejected { get; set; }
    public DateTimeRange? LastModified { get; set; }
    public DateTimeRange? Published { get; set; }
    public int? ResultsPerPage { get; set; }
    public int? StartIndex { get; set; }
    public string? SourceIdentifier { get; set; }
    public VirtualMatch? VirtualMatch { get; set; }
}

public enum CvssV2Severity
{
    Low,
    Medium,
    High
}

public enum CvssV3Severity
{
    Low,
    Medium,
    High,
    Critical
}

public struct DateTimeRange
{
    public DateTimeOffset Start { get; set; }
    public DateTimeOffset End { get; set; }
}

public class VirtualMatch(string matchValue, VirtualMatchVersion? startVersion, VirtualMatchVersion? endVersion)
{
    public string MatchValue { get; } = matchValue;
    public VirtualMatchVersion? StartVersion { get; } = startVersion;
    public VirtualMatchVersion? EndVersion { get; } = endVersion;
}

public class VirtualMatchVersion(string version, VirtualMatchVersionType type)
{
    public string Version { get; } = version;
    public VirtualMatchVersionType Type { get; } = type;
}

public enum VirtualMatchVersionType
{
    Include,
    Exclude
}
