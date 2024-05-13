using System.CommandLine;
using System.Runtime.CompilerServices;
using Valleysoft.Nvd.Client;

namespace Valleysoft.NvdExplorer.Commands;

internal class CveOptions : OptionsBase
{
    private readonly Option<int?> _limitOption;
    private readonly Option<string?> _cpeOption;
    private readonly Option<string?> _idOption;
    private readonly Option<string?> _tagOption;
    private readonly Option<string?> _cvssV2MetricsOption;
    private readonly Option<CvssV2Severity?> _cvssV2SeverityOption;
    private readonly Option<string?> _cvssV3MetricsOption;
    private readonly Option<CvssV3Severity?> _cvssV3SeverityOption;
    private readonly Option<string?> _cvssV4MetricsOption;
    private readonly Option<CvssV4Severity?> _cvssV4SeverityOption;
    private readonly Option<string?> _cweIdOption;
    private readonly Option<bool> _hasCertAlertsOption;
    private readonly Option<bool> _hasCertNotesOption;
    private readonly Option<bool> _hasKevOption;
    private readonly Option<bool> _hasOvalOption;
    private readonly Option<bool> _isVulnerableOption;
    private readonly Option<string> _keywordSearchOption;
    private readonly Option<bool> _keywordExactMatchOption;

    public int? Limit { get; set; }

    public string? Cpe { get; set; }

    public string? Id { get; set; }

    public string? Tag { get; set; }

    public string? CvssV2Metrics { get; set; }

    public CvssV2Severity? CvssV2Severity { get; set; }

    public string? CvssV3Metrics { get; set; }

    public CvssV3Severity? CvssV3Severity { get; set; }

    public string? CvssV4Metrics { get; set; }

    public CvssV4Severity? CvssV4Severity { get; set; }

    public string? CweId { get; set; }

    public bool HasCertAlerts { get; set; }

    public bool HasCertNotes { get; set; }

    public bool HasKev { get; set; }

    public bool HasOval { get; set; }

    public bool IsVulnerable { get; set; }

    public string? KeywordSearch { get; set; }


    public CveOptions()
    {
        const string CpeOptionName = "--cpe";
        const string KeywordsOptionName = "--keywords";


        _limitOption = Add(new Option<int?>("--limit", "Maximum number of CVEs to include in the result"));
        _cpeOption = Add(new Option<string?>(CpeOptionName, "Returns CVEs associated with a specific Common Platform Enumeration (CPE) name"));
        _idOption = Add(new Option<string?>("--cve", "Returns a CVE by its CVE ID"));
        _tagOption = Add(new Option<string?>("--tag", "Returns CVEs that include the provided tag"));
        _cvssV2MetricsOption = Add(new Option<string?>("--cvss-v2", "Returns CVEs that match the provided CVSS v2 vector string"));
        _cvssV2SeverityOption = Add(new Option<CvssV2Severity?>("--cvss-v2-severity", "Returns CVEs that match the provided CVSS v2 qualitative severity rating"));
        _cvssV3MetricsOption = Add(new Option<string?>("--cvss-v3", "Returns CVEs that match the provided CVSS v3 vector string"));
        _cvssV3SeverityOption = Add(new Option<CvssV3Severity?>("--cvss-v3-severity", "Returns CVEs that match the provided CVSS v3 qualitative severity rating"));
        _cvssV4MetricsOption = Add(new Option<string?>("--cvss-v4", "Returns CVEs that match the provided CVSS v4 vector string"));
        _cvssV4SeverityOption = Add(new Option<CvssV4Severity?>("--cvss-v4-severity", "Returns CVEs that match the provided CVSS v4 qualitative severity rating"));
        _cweIdOption = Add(new Option<string?>("--cwe", "Returns CVEs that include a weakness identified by the Common Weakness Enumeration (CWE) ID"));
        _hasCertAlertsOption = Add(new Option<bool>("--cert-alerts", "Returns CVEs that contain a Technical Alert from US-CERT"));
        _hasCertNotesOption = Add(new Option<bool>("--cert-notes", "Returns CVEs that contain a Vulnerability Note from CERT/CC"));
        _hasKevOption = Add(new Option<bool>("--kev", "Returns CVEs that appear in CISA's Known Exploited Vulnerabilities (KEV) Catalog"));
        _hasOvalOption = Add(new Option<bool>("--oval", "Returns CVEs that contain information from MITRE's Open Vulnerability and Assessment Language (OVAL)"));
        _isVulnerableOption = Add(new Option<bool>("--vulnerable", $"Returns CVEs associated with a CPE that is considered vulnerable (must be used with {CpeOptionName})"));
        _keywordSearchOption = Add(new Option<string>(KeywordsOptionName, "Returns CVEs that contain the provided keywords in the description"));
        _keywordExactMatchOption = Add(new Option<bool>("--exact-match", $"Modifies the keyword search to find an exact match (must be used with {KeywordsOptionName})"));
    }

    protected override void GetValues()
    {
        Limit = GetValue(_limitOption);
        Cpe = GetValue(_cpeOption);
        Id = GetValue(_idOption);
        Tag = GetValue(_tagOption);
        CvssV2Metrics = GetValue(_cvssV2MetricsOption);
        CvssV2Severity = GetValue(_cvssV2SeverityOption);
        CvssV3Metrics = GetValue(_cvssV3MetricsOption);
        CvssV3Severity = GetValue(_cvssV3SeverityOption);
        CvssV4Metrics = GetValue(_cvssV4MetricsOption);
        CvssV4Severity = GetValue(_cvssV4SeverityOption);
        CweId = GetValue(_cweIdOption);
        HasCertAlerts = GetValue(_hasCertAlertsOption);
        HasCertNotes = GetValue(_hasCertNotesOption);
        HasKev = GetValue(_hasKevOption);
        HasOval = GetValue(_hasOvalOption);
        IsVulnerable = GetValue(_isVulnerableOption);
        KeywordSearch = GetValue(_keywordSearchOption);
    }
}
