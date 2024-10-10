using System.CommandLine;
using System.Text.Json;
using Valleysoft.Nvd.Client;

namespace Valleysoft.NvdExplorer.Commands;

internal class CveCommand(NvdClient client, IConsole console) : CommandWithOptions<CveOptions>("cve", "Queries the Common Vulnerabilities and Exposures (CVE) database")
{
    private const int MaxResultsPerRequest = 2000;
    private readonly NvdClient _client = client;
    private readonly IConsole _console = console;
    private readonly JsonSerializerOptions _options = new()
    {
        WriteIndented = true
    };

    protected override async Task ExecuteAsync()
    {
        CveQueryFilter filter = new()
        {
            CveId = Options.Id,
            CpeName = Options.Cpe,
            CveTag = Options.Tag,
            CvssV2Metrics = Options.CvssV2Metrics,
            CvssV2Severity = Options.CvssV2Severity,
            CvssV3Metrics = Options.CvssV3Metrics,
            CvssV3Severity = Options.CvssV3Severity,
            CvssV4Metrics = Options.CvssV4Metrics,
            CvssV4Severity = Options.CvssV4Severity,
        };

        if (Options.Limit is not null)
        {
            filter.ResultsPerPage = Math.Min(Options.Limit.Value, MaxResultsPerRequest);
        }

        int totalReturnedCount = 0;
        List<Cve> vulnerabilities = [];
        CveQueryResult result;

        do
        {
            result = await _client.GetCvesAsync(filter);
            totalReturnedCount += result.Vulnerabilities.Length;
            vulnerabilities.AddRange(result.Vulnerabilities.Select(vuln => vuln.Cve));
            filter.StartIndex = totalReturnedCount;

            if (Options.Limit is not null)
            {
                filter.ResultsPerPage = Math.Min(Options.Limit.Value - totalReturnedCount, MaxResultsPerRequest);
            }
            
        } while (totalReturnedCount < result.TotalResults && totalReturnedCount < Options.Limit);

        switch (Options.OutputFormat)
        {
            case OutputFormat.Simple:
                OutputSimple(vulnerabilities);
                break;
            case OutputFormat.Json:
                OutputJson(vulnerabilities);
                break;
            default:
                throw new NotImplementedException();
        }
    }

    private void OutputSimple(List<Cve> vulnerabilities)
    {
        foreach (var vuln in vulnerabilities)
        {
            _console.WriteLine($"CVE:         {vuln.Id}");
            _console.WriteLine($"Description: {OutputHelper.GetValueForCurrentCulture(vuln.Descriptions)}");
            _console.WriteLine($"Published:   {OutputHelper.FormatDate(vuln.Published)}");
            _console.WriteLine(string.Empty);
        }
    }

    private void OutputJson(List<Cve> vulnerabilities)
    {
        string json = JsonSerializer.Serialize(vulnerabilities, _options);
        _console.WriteLine(json);
    }
}
