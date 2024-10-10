using System.CommandLine;
using System.Globalization;
using System.Text.Json;
using Valleysoft.Nvd.Client;

namespace Valleysoft.NvdExplorer.Commands;

internal class CpeCommand(NvdClient client, IConsole console) : CommandWithOptions<CpeOptions>("cpe", "Queries the Common Platform Enumeration (CPE) database")
{
    private const int MaxResultsPerRequest = 10000;
    private readonly NvdClient _client = client;
    private readonly IConsole _console = console;
    private readonly JsonSerializerOptions _options = new()
    {
        WriteIndented = true
    };

    protected override async Task ExecuteAsync()
    {
        CpeQueryFilter filter = new()
        {
            Keywords = Options.KeywordSearch,
            IsKeywordExactMatch = Options.IsKeywordExactMatch,
        };

        if (Options.Limit is not null)
        {
            filter.ResultsPerPage = Math.Min(Options.Limit.Value, MaxResultsPerRequest);
        }

        int totalReturnedCount = 0;
        List<Cpe> cpes = [];
        CpeQueryResult result;

        do
        {
            result = await _client.GetCpesAsync(filter);
            totalReturnedCount += result.Products.Length;
            cpes.AddRange(result.Products.Select(product => product.Cpe));
            filter.StartIndex = totalReturnedCount;

            if (Options.Limit is not null)
            {
                filter.ResultsPerPage = Math.Min(Options.Limit.Value - totalReturnedCount, MaxResultsPerRequest);
            }
            
        } while (totalReturnedCount < result.TotalResults && totalReturnedCount < Options.Limit);

        switch (Options.OutputFormat)
        {
            case OutputFormat.Simple:
                OutputSimple(cpes);
                break;
            case OutputFormat.Json:
                OutputJson(cpes);
                break;
            default:
                throw new NotImplementedException();
        }
    }

    private void OutputSimple(List<Cpe> cpes)
    {
        foreach (Cpe cpe in cpes)
        {
            _console.WriteLine($"Title:   {OutputHelper.GetValueForCurrentCulture(cpe.Titles)}");
            _console.WriteLine($"CPE:     {cpe.CpeName}");
            _console.WriteLine($"Created: {OutputHelper.FormatDate(cpe.Created)}");
            _console.WriteLine(string.Empty);
        }
    }

    private void OutputJson(List<Cpe> cpes)
    {
        string json = JsonSerializer.Serialize(cpes, _options);
        _console.WriteLine(json);
    }
}
