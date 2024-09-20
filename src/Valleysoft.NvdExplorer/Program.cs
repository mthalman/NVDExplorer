using System.CommandLine;
using System.CommandLine.IO;
using Valleysoft.Nvd.Client;
using Valleysoft.NvdExplorer.Commands;

string? apiKey = Environment.GetEnvironmentVariable("NVD_EXPLORER_API_KEY");

NvdClient client = new(new HttpClient(), apiKey);
SystemConsole console = new();

RootCommand rootCommand = new("CLI for querying National Vulnerability Database (NVD)")
{
    new CveCommand(client, console),
    new CpeCommand(client, console)
};

return rootCommand.Invoke(args);
