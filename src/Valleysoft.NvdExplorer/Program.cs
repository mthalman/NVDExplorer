using Valleysoft.Nvd.Client;

string apiKey = "<api-key>";

string cveId = "<cve>";
using HttpClient client = new();
NvdClient nvdClient = new(client, apiKey);
CveQueryResult cveQueryResult = await nvdClient.GetCves(new CveQueryFilter { CveId = cveId });
SeverityType severity = cveQueryResult.Vulnerabilities.First().Cve.Metrics!.CvssMetricV31.First().CvssData.BaseSeverity;
Console.WriteLine($"{cveId}: {severity}");
