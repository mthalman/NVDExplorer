namespace Valleysoft.Nvd.Client;

public class CpeQueryFilter
{
    public int? ResultsPerPage { get; set; }
    public int? StartIndex { get; set; }

    public string? Keywords { get; set; }
    public bool IsKeywordExactMatch { get; set; }
}
