using System.CommandLine;

namespace Valleysoft.NvdExplorer.Commands;

internal class CpeOptions : OptionsBase
{
    private readonly Option<string> _keywordSearchOption;
    private readonly Option<bool> _keywordExactMatchOption;

    public string? KeywordSearch { get; set; }

    public bool IsKeywordExactMatch { get; set; }


    public CpeOptions()
    {
        const string KeywordsOptionName = "--keywords";

        _keywordSearchOption = Add(new Option<string>(KeywordsOptionName, "Returns CPEs that contain the provided keywords in the description"));
        _keywordExactMatchOption = Add(new Option<bool>("--exact-match", $"Modifies the keyword search to find an exact match (must be used with {KeywordsOptionName})"));
    }

    protected override void GetValues()
    {
        base.GetValues();
        KeywordSearch = GetValue(_keywordSearchOption);
        IsKeywordExactMatch = GetValue(_keywordExactMatchOption);
    }
}
