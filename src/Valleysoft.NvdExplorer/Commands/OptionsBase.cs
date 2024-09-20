using System.Collections.Generic;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.Diagnostics.CodeAnalysis;

namespace Valleysoft.NvdExplorer.Commands;

public abstract class OptionsBase
{
    private readonly Option<OutputFormat> _outputFormatOption;
    private readonly Option<int?> _limitOption;
    private readonly List<Argument> _arguments = [];
    private readonly List<Option> _options = [];
    private ParseResult? _parseResult;

    protected OptionsBase()
    {
        _outputFormatOption = Add(new Option<OutputFormat>("--format", () => OutputFormat.Simple, "Set the format of the output"));
        _limitOption = Add(new Option<int?>("--limit", "Maximum number of CVEs to include in the result"));
    }

    public OutputFormat OutputFormat { get; set; } = OutputFormat.Simple;

    public int? Limit { get; set; }

    protected Argument<T> Add<T>(Argument<T> argument)
    {
        _arguments.Add(argument);
        return argument;
    }

    protected Option<T> Add<T>(Option<T> option)
    {
        _options.Add(option);
        return option;
    }

    protected T GetValue<T>(Argument<T> arg)
    {
        ValidateParseResult();
        return _parseResult.GetValueForArgument(arg);
    }

    protected T? GetValue<T>(Option<T> option)
    {
        ValidateParseResult();
        return _parseResult.GetValueForOption(option);
    }

    [MemberNotNull(nameof(_parseResult))]
    private void ValidateParseResult()
    {
        if (_parseResult is null)
        {
            throw new Exception($"'{nameof(SetParseResult)}' method must be called before get argument value");
        }
    }

    public void SetParseResult(ParseResult parseResult)
    {
        _parseResult = parseResult;
        GetValues();
    }

    protected virtual void GetValues()
    {
        OutputFormat = GetValue(_outputFormatOption);
        Limit = GetValue(_limitOption);
    }

    public void SetCommandOptions(Command cmd)
    {
        foreach (Argument arg in _arguments)
        {
            cmd.AddArgument(arg);
        }

        foreach (Option option in _options)
        {
            cmd.AddOption(option);
        }
    }
}

public enum OutputFormat
{
    Simple,
    Json
}

