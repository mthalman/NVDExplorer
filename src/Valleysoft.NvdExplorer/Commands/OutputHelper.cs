using System.Globalization;
using Valleysoft.Nvd.Client;

namespace Valleysoft.NvdExplorer.Commands;

internal static class OutputHelper
{
    public static string FormatDate(DateTimeOffset dateTime) =>
        dateTime.ToLocalTime().ToString("d");

    public static string GetValueForCurrentCulture(IEnumerable<ILanguageValue> languageValues)
    {
        ILanguageValue? langVal = languageValues
            .FirstOrDefault(title => IsCultureDerivedFromCurrentCulture(title));

        return langVal?.Value ?? languageValues.First().Value;
    }

    private static bool IsCultureDerivedFromCurrentCulture(ILanguageValue languageValue) =>
        IsSourceCultureDerivedFromTargetCulture(CultureInfo.CurrentCulture, CultureInfo.GetCultureInfo(languageValue.Language));

    private static bool IsSourceCultureDerivedFromTargetCulture(CultureInfo sourceCulture, CultureInfo targetCulture)
    {
        if (targetCulture.Name == sourceCulture.Name)
        {
            return true;
        }

        if (sourceCulture.Parent != CultureInfo.InvariantCulture)
        {
            return IsSourceCultureDerivedFromTargetCulture(sourceCulture.Parent, targetCulture);
        }

        return false;
    }
}
