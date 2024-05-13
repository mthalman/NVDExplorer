namespace Valleysoft.Nvd.Client;

[AttributeUsage(AttributeTargets.Field, AllowMultiple = false, Inherited = false)]
internal class NvdNameAttribute(string name) : Attribute
{
    public string Name { get; } = name;
}
