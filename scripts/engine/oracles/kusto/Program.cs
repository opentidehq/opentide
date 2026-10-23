// Kusto.Language side of scripts/oracles/oracle.py. Two modes, JSON on stdout:
//   parse <file>...  one object per file: syntax errors from KustoCode.Parse
//   symbols          functions, aggregates and plugins in GlobalState.Default
using System.Text.Json;
using Kusto.Language;
using Kusto.Language.Symbols;

switch (args.FirstOrDefault())
{
    case "parse":
        foreach (var path in args.Skip(1))
        {
            var code = KustoCode.Parse(File.ReadAllText(path));
            var errors = code.GetSyntaxDiagnostics()
                .Where(d => d.Severity == DiagnosticSeverity.Error)
                .Select(d => new { code = d.Code, message = d.Message, start = d.Start, length = d.Length });
            Console.WriteLine(JsonSerializer.Serialize(new { path, kind = code.Kind, errors }));
        }
        return 0;
    case "symbols":
        var globals = GlobalState.Default;
        var symbols = globals.Functions.Select(f => Symbol("function", f))
            .Concat(globals.Aggregates.Select(f => Symbol("aggregate", f)))
            .Concat(globals.PlugIns.Select(f => Symbol("plugin", f)));
        Console.WriteLine(JsonSerializer.Serialize(symbols));
        return 0;
    default:
        Console.Error.WriteLine("usage: KustoOracle parse <file>... | symbols");
        return 2;
}

static object Symbol(string kind, FunctionSymbol f) =>
    new { kind, name = f.Name, hidden = f.IsHidden, obsolete = f.IsObsolete };
