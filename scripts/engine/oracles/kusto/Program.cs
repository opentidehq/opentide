// Kusto.Language side of scripts/oracles/oracle.py. Three modes, JSON on stdout:
//   parse <file>...                    one object per file: syntax errors from KustoCode.Parse
//   semantic <schema.json> <file>...   one object per file: errors from KustoCode.ParseAndAnalyze
//                                      against a database of the engine's catalog tables
//                                      ({"tables": {T: [[col, type]]}, "functions": {F:
//                                      {"columns": [[col, type]], "params": [[name, type]]}}})
//   symbols                            functions, aggregates and plugins in GlobalState.Default
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
    case "semantic":
        var database = Database(JsonDocument.Parse(File.ReadAllText(args[1])).RootElement);
        foreach (var path in args.Skip(2))
        {
            var text = File.ReadAllText(path);
            var analyzed = KustoCode.ParseAndAnalyze(text, database);
            var errors = analyzed.GetDiagnostics()
                .Where(d => d.Severity == DiagnosticSeverity.Error)
                .Select(d => new
                {
                    code = d.Code,
                    message = d.Message,
                    start = d.Start,
                    length = d.Length,
                    text = d.Start >= 0 && d.Start + d.Length <= text.Length ? text.Substring(d.Start, d.Length) : "",
                });
            Console.WriteLine(JsonSerializer.Serialize(new { path, errors }));
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

static GlobalState Database(JsonElement schema)
{
    static TypeSymbol Type(string name) => ScalarTypes.GetSymbol(name) ?? ScalarTypes.Unknown;
    static TableSymbol Table(string name, JsonElement columns) =>
        new(name, columns.EnumerateArray().Select(c => new ColumnSymbol(c[0].GetString()!, Type(c[1].GetString()!))));
    var symbols = new List<Symbol>();
    foreach (var table in schema.GetProperty("tables").EnumerateObject())
        symbols.Add(Table(table.Name, table.Value));
    foreach (var function in schema.GetProperty("functions").EnumerateObject())
    {
        var parameters = function.Value.GetProperty("params").EnumerateArray()
            .Select(p => new Parameter(p[0].GetString()!, Type(p[1].GetString()!), minOccurring: 0))
            .ToArray();
        symbols.Add(new FunctionSymbol(function.Name, Table(function.Name, function.Value.GetProperty("columns")), parameters));
    }
    return GlobalState.Default.WithDatabase(new DatabaseSymbol("workspace", symbols));
}

static object Symbol(string kind, FunctionSymbol f) =>
    new { kind, name = f.Name, hidden = f.IsHidden, obsolete = f.IsObsolete };
