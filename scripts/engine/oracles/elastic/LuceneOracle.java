// Lucene oracle: the classic QueryParser from the Lucene jars Elasticsearch
// pins (Apache-2.0), downloaded at CI time only. Leading wildcards on, as in
// Elasticsearch's query_string.
// Usage: java -cp core.jar:queryparser.jar LuceneOracle.java <dir of .lucene files>
import java.nio.file.*;
import java.util.*;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.queryparser.classic.*;

public class LuceneOracle {
  public static void main(String[] args) throws Exception {
    List<Path> files = new ArrayList<>();
    try (var s = Files.list(Path.of(args[0]))) {
      s.filter(p -> p.toString().endsWith(".lucene")).sorted().forEach(files::add);
    }
    for (Path f : files) {
      QueryParser p = new QueryParser("_default", new StandardAnalyzer());
      p.setAllowLeadingWildcard(true);
      String verdict;
      try {
        p.parse(Files.readString(f));
        verdict = "OK\t";
      } catch (ParseException | RuntimeException e) {
        // RuntimeException covers an invalid /regexp/ (IllegalArgumentException).
        verdict = "ERR\t" + String.valueOf(e.getMessage()).lines().findFirst().orElse("");
      }
      System.out.println(f.getFileName() + "\t" + verdict);
    }
  }
}
