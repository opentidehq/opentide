// External scanner for CQL (CrowdStrike Query Language) words.
//
// CQL decides what a run of word characters is by what follows it, which a
// regular expression in grammar.js cannot see. This scanner lexes three
// tokens; every other token, including plain field names and keywords, comes
// from the grammar's own lexer.
//
//   function_name     `Ident` or `Ident:Ident` directly followed by `(`.
//                     RN-224: "a word is only interpreted as a function call
//                     if it is immediately followed by a starting
//                     parenthesis", so `rdns (x)` is not a call. Function
//                     names are not reserved and match in any case, so the
//                     grammar cannot list them. `and(`, `or(` and `not(` stay
//                     keywords. A function name is also lexed where a filter
//                     operand may start, so `foo in(x)` is a parse error
//                     (a call is never a filter operand) instead of the
//                     filters `foo`, `in` and `(x)`.
//   unquoted_pattern  a run of field characters and `* + - : /` with at least
//                     one of those five (`*login*`, `https://x.com/`,
//                     `m/fisk/i`, `docker/*`). A pattern cannot start with `/`
//                     (that is a regex or a comment) and ends before `:=`, so
//                     `Status:="OK"` is the field `Status` and an assignment.
//                     A run with none of the five is left to the grammar,
//                     which lexes it as a field name or keyword.
//   _value_pattern    the same token after `=`, `!=` and `like` and in
//                     saved-query and parameter values. There a word and `(`
//                     are a pattern and a group, never a call: LogScale's own
//                     dashboards write `#category=Request(uri=/x/ or ...)`.
//   _regex_end        the slash that closes a regex. The grammar's lexer
//                     would read `//` there as a line comment (`/a//b/` is two
//                     regexes), because comments are valid everywhere and the
//                     longest token wins; the scanner runs first.
//   _assign_field     a field name followed by `:=`, with blanks allowed
//                     between (`payload := ...`, `@display := x`, `a.b := 1`).
//                     A step may follow another without a pipe, and after a
//                     filter a plain word could be more free text or the start
//                     of an assignment; only the `:=` after it tells, which is
//                     one token further than the parser looks.
//   _pattern_error    a pattern that ends in `//` (`https://`, `ERROR// x`),
//                     which the grammar subset forbids. No rule accepts it, so
//                     the parser reports an error at that token. It is
//                     never valid, so tree-sitter marks it valid only while
//                     recovering from an error; the scanner reads that as
//                     "in recovery" and then never closes a regex.
//
// Function names are tried wherever a function call or a free-text pattern
// may start; patterns only where the grammar accepts one. No allocation and
// no state survives between tokens.

#include "tree_sitter/parser.h"

#include <stdbool.h>
#include <stdint.h>

enum TokenType {
  FUNCTION_NAME,
  UNQUOTED_PATTERN,
  VALUE_PATTERN,
  REGEX_END,
  PATTERN_ERROR,
  ASSIGN_FIELD,
};

static bool is_space(int32_t c) {
  return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

static bool is_alpha(int32_t c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

static bool is_digit(int32_t c) { return c >= '0' && c <= '9'; }

static bool is_ident_char(int32_t c) { return is_alpha(c) || is_digit(c) || c == '_'; }

// Appendix C "FieldChar", plus Unicode beyond Latin-1.
static bool is_field_char(int32_t c) {
  if (is_ident_char(c)) {
    return true;
  }
  switch (c) {
    case '#':
    case '%':
    case '&':
    case '.':
    case '@':
    case '\\':
    case '^':
    case '~':
      return true;
    default:
      break;
  }
  if (c < 0xA1) {
    return false;
  }
  // U+00AB and U+00BB (the guillemets) and U+00AD (soft hyphen) are reserved.
  return c != 0xAB && c != 0xAD && c != 0xBB;
}

// Characters an unquoted pattern adds to the field characters. `:` is
// handled separately (it may end the run before `:=`).
static bool is_pattern_only_char(int32_t c) { return c == '*' || c == '+' || c == '-' || c == '/'; }

enum Shape { IDENT1, COLON, IDENT2, OTHER };

void *tree_sitter_opentide_cql_external_scanner_create(void) { return NULL; }

void tree_sitter_opentide_cql_external_scanner_destroy(void *payload) { (void)payload; }

unsigned tree_sitter_opentide_cql_external_scanner_serialize(void *payload, char *buffer) {
  (void)payload;
  (void)buffer;
  return 0;
}

void tree_sitter_opentide_cql_external_scanner_deserialize(void *payload, const char *buffer,
                                                           unsigned length) {
  (void)payload;
  (void)buffer;
  (void)length;
}

bool tree_sitter_opentide_cql_external_scanner_scan(void *payload, TSLexer *lexer,
                                                    const bool *valid_symbols) {
  (void)payload;
  bool recovering = valid_symbols[PATTERN_ERROR];
  if (valid_symbols[REGEX_END] && !recovering && lexer->lookahead == '/') {
    lexer->advance(lexer, false);
    lexer->mark_end(lexer);
    lexer->result_symbol = REGEX_END;
    return true;
  }
  bool free_text = valid_symbols[UNQUOTED_PATTERN];
  bool want_pattern = free_text || valid_symbols[VALUE_PATTERN];
  bool want_function = valid_symbols[FUNCTION_NAME] || free_text;
  bool want_assign = valid_symbols[ASSIGN_FIELD] && !recovering;
  if (!want_function && !want_pattern && !want_assign) {
    return false;
  }
  while (is_space(lexer->lookahead)) {
    lexer->advance(lexer, true);
  }
  int32_t first = lexer->lookahead;
  if (want_pattern) {
    if (first == '/' || !(is_field_char(first) || is_pattern_only_char(first) || first == ':')) {
      return false;
    }
  } else if (!is_alpha(first) && !(want_assign && first != '#' && is_field_char(first))) {
    return false;
  }

  enum Shape shape = is_alpha(first) ? IDENT1 : OTHER;
  bool has_pattern_char = false;
  bool before_assign = false;
  unsigned length = 0;
  char word[3] = {0, 0, 0};  // lower-cased first three characters, for and/or/not
  int32_t last = 0;
  int32_t before_last = 0;

  while (!lexer->eof(lexer)) {
    int32_t c = lexer->lookahead;
    if (c == ':') {
      // The token so far ends before the colon; `:=` is the assignment.
      lexer->advance(lexer, false);
      if (lexer->lookahead == '=') {
        before_assign = true;
        break;
      }
      shape = shape == IDENT1 ? COLON : OTHER;
      if (!want_pattern && !want_assign && shape == OTHER) {
        break;
      }
      has_pattern_char = true;
    } else if (is_field_char(c) || (want_pattern && is_pattern_only_char(c))) {
      if (!is_ident_char(c)) {
        shape = OTHER;
        if (!want_pattern && !want_assign) {
          break;
        }
      } else if (shape == COLON) {
        shape = is_alpha(c) ? IDENT2 : OTHER;
      }
      if (is_pattern_only_char(c)) {
        has_pattern_char = true;
      }
      if (length < 3) {
        word[length] = (char)(is_alpha(c) ? (c | 0x20) : c);
      }
      lexer->advance(lexer, false);
    } else {
      break;
    }
    length++;
    before_last = last;
    last = c;
    lexer->mark_end(lexer);
  }
  if (length == 0) {
    return false;
  }
  // What directly follows the word, before any look past blanks below.
  int32_t after_word = lexer->lookahead;

  if (want_assign && !has_pattern_char) {
    // `name :=`: blanks may stand between the name and `:=`. The token
    // already ends after the name (mark_end), so looking on costs nothing.
    if (!before_assign) {
      while (is_space(lexer->lookahead)) {
        lexer->advance(lexer, false);
      }
      if (lexer->lookahead == ':') {
        lexer->advance(lexer, false);
        before_assign = lexer->lookahead == '=';
      }
    }
    if (before_assign) {
      lexer->result_symbol = ASSIGN_FIELD;
      return true;
    }
  }

  if (want_function && !before_assign && (shape == IDENT1 || shape == IDENT2) &&
      after_word == '(') {
    bool keyword = (length == 3 && ((word[0] == 'a' && word[1] == 'n' && word[2] == 'd') ||
                                    (word[0] == 'n' && word[1] == 'o' && word[2] == 't'))) ||
                   (length == 2 && word[0] == 'o' && word[1] == 'r');
    if (!keyword) {
      lexer->result_symbol = FUNCTION_NAME;
      return true;
    }
  }
  if (!want_pattern) {
    return false;
  }
  if (last == '/' && before_last == '/') {
    lexer->result_symbol = PATTERN_ERROR;
    return true;
  }
  if (has_pattern_char) {
    lexer->result_symbol = free_text ? UNQUOTED_PATTERN : VALUE_PATTERN;
    return true;
  }
  return false;
}
