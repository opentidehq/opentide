// External scanner for ES|QL comments.
//
// Elasticsearch lexes block comments with a recursive, non-greedy rule, so
// `/* a /* b */ c */` is one comment. A regular expression cannot count, so
// the `comment` token lives here. `//` line comments are handled here too,
// because one external token cannot share its name with a grammar rule.
//
// The block rule is simulated the way Elasticsearch's lexer runs it. Each
// candidate reading is a nesting depth plus how much of a two-character
// delimiter it has seen; candidates are kept in priority order (closing first,
// then opening a nested comment, then treating the character as text). When
// the outermost comment closes, that end is recorded and every lower-priority
// candidate is dropped; higher-priority candidates keep scanning and may find
// a longer comment. The token ends at the last recorded close. So:
//
//   /* a /* b */ c */     one comment (nested)
//   /* a /* b */          one comment (the inner opener falls back to text)
//   /* a */ */            a comment, then a stray `*/`
//   /* a /* b             unterminated: no comment token
//
// No allocation and no state survives between tokens.

#include "tree_sitter/parser.h"

#include <stdbool.h>
#include <stdint.h>

enum TokenType { COMMENT };

enum Pending { NONE, SLASH, STAR };

typedef struct {
  uint16_t depth;
  uint8_t pending;
} Reading;

#define MAX_READINGS 64

static bool is_space(int32_t c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }

static void push(Reading *out, unsigned *len, uint16_t depth, uint8_t pending) {
  for (unsigned i = 0; i < *len; i++) {
    if (out[i].depth == depth && out[i].pending == pending) {
      return;
    }
  }
  if (*len < MAX_READINGS) {
    out[*len].depth = depth;
    out[*len].pending = pending;
    (*len)++;
  }
}

static bool scan_block(TSLexer *lexer) {
  Reading current[MAX_READINGS];
  Reading next[MAX_READINGS];
  unsigned len = 1;
  current[0].depth = 1;
  current[0].pending = NONE;
  bool closed = false;
  while (len > 0 && !lexer->eof(lexer)) {
    int32_t c = lexer->lookahead;
    lexer->advance(lexer, false);
    unsigned next_len = 0;
    bool accepted = false;
    for (unsigned i = 0; i < len && !accepted; i++) {
      Reading r = current[i];
      switch (r.pending) {
        case STAR:
          if (c == '/') {
            if (r.depth == 1) {
              lexer->mark_end(lexer);
              closed = true;
              accepted = true;
            } else {
              push(next, &next_len, r.depth - 1, NONE);
            }
          }
          break;
        case SLASH:
          if (c == '*' && r.depth < UINT16_MAX) {
            push(next, &next_len, r.depth + 1, NONE);
          }
          break;
        default:
          if (c == '*') {
            push(next, &next_len, r.depth, STAR);
          } else if (c == '/') {
            push(next, &next_len, r.depth, SLASH);
          }
          push(next, &next_len, r.depth, NONE);
          break;
      }
    }
    for (unsigned i = 0; i < next_len; i++) {
      current[i] = next[i];
    }
    len = next_len;
  }
  return closed;
}

void *tree_sitter_opentide_esql_external_scanner_create(void) { return NULL; }

void tree_sitter_opentide_esql_external_scanner_destroy(void *payload) { (void)payload; }

unsigned tree_sitter_opentide_esql_external_scanner_serialize(void *payload, char *buffer) {
  (void)payload;
  (void)buffer;
  return 0;
}

void tree_sitter_opentide_esql_external_scanner_deserialize(void *payload, const char *buffer,
                                                            unsigned length) {
  (void)payload;
  (void)buffer;
  (void)length;
}

bool tree_sitter_opentide_esql_external_scanner_scan(void *payload, TSLexer *lexer,
                                                     const bool *valid_symbols) {
  (void)payload;
  if (!valid_symbols[COMMENT]) {
    return false;
  }
  while (is_space(lexer->lookahead)) {
    lexer->advance(lexer, true);
  }
  if (lexer->lookahead != '/') {
    return false;
  }
  lexer->advance(lexer, false);
  if (lexer->lookahead == '/') {
    while (!lexer->eof(lexer) && lexer->lookahead != '\n' && lexer->lookahead != '\r') {
      lexer->advance(lexer, false);
    }
    lexer->mark_end(lexer);
    lexer->result_symbol = COMMENT;
    return true;
  }
  if (lexer->lookahead != '*') {
    return false;
  }
  lexer->advance(lexer, false);
  if (scan_block(lexer)) {
    lexer->result_symbol = COMMENT;
    return true;
  }
  return false;
}
