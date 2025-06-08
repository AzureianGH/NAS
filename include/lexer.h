#ifndef LEXER_H
#define LEXER_H

#include "nas.h"

// Lexer state
typedef struct
{
    char *input;
    size_t position;
    size_t length;
    int line;
    int column;
    token_t current_token;
} lexer_t;

// Lexer functions
lexer_t *lexer_create(const char *input);
void lexer_destroy(lexer_t *lexer);
token_t lexer_next_token(lexer_t *lexer);
token_t lexer_peek_token(lexer_t *lexer);
bool lexer_is_at_end(lexer_t *lexer);

// Helper functions
bool is_alpha(char c);
bool is_digit(char c);
bool is_alnum(char c);
bool is_whitespace(char c);
register_t parse_register(const char *str);
const char *register_to_string(register_t reg);

#endif // LEXER_H
