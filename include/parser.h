#ifndef PARSER_H
#define PARSER_H

#include "nas.h"

// Parser state
typedef struct {
    lexer_t* lexer;
    token_t current_token;
    assembler_t* assembler;
} parser_t;

// Parser functions
parser_t* parser_create(lexer_t* lexer, assembler_t* assembler);
void parser_destroy(parser_t* parser);
bool parser_parse_line(parser_t* parser, instruction_t* instruction);
bool parser_parse_directive(parser_t* parser);

// Helper functions
bool parser_expect_token(parser_t* parser, token_type_t type);
bool parser_match_token(parser_t* parser, token_type_t type);
void parser_advance(parser_t* parser);
operand_t parser_parse_operand(parser_t* parser);
int32_t parser_parse_immediate(parser_t* parser);
operand_t parser_parse_memory(parser_t* parser);

// REP prefix helper functions
bool parser_is_rep_prefix(const char* mnemonic);
bool parser_is_string_operation(const char* mnemonic);
bool parser_parse_rep_instruction(parser_t* parser, instruction_t* instruction);

// Expression evaluation functions
int32_t parser_evaluate_expression(parser_t* parser);

#endif // PARSER_H
