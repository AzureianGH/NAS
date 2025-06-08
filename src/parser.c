#include "nas.h"

parser_t* parser_create(lexer_t* lexer, assembler_t* assembler) {
    parser_t* parser = malloc(sizeof(parser_t));
    if (!parser) return NULL;
    
    parser->lexer = lexer;
    parser->assembler = assembler;
    parser->current_token = lexer_next_token(lexer);
    
    return parser;
}

void parser_destroy(parser_t* parser) {
    if (parser) {
        free(parser);
    }
}

void parser_advance(parser_t* parser) {
    parser->current_token = lexer_next_token(parser->lexer);
}

bool parser_match_token(parser_t* parser, token_type_t type) {
    if (parser->current_token.type == type) {
        parser_advance(parser);
        return true;
    }
    return false;
}

bool parser_expect_token(parser_t* parser, token_type_t type) {
    if (parser->current_token.type == type) {
        parser_advance(parser);
        return true;
    }
    return false;
}

int32_t parser_parse_immediate(parser_t* parser) {
    if (parser->current_token.type != TOKEN_IMMEDIATE) {
        return 0;
    }
    
    char* value_str = parser->current_token.value;
    int32_t value;
    
    // Handle hex numbers
    if (strncmp(value_str, "0x", 2) == 0 || strncmp(value_str, "0X", 2) == 0) {
        value = (int32_t)strtol(value_str, NULL, 16);
    } else {
        value = (int32_t)strtol(value_str, NULL, 10);
    }
    
    parser_advance(parser);
    return value;
}

operand_t parser_parse_memory(parser_t* parser) {
    operand_t operand = {0};
    operand.type = OPERAND_MEMORY;
    operand.value.memory.segment = REG_NONE; // No segment override by default

    if (!parser_expect_token(parser, TOKEN_LBRACKET)) {
        operand.type = OPERAND_NONE;
        return operand;
    }

    // Check for segment override: [segment:register] or [segment:immediate]
    if (parser->current_token.type == TOKEN_REGISTER) {
        register_t potential_segment = parse_register(parser->current_token.value);
        // Check if this is a segment register followed by a colon
        if ((potential_segment == REG_CS || potential_segment == REG_DS || 
             potential_segment == REG_ES || potential_segment == REG_SS)) {
            token_t next = lexer_peek_token(parser->lexer);
            if (next.type == TOKEN_COLON) {
                // This is a segment override
                operand.value.memory.segment = potential_segment;
                parser_advance(parser); // consume segment register
                parser_advance(parser); // consume colon
            }
        }
    }    // Handle label-based memory operand [label] or [segment:label]
    if (parser->current_token.type == TOKEN_LABEL) {
        operand.value.memory.has_label = true;
        strncpy(operand.value.memory.label, parser->current_token.value, MAX_LABEL_LENGTH - 1);
        operand.value.memory.label[MAX_LABEL_LENGTH - 1] = '\0';
        // Register this symbol as being referenced (undefined for now)
        symbol_reference(parser->assembler, parser->current_token.value);
        // Advance past label
        parser_advance(parser);
        // Expect closing bracket
        if (!parser_expect_token(parser, TOKEN_RBRACKET)) {
            operand.type = OPERAND_NONE;
            return operand;
        }
        return operand;
    }

    // Handle immediate memory operand [0x7C00] or [segment:0x7C00]
    if (parser->current_token.type == TOKEN_IMMEDIATE) {
        // This is a direct memory address [immediate] or [segment:immediate]
        operand.value.memory.displacement = parser_parse_immediate(parser);
        operand.value.memory.base = REG_NONE; // No base register
        operand.value.memory.has_label = false;
        // Expect closing bracket
        if (!parser_expect_token(parser, TOKEN_RBRACKET)) {
            operand.type = OPERAND_NONE;
            return operand;
        }
        return operand;
    }    // Parse base register (after potential segment override)
    if (parser->current_token.type == TOKEN_REGISTER) {
        operand.value.memory.base = parse_register(parser->current_token.value);
        operand.value.memory.index = REG_NONE; // Initialize index to none
        parser_advance(parser);
        
        // Check for index register or displacement (+ or - followed by register or number)
        if (parser->current_token.type == TOKEN_PLUS || parser->current_token.type == TOKEN_MINUS) {
            bool is_negative = (parser->current_token.type == TOKEN_MINUS);
            parser_advance(parser); // consume + or -
            
            if (parser->current_token.type == TOKEN_REGISTER) {
                // This is an index register: [base+index]
                if (is_negative) {
                    assembler_error(parser->assembler, "Index registers cannot be negative in memory operand at line %d", 
                                   parser->current_token.line);
                    operand.type = OPERAND_NONE;
                    return operand;
                }
                operand.value.memory.index = parse_register(parser->current_token.value);
                parser_advance(parser);
                
                // Check for additional displacement after index: [base+index+displacement]
                if (parser->current_token.type == TOKEN_PLUS || parser->current_token.type == TOKEN_MINUS) {
                    bool disp_negative = (parser->current_token.type == TOKEN_MINUS);
                    parser_advance(parser); // consume + or -
                    
                    if (parser->current_token.type == TOKEN_IMMEDIATE) {
                        int32_t displacement = parser_parse_immediate(parser);
                        operand.value.memory.displacement = disp_negative ? -displacement : displacement;
                    } else {
                        assembler_error(parser->assembler, "Expected immediate value after %c in memory operand at line %d", 
                                       disp_negative ? '-' : '+', parser->current_token.line);
                        operand.type = OPERAND_NONE;
                        return operand;
                    }
                }
            } else if (parser->current_token.type == TOKEN_IMMEDIATE) {
                // This is a displacement: [base+displacement]
                int32_t displacement = parser_parse_immediate(parser);
                operand.value.memory.displacement = is_negative ? -displacement : displacement;
            } else {
                assembler_error(parser->assembler, "Expected register or immediate value after %c in memory operand at line %d", 
                               is_negative ? '-' : '+', parser->current_token.line);
                operand.type = OPERAND_NONE;
                return operand;
            }
        }
    }
    
    if (!parser_expect_token(parser, TOKEN_RBRACKET)) {
        operand.type = OPERAND_NONE;
        return operand;
    }
    
    return operand;
}

operand_t parser_parse_operand(parser_t* parser) {
    operand_t operand = {0};

    // Check for size specifiers (byte, word, dword)
    int explicit_size = 0;
    if (parser->current_token.type == TOKEN_BYTE) {
        explicit_size = 8;
        parser_advance(parser);
    } else if (parser->current_token.type == TOKEN_WORD) {
        explicit_size = 16;
        parser_advance(parser);
    } else if (parser->current_token.type == TOKEN_DWORD) {
        explicit_size = 32;
        parser_advance(parser);
    }    // Check for far pointer literal: segment:offset
    token_t next = lexer_peek_token(parser->lexer);
    if (parser->current_token.type == TOKEN_IMMEDIATE && next.type == TOKEN_COLON) {
        // Parse segment part
        int32_t segment = parser_parse_immediate(parser);
        // Consume colon
        parser_advance(parser);
        // Expect offset immediate
        if (parser->current_token.type == TOKEN_IMMEDIATE) {
            int32_t offset = parser_parse_immediate(parser);
            operand.type = OPERAND_FARPTR;
            operand.value.far_ptr.segment = (uint16_t)segment;
            operand.value.far_ptr.offset = (uint16_t)offset;
            // Far pointer uses 32-bit far address (16-bit offset + 16-bit segment)
            operand.size = 32;
            return operand;
        } else {
            assembler_error(parser->assembler, "Expected offset after ':' in far pointer at line %d", parser->current_token.line);
            operand.type = OPERAND_NONE;
            return operand;
        }
    }

    switch (parser->current_token.type) {
        case TOKEN_REGISTER:
            operand.type = OPERAND_REGISTER;
            operand.value.reg = parse_register(parser->current_token.value);
            if (operand.value.reg == REG_NONE) {
                operand.type = OPERAND_NONE;
                return operand;
            }
            operand.size = explicit_size ? explicit_size : get_register_size(operand.value.reg);
            parser_advance(parser);
            break;
            
        case TOKEN_IMMEDIATE:
            operand.type = OPERAND_IMMEDIATE;
            operand.value.immediate = parser_parse_immediate(parser);
            operand.size = explicit_size ? explicit_size : 16; // Default to 16-bit
            break;
              case TOKEN_LBRACKET:
            operand = parser_parse_memory(parser);
            if (explicit_size && operand.type == OPERAND_MEMORY) {
                operand.size = explicit_size;
            }
            break;
              case TOKEN_LABEL:
            // Check if this is a defined symbol (like from #define)
            symbol_t* symbol = symbol_lookup(parser->assembler, parser->current_token.value);
            if (symbol && symbol->defined) {
                // Convert defined symbol to immediate operand
                operand.type = OPERAND_IMMEDIATE;
                operand.value.immediate = (int32_t)symbol->address;
                operand.size = explicit_size ? explicit_size : 16; // Default to 16-bit
            } else {
                // Keep as label operand for later resolution
                // Register this symbol as being referenced (undefined for now)
                symbol_reference(parser->assembler, parser->current_token.value);
                operand.type = OPERAND_LABEL;
                strncpy(operand.value.label, parser->current_token.value, MAX_LABEL_LENGTH - 1);
                operand.value.label[MAX_LABEL_LENGTH - 1] = '\0';
                operand.size = explicit_size ? explicit_size : 16; // Default to 16-bit
            }
            parser_advance(parser);
            break;
            
        default:
            if (explicit_size) {
                assembler_error(parser->assembler, "Expected operand after size specifier at line %d", 
                               parser->current_token.line);
            }
            operand.type = OPERAND_NONE;
            break;
    }
    
    return operand;
}

bool parser_parse_directive(parser_t* parser) {
    if (parser->current_token.type != TOKEN_DIRECTIVE) {
        return false;
    }    // Copy directive name before advancing
    char directive[MAX_OPERAND_LENGTH];
    strncpy(directive, parser->current_token.value, MAX_OPERAND_LENGTH - 1);
    directive[MAX_OPERAND_LENGTH - 1] = '\0';    
    if (parser->assembler->verbose) {
        printf("Parsing directive: %s\n", directive);
    }
    parser_advance(parser); // consume directive token

    // Handle origin directive
    if (strcmp(directive, "#origin") == 0) {
        if (parser->current_token.type == TOKEN_IMMEDIATE) {
            uint32_t origin = (uint32_t)parser_parse_immediate(parser);
            assembler_set_origin(parser->assembler, origin);
        } else {
            assembler_error(parser->assembler, "Expected immediate value after #origin directive at line %d", 
                           parser->current_token.line);
            return false;
        }    // Handle width directive
    } else if (strcmp(directive, "#width") == 0) {
        if (parser->current_token.type == TOKEN_IMMEDIATE) {
            int width = parser_parse_immediate(parser);
            if (width != 16 && width != 32) {
                assembler_error(parser->assembler, "Invalid width value %d at line %d. Must be 16 or 32", 
                               width, parser->current_token.line);
                return false;
            }
            
            asm_mode_t directive_mode = (width == 32) ? MODE_32BIT : MODE_16BIT;
            
            // Check for conflict with command line mode if both are set
            if (parser->assembler->cmdline_mode_set && parser->assembler->cmdline_mode != directive_mode) {
                assembler_error(parser->assembler, "Conflict of interest: #width %d directive at line %d conflicts with command line flag -m%d", 
                               width, parser->current_token.line, parser->assembler->cmdline_mode);
                return false;
            }
            
            parser->assembler->directive_mode_set = true;
            assembler_set_mode(parser->assembler, directive_mode);
        } else {
            assembler_error(parser->assembler, "Expected immediate value after #width directive at line %d", 
                           parser->current_token.line);
            return false;
        }    // Handle db (define byte) directive
    } else if (strcmp(directive, "#db") == 0) {
        // Parse comma-separated list of byte values
        do {
            if (parser->current_token.type == TOKEN_IMMEDIATE) {
                int32_t value = parser_parse_immediate(parser);
                if (value < 0 || value > 255) {
                    assembler_error(parser->assembler, "Byte value %d out of range (0-255) at line %d", 
                                   value, parser->current_token.line);
                    return false;
                }
                if (!codegen_emit_byte(parser->assembler, (uint8_t)value)) {
                    assembler_error(parser->assembler, "Failed to emit byte at line %d", 
                                   parser->current_token.line);
                    return false;
                }
            } else {
                assembler_error(parser->assembler, "Expected immediate value in #db directive at line %d", 
                               parser->current_token.line);
                return false;
            }
            
            // Check for comma to continue parsing more values
            if (parser->current_token.type == TOKEN_COMMA) {
                parser_advance(parser); // consume comma
            } else {
                break; // No more values
            }
        } while (parser->current_token.type != TOKEN_NEWLINE && parser->current_token.type != TOKEN_EOF);

    // Handle dw (define word) directive
    } else if (strcmp(directive, "#dw") == 0) {
        // Parse comma-separated list of word values
        do {
            if (parser->current_token.type == TOKEN_IMMEDIATE) {
                int32_t value = parser_parse_immediate(parser);
                if (value < 0 || value > 0xFFFF) {
                    assembler_error(parser->assembler, "Word value %d out of range (0-65535) at line %d", 
                                   value, parser->current_token.line);
                    return false;
                }
                if (!codegen_emit_word(parser->assembler, (uint16_t)value)) {
                    assembler_error(parser->assembler, "Failed to emit word at line %d", 
                                   parser->current_token.line);
                    return false;
                }
            } else {
                assembler_error(parser->assembler, "Expected immediate value in #dw directive at line %d", 
                               parser->current_token.line);
                return false;
            }
            
            // Check for comma to continue parsing more values
            if (parser->current_token.type == TOKEN_COMMA) {
                parser_advance(parser); // consume comma
            } else {
                break; // No more values
            }
        } while (parser->current_token.type != TOKEN_NEWLINE && parser->current_token.type != TOKEN_EOF);// Handle define directive
    } else if (strcmp(directive, "#define") == 0) {
        if (parser->current_token.type == TOKEN_LABEL) {
            char name[MAX_LABEL_LENGTH];
            strncpy(name, parser->current_token.value, MAX_LABEL_LENGTH - 1);
            name[MAX_LABEL_LENGTH - 1] = '\0';
            parser_advance(parser);
            if (parser->current_token.type == TOKEN_IMMEDIATE) {
                uint32_t val = (uint32_t)parser_parse_immediate(parser);
                if (!symbol_define(parser->assembler, name, val)) {
                    assembler_error(parser->assembler, "Symbol '%s' already defined at line %d", 
                                   name, parser->current_token.line);
                    return false;
                }
            } else {
                assembler_error(parser->assembler, "Expected immediate value after symbol name in #define directive at line %d", 
                               parser->current_token.line);
                return false;
            }
        } else {
            assembler_error(parser->assembler, "Expected symbol name after #define directive at line %d", 
                           parser->current_token.line);
            return false;
        }

    // Handle times directive
    } else if (strcmp(directive, "#times") == 0) {
        // Parse the count expression
        int32_t count = parser_evaluate_expression(parser);
        
        // Check if count is negative
        if (count < 0) {
            assembler_error(parser->assembler, "Negative count %d in #times directive at line %d", 
                           count, parser->current_token.line);
            return false;
        }
        
        // Parse the data directive that follows
        if (parser->current_token.type == TOKEN_DIRECTIVE) {
            char data_directive[MAX_OPERAND_LENGTH];
            strncpy(data_directive, parser->current_token.value, MAX_OPERAND_LENGTH - 1);
            data_directive[MAX_OPERAND_LENGTH - 1] = '\0';
            parser_advance(parser);
            
            if (strcmp(data_directive, "#db") == 0) {
                // Parse the byte value
                if (parser->current_token.type == TOKEN_IMMEDIATE) {
                    int32_t value = parser_parse_immediate(parser);
                    if (value < 0 || value > 255) {
                        assembler_error(parser->assembler, "Byte value %d out of range (0-255) at line %d", 
                                       value, parser->current_token.line);
                        return false;
                    }
                    // Emit the byte 'count' times
                    for (int32_t i = 0; i < count; i++) {
                        if (!codegen_emit_byte(parser->assembler, (uint8_t)value)) {
                            assembler_error(parser->assembler, "Failed to emit byte at line %d", 
                                           parser->current_token.line);
                            return false;
                        }
                    }
                } else {
                    assembler_error(parser->assembler, "Expected immediate value after #db in #times directive at line %d", 
                                   parser->current_token.line);
                    return false;
                }
            } else if (strcmp(data_directive, "#dw") == 0) {
                // Parse the word value
                if (parser->current_token.type == TOKEN_IMMEDIATE) {
                    int32_t value = parser_parse_immediate(parser);
                    if (value < 0 || value > 0xFFFF) {
                        assembler_error(parser->assembler, "Word value %d out of range (0-65535) at line %d", 
                                       value, parser->current_token.line);
                        return false;
                    }
                    // Emit the word 'count' times
                    for (int32_t i = 0; i < count; i++) {
                        if (!codegen_emit_word(parser->assembler, (uint16_t)value)) {
                            assembler_error(parser->assembler, "Failed to emit word at line %d", 
                                           parser->current_token.line);
                            return false;
                        }
                    }
                } else {
                    assembler_error(parser->assembler, "Expected immediate value after #dw in #times directive at line %d", 
                                   parser->current_token.line);
                    return false;
                }
            } else {
                assembler_error(parser->assembler, "Unsupported data directive '%s' after #times at line %d", 
                               data_directive, parser->current_token.line);
                return false;
            }
        } else {
            assembler_error(parser->assembler, "Expected data directive (#db or #dw) after #times count at line %d", 
                           parser->current_token.line);
            return false;
        }
    } else {
        // Unknown directive
        assembler_error(parser->assembler, "Unknown directive '%s' at line %d", 
                       directive, parser->current_token.line);
        return false;
    }

    return true;
}

bool parser_parse_line(parser_t* parser, instruction_t* instruction) {
    memset(instruction, 0, sizeof(instruction_t));
    instruction->line = parser->current_token.line;
    
    // Skip empty lines and comments
    while (parser->current_token.type == TOKEN_NEWLINE) {
        parser_advance(parser);
    }
    
    if (parser->current_token.type == TOKEN_EOF) {
        return false;
    }
    
    // Handle directives
    if (parser->current_token.type == TOKEN_DIRECTIVE) {
        // Attempt to parse directive
        if (!parser_parse_directive(parser)) {
            return false; // Error already reported by parser_parse_directive
        }
        // Skip rest of line
        while (parser->current_token.type != TOKEN_NEWLINE && parser->current_token.type != TOKEN_EOF) {
            parser_advance(parser);
        }
        return true;
    }
      // Handle labels
    if (parser->current_token.type == TOKEN_LABEL) {
        token_t next = lexer_peek_token(parser->lexer);
        if (next.type != TOKEN_INSTRUCTION) {
            // This is a label definition - only define on pass 1
            if (parser->assembler->pass == 1) {
                symbol_define(parser->assembler, parser->current_token.value, 
                             codegen_get_current_address(parser->assembler));
            }
            parser_advance(parser);
              // Check for colon after label
            if (parser->current_token.type == TOKEN_COLON) {
                parser_advance(parser);
            }
            
            // Continue parsing if there's an instruction on the same line
            if (parser->current_token.type != TOKEN_INSTRUCTION) {
                return true;
            }
        }
    }
      // Parse instruction (with REP prefix support)
    if (parser->current_token.type == TOKEN_INSTRUCTION) {
        // Check if this is a REP prefix
        if (parser_is_rep_prefix(parser->current_token.value)) {
            // Handle REP prefix
            if (!parser_parse_rep_instruction(parser, instruction)) {
                return false;
            }
        } else {
            // Regular instruction
            strncpy(instruction->mnemonic, parser->current_token.value, sizeof(instruction->mnemonic) - 1);
            instruction->mnemonic[sizeof(instruction->mnemonic) - 1] = '\0';
            
            // Validate that it's a known instruction
            if (!is_valid_instruction(instruction->mnemonic)) {
                assembler_error(parser->assembler, "Unknown instruction '%s' at line %d", 
                               instruction->mnemonic, parser->current_token.line);
                return false;
            }
            
            parser_advance(parser);
        }
        
        // Parse operands
        while (parser->current_token.type != TOKEN_NEWLINE && 
               parser->current_token.type != TOKEN_EOF &&
               instruction->operand_count < 3) {
            
            operand_t operand = parser_parse_operand(parser);
            if (operand.type == OPERAND_NONE) {
                assembler_error(parser->assembler, "Invalid operand in instruction '%s' at line %d", 
                               instruction->mnemonic, parser->current_token.line);
                return false;
            }
            instruction->operands[instruction->operand_count++] = operand;
            
            // Check for comma separator
            if (parser->current_token.type == TOKEN_COMMA) {
                parser_advance(parser);
                // Make sure there's another operand after comma
                if (parser->current_token.type == TOKEN_NEWLINE || parser->current_token.type == TOKEN_EOF) {
                    assembler_error(parser->assembler, "Expected operand after comma in instruction '%s' at line %d", 
                                   instruction->mnemonic, parser->current_token.line);
                    return false;
                }
            } else {
                break;
            }
        }
        
        // Check if we have too many operands
        if (instruction->operand_count >= 3 && 
            parser->current_token.type != TOKEN_NEWLINE && 
            parser->current_token.type != TOKEN_EOF &&
            parser->current_token.type == TOKEN_COMMA) {
            assembler_error(parser->assembler, "Too many operands for instruction '%s' at line %d", 
                           instruction->mnemonic, parser->current_token.line);
            return false;
        }
        
        return true;
    }
    
    // Handle unknown tokens
    if (parser->current_token.type == TOKEN_UNKNOWN) {
        assembler_error(parser->assembler, "Unexpected character '%s' at line %d", 
                       parser->current_token.value, parser->current_token.line);
        return false;
    }
    
    // If we get here, we have an unexpected token type
    assembler_error(parser->assembler, "Unexpected token at line %d", parser->current_token.line);
    return false;
}

// Expression evaluation functions (simple recursive descent parser)
static int32_t parser_evaluate_factor(parser_t* parser) {
    int32_t value = 0;
    
    switch (parser->current_token.type) {
        case TOKEN_IMMEDIATE:
            value = parser_parse_immediate(parser);
            break;
              case TOKEN_LABEL:
            // Handle special symbols like $ (current address) and $$ (section start)
            if (strcmp(parser->current_token.value, "$") == 0) {
                // Return the relative offset from origin (size of assembled code so far)
                value = (int32_t)(codegen_get_current_address(parser->assembler) - parser->assembler->origin);
                parser_advance(parser);
            } else if (strcmp(parser->current_token.value, "$$") == 0) {
                value = (int32_t)parser->assembler->origin;
                parser_advance(parser);
            } else {
                // Look up symbol
                symbol_t* symbol = symbol_lookup(parser->assembler, parser->current_token.value);
                if (symbol && symbol->defined) {
                    value = (int32_t)symbol->address;
                } else {
                    assembler_error(parser->assembler, "Undefined symbol '%s' at line %d", 
                                   parser->current_token.value, parser->current_token.line);
                    return 0;
                }
                parser_advance(parser);
            }
            break;
            
        case TOKEN_LPAREN:
            parser_advance(parser); // consume '('
            value = parser_evaluate_expression(parser);
            if (!parser_expect_token(parser, TOKEN_RPAREN)) {
                assembler_error(parser->assembler, "Expected ')' in expression at line %d", 
                               parser->current_token.line);
                return 0;
            }
            break;
            
        default:
            assembler_error(parser->assembler, "Unexpected token '%s' in expression at line %d", 
                           parser->current_token.value, parser->current_token.line);
            return 0;
    }
    
    return value;
}

static int32_t parser_evaluate_term(parser_t* parser) {
    int32_t left = parser_evaluate_factor(parser);
    
    while (parser->current_token.type == TOKEN_MULTIPLY || 
           parser->current_token.type == TOKEN_DIVIDE) {
        token_type_t op = parser->current_token.type;
        parser_advance(parser);
        int32_t right = parser_evaluate_factor(parser);
        
        if (op == TOKEN_MULTIPLY) {
            left *= right;
        } else {
            if (right == 0) {
                assembler_error(parser->assembler, "Division by zero in expression at line %d", 
                               parser->current_token.line);
                return 0;
            }
            left /= right;
        }
    }
    
    return left;
}

int32_t parser_evaluate_expression(parser_t* parser) {
    int32_t left = parser_evaluate_term(parser);
    
    while (parser->current_token.type == TOKEN_PLUS || 
           parser->current_token.type == TOKEN_MINUS) {
        token_type_t op = parser->current_token.type;
        parser_advance(parser);
        int32_t right = parser_evaluate_term(parser);
        
        if (op == TOKEN_PLUS) {
            left += right;
        } else {
            left -= right;
        }
    }
    
    return left;
}

// REP prefix helper functions
bool parser_is_rep_prefix(const char* mnemonic) {
    return strcmp(mnemonic, "rep") == 0 ||
           strcmp(mnemonic, "repe") == 0 ||
           strcmp(mnemonic, "repz") == 0 ||
           strcmp(mnemonic, "repne") == 0 ||
           strcmp(mnemonic, "repnz") == 0;
}

bool parser_is_string_operation(const char* mnemonic) {
    return strcmp(mnemonic, "movsb") == 0 ||
           strcmp(mnemonic, "movsw") == 0 ||
           strcmp(mnemonic, "cmpsb") == 0 ||
           strcmp(mnemonic, "cmpsw") == 0 ||
           strcmp(mnemonic, "scasb") == 0 ||
           strcmp(mnemonic, "scasw") == 0 ||
           strcmp(mnemonic, "stosb") == 0 ||
           strcmp(mnemonic, "stosw") == 0 ||
           strcmp(mnemonic, "lodsb") == 0 ||
           strcmp(mnemonic, "lodsw") == 0;
}

bool parser_parse_rep_instruction(parser_t* parser, instruction_t* instruction) {
    // Store the REP prefix
    char rep_prefix[16];
    strncpy(rep_prefix, parser->current_token.value, sizeof(rep_prefix) - 1);
    rep_prefix[sizeof(rep_prefix) - 1] = '\0';
    
    // Advance past the REP prefix
    parser_advance(parser);
    
    // Next token should be a string operation
    if (parser->current_token.type != TOKEN_INSTRUCTION) {
        assembler_error(parser->assembler, "Expected string operation after REP prefix '%s' at line %d", 
                       rep_prefix, parser->current_token.line);
        return false;
    }
    
    // Check if it's a valid string operation
    if (!parser_is_string_operation(parser->current_token.value)) {
        assembler_error(parser->assembler, "Invalid string operation '%s' after REP prefix '%s' at line %d", 
                       parser->current_token.value, rep_prefix, parser->current_token.line);
        return false;
    }
    
    // For REPE/REPZ and REPNE/REPNZ, only allow compare and scan operations
    if ((strcmp(rep_prefix, "repe") == 0 || strcmp(rep_prefix, "repz") == 0 ||
         strcmp(rep_prefix, "repne") == 0 || strcmp(rep_prefix, "repnz") == 0)) {
        if (!(strncmp(parser->current_token.value, "cmps", 4) == 0 ||
              strncmp(parser->current_token.value, "scas", 4) == 0)) {
            assembler_error(parser->assembler, "REP prefix '%s' can only be used with compare/scan operations, not '%s' at line %d", 
                           rep_prefix, parser->current_token.value, parser->current_token.line);
            return false;
        }
    }
    
    // Create combined mnemonic for the instruction (e.g., "rep_movsb")
    snprintf(instruction->mnemonic, sizeof(instruction->mnemonic), "%s_%s", 
             rep_prefix, parser->current_token.value);
    
    // Advance past the string operation
    parser_advance(parser);
    
    return true;
}
