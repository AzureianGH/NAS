#include "nas.h"
#include <stdarg.h>

assembler_t* assembler_create(void) {
    assembler_t* asm_ctx = malloc(sizeof(assembler_t));
    if (!asm_ctx) return NULL;
    
    memset(asm_ctx, 0, sizeof(assembler_t));
    
    // Default settings
    asm_ctx->mode = MODE_16BIT;
    asm_ctx->cmdline_mode = MODE_16BIT;
    asm_ctx->cmdline_mode_set = false;
    asm_ctx->directive_mode_set = false;    asm_ctx->format = FORMAT_BIN;
    asm_ctx->origin = 0x7C00; // Default boot sector origin
    asm_ctx->current_address = asm_ctx->origin;
    asm_ctx->pass = 1; // Initialize to pass 1
    
    // Allocate initial code buffer
    asm_ctx->code_capacity = 65536; // 64KB initial capacity
    asm_ctx->code_buffer = malloc(asm_ctx->code_capacity);
    if (!asm_ctx->code_buffer) {
        free(asm_ctx);
        return NULL;
    }
    
    return asm_ctx;
}

void assembler_destroy(assembler_t* asm_ctx) {
    if (asm_ctx) {
        if (asm_ctx->code_buffer) {
            free(asm_ctx->code_buffer);
        }
        if (asm_ctx->symbols) {
            symbol_table_destroy(asm_ctx->symbols);
        }
        if (asm_ctx->input && asm_ctx->input != stdin) {
            fclose(asm_ctx->input);
        }
        if (asm_ctx->output && asm_ctx->output != stdout) {
            fclose(asm_ctx->output);
        }
        free(asm_ctx);
    }
}

bool assembler_set_mode(assembler_t* asm_ctx, asm_mode_t mode) {
    asm_ctx->mode = mode;
    return true;
}

bool assembler_set_cmdline_mode(assembler_t* asm_ctx, asm_mode_t mode) {
    asm_ctx->cmdline_mode = mode;
    asm_ctx->cmdline_mode_set = true;
    asm_ctx->mode = mode;  // Also set the current mode
    return true;
}

bool assembler_set_format(assembler_t* asm_ctx, output_format_t format) {
    asm_ctx->format = format;
    return true;
}

bool assembler_set_origin(assembler_t* asm_ctx, uint32_t origin) {
    asm_ctx->origin = origin;
    asm_ctx->current_address = origin;
    return true;
}

// Symbol table functions
void symbol_table_dump(assembler_t* asm_ctx) {
    if (!asm_ctx->verbose) return;
    
    printf("DEBUG: Symbol table contents:\n");
    symbol_t* current = asm_ctx->symbols;
    int count = 0;
    while (current) {
        printf("  %d: '%s' -> 0x%04X (defined=%s)\n", 
               ++count, current->name, current->address, current->defined ? "true" : "false");
        current = current->next;
    }
    if (count == 0) {
        printf("  (empty)\n");
    }
}

symbol_t* symbol_lookup(assembler_t* asm_ctx, const char* name) {
    symbol_t* current = asm_ctx->symbols;
    while (current) {
        if (strcmp(current->name, name) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

bool symbol_define(assembler_t* asm_ctx, const char* name, uint32_t address) {
    symbol_t* existing = symbol_lookup(asm_ctx, name);
    if (existing) {
        if (existing->defined) {
            return false; // Symbol already defined
        }
        existing->address = address;
        existing->defined = true;
        return true;
    }
    
    symbol_t* new_symbol = malloc(sizeof(symbol_t));
    if (!new_symbol) return false;
    
    strncpy(new_symbol->name, name, MAX_LABEL_LENGTH - 1);
    new_symbol->name[MAX_LABEL_LENGTH - 1] = '\0';
    new_symbol->address = address;
    new_symbol->defined = true;
    new_symbol->next = asm_ctx->symbols;
    asm_ctx->symbols = new_symbol;
    
    return true;
}

bool symbol_reference(assembler_t* asm_ctx, const char* name) {
    symbol_t* existing = symbol_lookup(asm_ctx, name);
    if (existing) {
        return true;
    }
    
    // Create undefined symbol
    symbol_t* new_symbol = malloc(sizeof(symbol_t));
    if (!new_symbol) return false;
    
    strncpy(new_symbol->name, name, MAX_LABEL_LENGTH - 1);
    new_symbol->name[MAX_LABEL_LENGTH - 1] = '\0';
    new_symbol->address = 0;
    new_symbol->defined = false;
    new_symbol->next = asm_ctx->symbols;
    asm_ctx->symbols = new_symbol;
    
    return true;
}

void symbol_table_destroy(symbol_t* symbols) {
    while (symbols) {
        symbol_t* next = symbols->next;
        free(symbols);
        symbols = next;
    }
}

// Output functions
bool output_write_binary(assembler_t* asm_ctx) {
    if (!asm_ctx->output) return false;
    
    size_t written = fwrite(asm_ctx->code_buffer, 1, asm_ctx->code_size, asm_ctx->output);
    return written == asm_ctx->code_size;
}

bool output_write_hex(assembler_t* asm_ctx) {
    if (!asm_ctx->output) return false;
    
    for (size_t i = 0; i < asm_ctx->code_size; i++) {
        fprintf(asm_ctx->output, "%02X ", asm_ctx->code_buffer[i]);
        if ((i + 1) % 16 == 0) {
            fprintf(asm_ctx->output, "\n");
        }
    }
    
    if (asm_ctx->code_size % 16 != 0) {
        fprintf(asm_ctx->output, "\n");
    }
    
    return true;
}

// Error handling
void assembler_error(assembler_t* asm_ctx, const char* format, ...) {
    asm_ctx->error_occurred = true;
    va_list args;
    va_start(args, format);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void assembler_warning(assembler_t* asm_ctx, const char* format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "Warning: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

static char* read_file_content(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) return NULL;
    
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* content = malloc(length + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    
    fread(content, 1, length, file);
    content[length] = '\0';
    fclose(file);
    
    return content;
}

static bool assembler_pass(assembler_t* asm_ctx, const char* input_content, int pass) {
    // Create lexer and parser for this pass
    lexer_t* lexer = lexer_create(input_content);
    if (!lexer) {
        assembler_error(asm_ctx, "Failed to create lexer for pass %d", pass);
        return false;
    }
    
    parser_t* parser = parser_create(lexer, asm_ctx);
    if (!parser) {
        assembler_error(asm_ctx, "Failed to create parser for pass %d", pass);
        lexer_destroy(lexer);
        return false;
    }
    
    asm_ctx->pass = pass;
    bool success = true;
    instruction_t instruction;
    
    // Reset address tracking for each pass
    asm_ctx->current_address = asm_ctx->origin;
    if (pass == 2) {
        codegen_reset(asm_ctx);  // Only reset code buffer on pass 2
    }
      if (asm_ctx->verbose) {
        printf("Starting pass %d...\n", pass);
        if (pass == 2) {
            symbol_table_dump(asm_ctx);
        }
    }
    
    // Process all lines
    while (true) {
        bool parsed = parser_parse_line(parser, &instruction);
        if (!parsed) {
            break; // no more lines or reached EOF, or parsing error occurred
        }
        
        // Check if an error occurred during parsing
        if (asm_ctx->error_occurred) {
            success = false;
            break;
        }
          // On pass 1, we just collect labels and calculate sizes
        // On pass 2, we generate actual code
        if (instruction.mnemonic[0] != '\0') {
            if (pass == 1) {
                // Pass 1: Just calculate instruction size to advance address
                uint8_t dummy_buffer[16];
                size_t size = 0;
                generate_opcode(&instruction, dummy_buffer, &size, asm_ctx);
                asm_ctx->current_address += size;
            } else {
                // Pass 2: Generate actual code (codegen_generate_instruction advances address)
                if (!codegen_generate_instruction(asm_ctx, &instruction)) {
                    assembler_error(asm_ctx, "Failed to generate code for instruction '%s' at line %d", 
                                   instruction.mnemonic, instruction.line);
                    success = false;
                    break;
                }
            }
        }
    }
    
    // Cleanup
    parser_destroy(parser);
    lexer_destroy(lexer);
    
    if (asm_ctx->verbose) {
        printf("Pass %d completed. Current address: 0x%x\n", pass, asm_ctx->current_address);
    }
    
    return success;
}bool assembler_assemble_file(assembler_t* asm_ctx, const char* input_file, const char* output_file) {
    // Read input file
    char* input_content = read_file_content(input_file);
    if (!input_content) {
        assembler_error(asm_ctx, "Failed to read input file: %s", input_file);
        return false;
    }
    
    // Open output file
    asm_ctx->output = fopen(output_file, "wb");
    if (!asm_ctx->output) {
        assembler_error(asm_ctx, "Failed to open output file: %s", output_file);
        free(input_content);
        return false;
    }
    
    bool success = true;
    
    // Pass 1: Collect all labels and their addresses
    if (!assembler_pass(asm_ctx, input_content, 1)) {
        success = false;
        goto cleanup;
    }
    
    // Pass 2: Generate actual machine code with correct addresses
    if (!assembler_pass(asm_ctx, input_content, 2)) {
        success = false;
        goto cleanup;
    }
    
    // Write output
    if (success) {
        switch (asm_ctx->format) {
            case FORMAT_BIN:
                success = output_write_binary(asm_ctx);
                break;
            case FORMAT_HEX:
                success = output_write_hex(asm_ctx);
                break;
            default:
                success = false;
                break;
        }
    }
    
cleanup:
    free(input_content);
    fclose(asm_ctx->output);
    asm_ctx->output = NULL;
    
    if (success && asm_ctx->verbose) {
        printf("Assembly completed successfully. Output size: %zu bytes\n", asm_ctx->code_size);
    }
    
    return success;
}
