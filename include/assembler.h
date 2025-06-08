#ifndef ASSEMBLER_H
#define ASSEMBLER_H

#include "nas.h"

// Assembler functions
assembler_t* assembler_create(void);
void assembler_destroy(assembler_t* asm_ctx);
bool assembler_assemble_file(assembler_t* asm_ctx, const char* input_file, const char* output_file);
bool assembler_set_mode(assembler_t* asm_ctx, asm_mode_t mode);
bool assembler_set_cmdline_mode(assembler_t* asm_ctx, asm_mode_t mode);
bool assembler_set_format(assembler_t* asm_ctx, output_format_t format);
bool assembler_set_origin(assembler_t* asm_ctx, uint32_t origin);

// Symbol table functions
symbol_t* symbol_lookup(assembler_t* asm_ctx, const char* name);
bool symbol_define(assembler_t* asm_ctx, const char* name, uint32_t address);
bool symbol_reference(assembler_t* asm_ctx, const char* name);
void symbol_table_destroy(symbol_t* symbols);
void symbol_table_dump(assembler_t* asm_ctx);
bool symbol_check_undefined(assembler_t* asm_ctx);

// Output functions
bool output_write_binary(assembler_t* asm_ctx);
bool output_write_hex(assembler_t* asm_ctx);

// Error handling
void assembler_error(assembler_t* asm_ctx, const char* format, ...);
void assembler_warning(assembler_t* asm_ctx, const char* format, ...);

#endif // ASSEMBLER_H
