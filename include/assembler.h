#ifndef ASSEMBLER_H
#define ASSEMBLER_H

#include "nas.h"

// Relocation types
// i386 relocation types
#define R_386_NONE 0 // No reloc
#define R_386_32 1   // Direct 32 bit
#define R_386_PC32 2 // PC relative 32 bit

// x86-64 relocation types
// x86-64 relocation types
#define R_X86_64_NONE 0     // No reloc
#define R_X86_64_64 1       // Direct 64 bit
#define R_X86_64_PC32 2     // PC relative 32 bit signed
#define R_X86_64_GOT32 3    // 32 bit GOT entry
#define R_X86_64_PLT32 4    // 32 bit PLT address
#define R_X86_64_32 10      // Direct 32 bit zero extended
#define R_X86_64_32S 11     // Direct 32 bit sign extended

// Assembler functions
assembler_t *assembler_create(void);
void assembler_destroy(assembler_t *asm_ctx);
bool assembler_assemble_file(assembler_t *asm_ctx, const char *input_file, const char *output_file);
bool assembler_set_mode(assembler_t *asm_ctx, asm_mode_t mode);
bool assembler_set_cmdline_mode(assembler_t *asm_ctx, asm_mode_t mode);
bool assembler_set_format(assembler_t *asm_ctx, output_format_t format);
bool assembler_set_origin(assembler_t *asm_ctx, uint32_t origin);

// Symbol table functions
symbol_t *symbol_lookup(assembler_t *asm_ctx, const char *name);
bool symbol_define(assembler_t *asm_ctx, const char *name, uint32_t address);
bool symbol_reference(assembler_t *asm_ctx, const char *name);
bool symbol_mark_global(assembler_t *asm_ctx, const char *name);
bool symbol_mark_external(assembler_t *asm_ctx, const char *name);
void symbol_table_destroy(symbol_t *symbols);
void symbol_table_dump(assembler_t *asm_ctx);
bool symbol_check_undefined(assembler_t *asm_ctx);

// Section management functions
section_t *section_create(const char *name, section_type_t type);
bool section_add(assembler_t *asm_ctx, section_t *section);
section_t *section_find(assembler_t *asm_ctx, const char *name);
bool section_switch(assembler_t *asm_ctx, const char *name);
void section_table_destroy(section_t *sections);
section_t *section_get_current(assembler_t *asm_ctx);
void section_calculate_addresses(assembler_t *asm_ctx);
size_t section_get_total_size(assembler_t *asm_ctx);

// Output functions
bool output_write_binary(assembler_t *asm_ctx);
bool output_write_hex(assembler_t *asm_ctx);
bool output_write_elf(assembler_t *asm_ctx);

// Relocation management functions
void relocation_add(assembler_t *asm_ctx, uint32_t offset, const char *symbol_name, int relocation_type, section_type_t section, int64_t addend);
void relocation_table_destroy(relocation_t *relocations);

// Error handling
void assembler_error(assembler_t *asm_ctx, const char *format, ...);
void assembler_warning(assembler_t *asm_ctx, const char *format, ...);

#endif // ASSEMBLER_H
