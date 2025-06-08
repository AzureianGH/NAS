#ifndef CODEGEN_H
#define CODEGEN_H

#include "nas.h"

// Code generation functions
bool codegen_generate_instruction(assembler_t *asm_ctx, const instruction_t *instr);
bool codegen_emit_byte(assembler_t *asm_ctx, uint8_t byte);
bool codegen_emit_word(assembler_t *asm_ctx, uint16_t word);
bool codegen_emit_dword(assembler_t *asm_ctx, uint32_t dword);
bool codegen_emit_bytes(assembler_t *asm_ctx, const uint8_t *bytes, size_t count);

// Address calculation
uint32_t codegen_get_current_address(assembler_t *asm_ctx);
void codegen_set_address(assembler_t *asm_ctx, uint32_t address);
bool codegen_align(assembler_t *asm_ctx, int alignment);

// Buffer management
bool codegen_ensure_capacity(assembler_t *asm_ctx, size_t additional_size);
void codegen_reset(assembler_t *asm_ctx);

#endif // CODEGEN_H
