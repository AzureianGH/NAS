#ifndef INSTRUCTION_SET_H
#define INSTRUCTION_SET_H

#include "nas.h"

// Instruction encoding types
typedef enum
{
    ENC_NONE,
    ENC_SINGLE,     // Single byte opcode (cli, sti, ret)    
    ENC_REG_REG,    // Register to register (mov ax, bx)
    ENC_REG_IMM,    // Register immediate (mov ax, 0x1234)
    ENC_REG_MEM,    // Register memory (mov ax, [bx])
    ENC_MEM_REG,    // Memory register (mov [bx], ax)
    ENC_MEM_IMM,    // Memory immediate (mov [bx], 0x1234)
    ENC_PUSH_REG,   // Push register
    ENC_POP_REG,    // Pop register
    ENC_PUSH_IMM,   // Push immediate
    ENC_PUSH_MEM,   // Push memory
    ENC_CALL_REL,   // Call relative
    ENC_JMP_REL,    // Jump relative
    ENC_INT_IMM,    // Interrupt immediate
    ENC_REP_STRING, // REP prefix + string operation
    ENC_TWO_BYTE_MEM, // Two-byte instruction with memory operand (0x0F xx /r)
    ENC_SPECIAL     // Special handling required
} encoding_type_t;

// Instruction definition
typedef struct
{
    char mnemonic[16];
    encoding_type_t encoding;
    uint16_t opcode;
    uint8_t modrm_reg; // For instructions that use ModR/M byte
    bool has_modrm;
    bool has_displacement;
    bool has_immediate;
    int operand_count;
} instruction_def_t;

// Instruction set functions
const instruction_def_t *find_instruction(const char *mnemonic);
bool is_valid_instruction(const char *mnemonic);

// ModR/M byte construction
uint8_t make_modrm(uint8_t mod, uint8_t reg, uint8_t rm);
uint8_t register_to_modrm(register_t reg);
uint8_t get_base_index_rm(register_t base_reg, register_t index_reg);
int get_register_size(register_t reg);

// Opcode generation
bool generate_opcode(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx);

#endif // INSTRUCTION_SET_H
