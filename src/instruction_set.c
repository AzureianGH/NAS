#include "nas.h"
#include "assembler.h"
#include <string.h>

// Instruction definitions for 16-bit x86
static const instruction_def_t instruction_table[] = { // Data movement
    {"mov", ENC_REG_REG, 0x89, 0, true, false, false, 2},
    {"push", ENC_PUSH_REG, 0x50, 0, false, false, false, 1},
    {"push", ENC_PUSH_MEM, 0xFF, 6, true, false, false, 1},
    {"pop", ENC_POP_REG, 0x58, 0, false, false, false, 1},
    {"xchg", ENC_REG_REG, 0x87, 0, true, false, false, 2},
    {"lea", ENC_REG_MEM, 0x8D, 0, true, false, false, 2},

    // Arithmetic - register to register
    {"add", ENC_REG_REG, 0x01, 0, true, false, false, 2},
    {"sub", ENC_REG_REG, 0x29, 0, true, false, false, 2},
    {"xor", ENC_REG_REG, 0x31, 0, true, false, false, 2},
    {"cmp", ENC_REG_REG, 0x39, 0, true, false, false, 2},
    {"and", ENC_REG_REG, 0x21, 0, true, false, false, 2},
    {"or", ENC_REG_REG, 0x09, 0, true, false, false, 2},
    {"adc", ENC_REG_REG, 0x11, 0, true, false, false, 2},
    {"sbb", ENC_REG_REG, 0x19, 0, true, false, false, 2},
    {"test", ENC_REG_REG, 0x85, 0, true, false, false, 2},

    // Arithmetic - register with immediate
    {"add", ENC_REG_IMM, 0x83, 0, true, false, true, 2},
    {"sub", ENC_REG_IMM, 0x83, 5, true, false, true, 2},
    {"xor", ENC_REG_IMM, 0x83, 6, true, false, true, 2},
    {"cmp", ENC_REG_IMM, 0x83, 7, true, false, true, 2},
    {"and", ENC_REG_IMM, 0x83, 4, true, false, true, 2},
    {"or", ENC_REG_IMM, 0x83, 1, true, false, true, 2},
    {"adc", ENC_REG_IMM, 0x83, 2, true, false, true, 2},
    {"sbb", ENC_REG_IMM, 0x83, 3, true, false, true, 2},
    {"test", ENC_REG_IMM, 0xF7, 0, true, false, true, 2},

    // Multiplication and Division
    {"mul", ENC_SPECIAL, 0xF7, 4, true, false, false, 1},
    {"imul", ENC_SPECIAL, 0xF7, 5, true, false, false, 1},
    {"div", ENC_SPECIAL, 0xF7, 6, true, false, false, 1},
    {"idiv", ENC_SPECIAL, 0xF7, 7, true, false, false, 1},

    // Increment/Decrement
    {"inc", ENC_SPECIAL, 0x40, 0, false, false, false, 1}, // INC reg16 (0x40+r)
    {"dec", ENC_SPECIAL, 0x48, 0, false, false, false, 1}, // DEC reg16 (0x48+r)

    // Bit manipulation and shifts
    {"shl", ENC_SPECIAL, 0xD3, 4, true, false, false, 2},
    {"shr", ENC_SPECIAL, 0xD3, 5, true, false, false, 2},
    {"sal", ENC_SPECIAL, 0xD3, 4, true, false, false, 2}, // Same as SHL
    {"sar", ENC_SPECIAL, 0xD3, 7, true, false, false, 2},
    {"rol", ENC_SPECIAL, 0xD3, 0, true, false, false, 2},
    {"ror", ENC_SPECIAL, 0xD3, 1, true, false, false, 2},
    {"rcl", ENC_SPECIAL, 0xD3, 2, true, false, false, 2},
    {"rcr", ENC_SPECIAL, 0xD3, 3, true, false, false, 2},

    // Logical operations (NOT, NEG)
    {"not", ENC_SPECIAL, 0xF7, 2, true, false, false, 1},
    {"neg", ENC_SPECIAL, 0xF7, 3, true, false, false, 1},

    // Control flow - conditional jumps (8-bit displacement)
    {"jmp", ENC_JMP_REL, 0xEB, 0, false, true, true, 1}, // Short jump
    {"je", ENC_JMP_REL, 0x74, 0, false, true, true, 1},
    {"jne", ENC_JMP_REL, 0x75, 0, false, true, true, 1},
    {"jz", ENC_JMP_REL, 0x74, 0, false, true, true, 1},
    {"jnz", ENC_JMP_REL, 0x75, 0, false, true, true, 1},
    {"jb", ENC_JMP_REL, 0x72, 0, false, true, true, 1},
    {"jnb", ENC_JMP_REL, 0x73, 0, false, true, true, 1},
    {"jc", ENC_JMP_REL, 0x72, 0, false, true, true, 1},  // Same as JB
    {"jnc", ENC_JMP_REL, 0x73, 0, false, true, true, 1}, // Same as JNB
    {"ja", ENC_JMP_REL, 0x77, 0, false, true, true, 1},
    {"jna", ENC_JMP_REL, 0x76, 0, false, true, true, 1},
    {"jae", ENC_JMP_REL, 0x73, 0, false, true, true, 1},  // Same as JNB
    {"jnae", ENC_JMP_REL, 0x72, 0, false, true, true, 1}, // Same as JB
    {"jbe", ENC_JMP_REL, 0x76, 0, false, true, true, 1},  // Same as JNA
    {"jnbe", ENC_JMP_REL, 0x77, 0, false, true, true, 1}, // Same as JA
    {"jl", ENC_JMP_REL, 0x7C, 0, false, true, true, 1},
    {"jnl", ENC_JMP_REL, 0x7D, 0, false, true, true, 1},
    {"jle", ENC_JMP_REL, 0x7E, 0, false, true, true, 1},
    {"jnle", ENC_JMP_REL, 0x7F, 0, false, true, true, 1},
    {"jg", ENC_JMP_REL, 0x7F, 0, false, true, true, 1},   // Same as JNLE
    {"jng", ENC_JMP_REL, 0x7E, 0, false, true, true, 1},  // Same as JLE
    {"jge", ENC_JMP_REL, 0x7D, 0, false, true, true, 1},  // Same as JNL
    {"jnge", ENC_JMP_REL, 0x7C, 0, false, true, true, 1}, // Same as JL
    {"js", ENC_JMP_REL, 0x78, 0, false, true, true, 1},
    {"jns", ENC_JMP_REL, 0x79, 0, false, true, true, 1},
    {"jo", ENC_JMP_REL, 0x70, 0, false, true, true, 1},
    {"jno", ENC_JMP_REL, 0x71, 0, false, true, true, 1},
    {"jp", ENC_JMP_REL, 0x7A, 0, false, true, true, 1},
    {"jnp", ENC_JMP_REL, 0x7B, 0, false, true, true, 1},
    {"jpe", ENC_JMP_REL, 0x7A, 0, false, true, true, 1}, // Same as JP
    {"jpo", ENC_JMP_REL, 0x7B, 0, false, true, true, 1}, // Same as JNP

    // Control flow - calls and returns
    {"call", ENC_CALL_REL, 0xE8, 0, false, true, true, 1},
    {"ret", ENC_SINGLE, 0xC3, 0, false, false, false, 0},
    {"retf", ENC_SINGLE, 0xCB, 0, false, false, false, 0}, // Far return
    {"retn", ENC_SPECIAL, 0xC2, 0, false, false, true, 1}, // Return with immediate

    // Loop instructions
    {"loop", ENC_JMP_REL, 0xE2, 0, false, true, true, 1},
    {"loope", ENC_JMP_REL, 0xE1, 0, false, true, true, 1},
    {"loopz", ENC_JMP_REL, 0xE1, 0, false, true, true, 1}, // Same as LOOPE
    {"loopne", ENC_JMP_REL, 0xE0, 0, false, true, true, 1},
    {"loopnz", ENC_JMP_REL, 0xE0, 0, false, true, true, 1}, // Same as LOOPNE
    {"jcxz", ENC_JMP_REL, 0xE3, 0, false, true, true, 1},   // String operations
    {"movsb", ENC_SINGLE, 0xA4, 0, false, false, false, 0},
    {"movsw", ENC_SINGLE, 0xA5, 0, false, false, false, 0},
    {"movsd", ENC_SINGLE, 0xA5, 0, false, false, false, 0}, // 32-bit move
    {"movsq", ENC_SINGLE, 0xA5, 0, false, false, false, 0}, // 64-bit move (with REX.W)
    {"cmpsb", ENC_SINGLE, 0xA6, 0, false, false, false, 0},
    {"cmpsw", ENC_SINGLE, 0xA7, 0, false, false, false, 0},
    {"cmpsd", ENC_SINGLE, 0xA7, 0, false, false, false, 0}, // 32-bit compare
    {"cmpsq", ENC_SINGLE, 0xA7, 0, false, false, false, 0}, // 64-bit compare (with REX.W)
    {"scasb", ENC_SINGLE, 0xAE, 0, false, false, false, 0},
    {"scasw", ENC_SINGLE, 0xAF, 0, false, false, false, 0},
    {"scasd", ENC_SINGLE, 0xAF, 0, false, false, false, 0}, // 32-bit scan
    {"scasq", ENC_SINGLE, 0xAF, 0, false, false, false, 0}, // 64-bit scan (with REX.W)
    {"lodsb", ENC_SINGLE, 0xAC, 0, false, false, false, 0},
    {"lodsw", ENC_SINGLE, 0xAD, 0, false, false, false, 0},
    {"lodsd", ENC_SINGLE, 0xAD, 0, false, false, false, 0}, // 32-bit load
    {"lodsq", ENC_SINGLE, 0xAD, 0, false, false, false, 0}, // 64-bit load (with REX.W)
    {"stosb", ENC_SINGLE, 0xAA, 0, false, false, false, 0},
    {"stosw", ENC_SINGLE, 0xAB, 0, false, false, false, 0},
    {"stosd", ENC_SINGLE, 0xAB, 0, false, false, false, 0}, // 32-bit store
    {"stosq", ENC_SINGLE, 0xAB, 0, false, false, false, 0}, // 64-bit store (with REX.W)

    // String prefixes
    {"rep", ENC_SINGLE, 0xF3, 0, false, false, false, 0},
    {"repe", ENC_SINGLE, 0xF3, 0, false, false, false, 0}, // Same as REP
    {"repz", ENC_SINGLE, 0xF3, 0, false, false, false, 0}, // Same as REP
    {"repne", ENC_SINGLE, 0xF2, 0, false, false, false, 0},
    {"repnz", ENC_SINGLE, 0xF2, 0, false, false, false, 0}, // Same as REPNE

    // REP prefix + string operation combinations
    {"rep_movsb", ENC_REP_STRING, 0xF3A4, 0, false, false, false, 0},
    {"rep_movsw", ENC_REP_STRING, 0xF3A5, 0, false, false, false, 0},
    {"rep_stosb", ENC_REP_STRING, 0xF3AA, 0, false, false, false, 0},
    {"rep_stosw", ENC_REP_STRING, 0xF3AB, 0, false, false, false, 0},
    {"rep_lodsb", ENC_REP_STRING, 0xF3AC, 0, false, false, false, 0},
    {"rep_lodsw", ENC_REP_STRING, 0xF3AD, 0, false, false, false, 0},
    {"repe_cmpsb", ENC_REP_STRING, 0xF3A6, 0, false, false, false, 0},
    {"repe_cmpsw", ENC_REP_STRING, 0xF3A7, 0, false, false, false, 0},
    {"repe_scasb", ENC_REP_STRING, 0xF3AE, 0, false, false, false, 0},
    {"repe_scasw", ENC_REP_STRING, 0xF3AF, 0, false, false, false, 0},
    {"repz_cmpsb", ENC_REP_STRING, 0xF3A6, 0, false, false, false, 0}, // Same as REPE
    {"repz_cmpsw", ENC_REP_STRING, 0xF3A7, 0, false, false, false, 0}, // Same as REPE
    {"repz_scasb", ENC_REP_STRING, 0xF3AE, 0, false, false, false, 0}, // Same as REPE
    {"repz_scasw", ENC_REP_STRING, 0xF3AF, 0, false, false, false, 0}, // Same as REPE
    {"repne_cmpsb", ENC_REP_STRING, 0xF2A6, 0, false, false, false, 0},
    {"repne_cmpsw", ENC_REP_STRING, 0xF2A7, 0, false, false, false, 0},
    {"repne_scasb", ENC_REP_STRING, 0xF2AE, 0, false, false, false, 0},
    {"repne_scasw", ENC_REP_STRING, 0xF2AF, 0, false, false, false, 0},
    {"repnz_cmpsb", ENC_REP_STRING, 0xF2A6, 0, false, false, false, 0}, // Same as REPNE
    {"repnz_cmpsw", ENC_REP_STRING, 0xF2A7, 0, false, false, false, 0}, // Same as REPNE
    {"repnz_scasb", ENC_REP_STRING, 0xF2AE, 0, false, false, false, 0}, // Same as REPNE
    {"repnz_scasw", ENC_REP_STRING, 0xF2AF, 0, false, false, false, 0}, // Same as REPNE

    // Flag operations
    {"clc", ENC_SINGLE, 0xF8, 0, false, false, false, 0},
    {"stc", ENC_SINGLE, 0xF9, 0, false, false, false, 0},
    {"cmc", ENC_SINGLE, 0xF5, 0, false, false, false, 0},
    {"cld", ENC_SINGLE, 0xFC, 0, false, false, false, 0},
    {"std", ENC_SINGLE, 0xFD, 0, false, false, false, 0},
    {"cli", ENC_SINGLE, 0xFA, 0, false, false, false, 0},
    {"sti", ENC_SINGLE, 0xFB, 0, false, false, false, 0},
    {"lahf", ENC_SINGLE, 0x9F, 0, false, false, false, 0},
    {"sahf", ENC_SINGLE, 0x9E, 0, false, false, false, 0},
    {"pushf", ENC_SINGLE, 0x9C, 0, false, false, false, 0},
    {"popf", ENC_SINGLE, 0x9D, 0, false, false, false, 0},

    // System instructions
    {"int", ENC_INT_IMM, 0xCD, 0, false, false, true, 1},
    {"int3", ENC_SINGLE, 0xCC, 0, false, false, false, 0}, // Breakpoint
    {"into", ENC_SINGLE, 0xCE, 0, false, false, false, 0}, // Interrupt on overflow
    {"iret", ENC_SINGLE, 0xCF, 0, false, false, false, 0}, // Interrupt return
    {"hlt", ENC_SINGLE, 0xF4, 0, false, false, false, 0},
    {"wait", ENC_SINGLE, 0x9B, 0, false, false, false, 0},
    {"lock", ENC_SINGLE, 0xF0, 0, false, false, false, 0},      // Lock prefix
    {"lgdt", ENC_TWO_BYTE_MEM, 0x01, 2, true, false, false, 1}, // Load Global Descriptor Table

    // Processor control
    {"nop", ENC_SINGLE, 0x90, 0, false, false, false, 0},
    // BCD operations
    {"daa", ENC_SINGLE, 0x27, 0, false, false, false, 0},  // Decimal adjust after addition
    {"das", ENC_SINGLE, 0x2F, 0, false, false, false, 0},  // Decimal adjust after subtraction
    {"aaa", ENC_SINGLE, 0x37, 0, false, false, false, 0},  // ASCII adjust after addition
    {"aas", ENC_SINGLE, 0x3F, 0, false, false, false, 0},  // ASCII adjust after subtraction
    {"aam", ENC_SPECIAL, 0xD4, 0, false, false, false, 0}, // ASCII adjust after multiply
    {"aad", ENC_SPECIAL, 0xD5, 0, false, false, false, 0}, // ASCII adjust before division

    // Segment override prefixes (handled specially in parser)
    {"es:", ENC_SINGLE, 0x26, 0, false, false, false, 0},
    {"cs:", ENC_SINGLE, 0x2E, 0, false, false, false, 0},
    {"ss:", ENC_SINGLE, 0x36, 0, false, false, false, 0},
    {"ds:", ENC_SINGLE, 0x3E, 0, false, false, false, 0},

    // I/O operations
    {"in", ENC_SPECIAL, 0xE4, 0, false, false, true, 2},  // IN AL, imm8 or IN AX, imm8
    {"out", ENC_SPECIAL, 0xE6, 0, false, false, true, 2}, // OUT imm8, AL or OUT imm8, AX
                                                          // Convert operations
    {"cbw", ENC_SINGLE, 0x98, 0, false, false, false, 0}, // Convert byte to word
    {"cwd", ENC_SINGLE, 0x99, 0, false, false, false, 0}, // Convert word to doubleword

    // Stack operations - push/pop all registers
    {"pusha", ENC_SINGLE, 0x60, 0, false, false, false, 0}, // Push all general purpose registers
    {"popa", ENC_SINGLE, 0x61, 0, false, false, false, 0},  // Pop all general purpose registers

    // Special x86
    {"sysenter", ENC_SPECIAL, 0x0F34, 0, false, false, false, 0}, // System call entry (x86)
    {"sysexit", ENC_SPECIAL, 0x0F35, 0, false, false, false, 0},  // System call exit (x86)

    // Special x64
    {"syscall", ENC_SPECIAL, 0x0F05, 0, false, false, false, 0}, // System call (x64)
    {"sysret", ENC_SPECIAL, 0x0F07, 0, false, false, false, 0},  // System return (x64)

    // End marker
    {"", ENC_NONE, 0, 0, false, false, false, 0}};

static bool encode_arith_mem_imm(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx);
static bool encode_mov_mem_imm(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx);
static bool encode_two_byte_mem(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx);
static uint8_t register_to_rm(register_t reg, asm_mode_t mode);

// Function to get the opposite condition opcode for conditional jumps
static uint8_t get_opposite_condition_opcode(uint8_t opcode)
{
    switch (opcode)
    {
    case 0x70:
        return 0x71; // JO -> JNO
    case 0x71:
        return 0x70; // JNO -> JO
    case 0x72:
        return 0x73; // JB/JC -> JNB/JNC
    case 0x73:
        return 0x72; // JNB/JNC -> JB/JC
    case 0x74:
        return 0x75; // JE/JZ -> JNE/JNZ
    case 0x75:
        return 0x74; // JNE/JNZ -> JE/JZ
    case 0x76:
        return 0x77; // JBE/JNA -> JA/JNBE
    case 0x77:
        return 0x76; // JA/JNBE -> JBE/JNA
    case 0x78:
        return 0x79; // JS -> JNS
    case 0x79:
        return 0x78; // JNS -> JS
    case 0x7A:
        return 0x7B; // JP/JPE -> JNP/JPO
    case 0x7B:
        return 0x7A; // JNP/JPO -> JP/JPE
    case 0x7C:
        return 0x7D; // JL/JNGE -> JNL/JGE
    case 0x7D:
        return 0x7C; // JNL/JGE -> JL/JNGE
    case 0x7E:
        return 0x7F; // JLE/JNG -> JG/JNLE
    case 0x7F:
        return 0x7E; // JG/JNLE -> JLE/JNG
    default:
        return 0; // Unknown or not a conditional jump
    }
}

// Function to get the near conditional jump opcode (0F 8x) for conditional jumps
static uint8_t get_near_condition_opcode(uint8_t opcode)
{
    switch (opcode)
    {
    case 0x70:
        return 0x80; // JO -> 0F 80
    case 0x71:
        return 0x81; // JNO -> 0F 81
    case 0x72:
        return 0x82; // JB/JC -> 0F 82
    case 0x73:
        return 0x83; // JNB/JNC -> 0F 83
    case 0x74:
        return 0x84; // JE/JZ -> 0F 84
    case 0x75:
        return 0x85; // JNE/JNZ -> 0F 85
    case 0x76:
        return 0x86; // JBE/JNA -> 0F 86
    case 0x77:
        return 0x87; // JA/JNBE -> 0F 87
    case 0x78:
        return 0x88; // JS -> 0F 88
    case 0x79:
        return 0x89; // JNS -> 0F 89
    case 0x7A:
        return 0x8A; // JP/JPE -> 0F 8A
    case 0x7B:
        return 0x8B; // JNP/JPO -> 0F 8B
    case 0x7C:
        return 0x8C; // JL/JNGE -> 0F 8C
    case 0x7D:
        return 0x8D; // JNL/JGE -> 0F 8D
    case 0x7E:
        return 0x8E; // JLE/JNG -> 0F 8E
    case 0x7F:
        return 0x8F; // JG/JNLE -> 0F 8F
    default:
        return 0; // Unknown or not a conditional jump
    }
}

const instruction_def_t *find_instruction(const char *mnemonic)
{
    for (int i = 0; instruction_table[i].encoding != ENC_NONE; i++)
    {
        if (strcasecmp(instruction_table[i].mnemonic, mnemonic) == 0)
        {
            return &instruction_table[i];
        }
    }
    return NULL;
}

bool is_valid_instruction(const char *mnemonic)
{
    return find_instruction(mnemonic) != NULL;
}

uint8_t make_modrm(uint8_t mod, uint8_t reg, uint8_t rm)
{
    return (mod << 6) | (reg << 3) | rm;
}

// Helper function to get r/m field for 16-bit base+index addressing modes
uint8_t get_base_index_rm(register_t base_reg, register_t index_reg)
{
    // 16-bit addressing mode r/m field encoding for base+index combinations
    // Based on Intel x86 16-bit addressing modes:
    // r/m = 0: [BX + SI]
    // r/m = 1: [BX + DI]
    // r/m = 2: [BP + SI]
    // r/m = 3: [BP + DI]

    if (base_reg == REG_BX && index_reg == REG_SI)
    {
        return 0; // [BX + SI]
    }
    else if (base_reg == REG_BX && index_reg == REG_DI)
    {
        return 1; // [BX + DI]
    }
    else if (base_reg == REG_BP && index_reg == REG_SI)
    {
        return 2; // [BP + SI]
    }
    else if (base_reg == REG_BP && index_reg == REG_DI)
    {
        return 3; // [BP + DI]
    }
    else
    {
        // Invalid combination for 16-bit addressing
        // Return default to BP+SI (most commonly used)
        return 2;
    }
}

uint8_t register_to_modrm(register_t reg)
{
    switch (reg)
    {
    case REG_AL:
    case REG_AX:
    case REG_EAX:
    case REG_RAX:
        return 0;
    case REG_CL:
    case REG_CX:
    case REG_ECX:
    case REG_RCX:
        return 1;
    case REG_DL:
    case REG_DX:
    case REG_EDX:
    case REG_RDX:
        return 2;
    case REG_BL:
    case REG_BX:
    case REG_EBX:
    case REG_RBX:
        return 3;
    case REG_AH:
    case REG_SP:
    case REG_ESP:
    case REG_RSP:
    case REG_SPL:
        return 4;
    case REG_CH:
    case REG_BP:
    case REG_EBP:
    case REG_RBP:
    case REG_BPL:
        return 5;
    case REG_DH:
    case REG_SI:
    case REG_ESI:
    case REG_RSI:
    case REG_SIL:
        return 6;
    case REG_BH:
    case REG_DI:
    case REG_EDI:
    case REG_RDI:
    case REG_DIL:
        return 7;
    // R8-R15 registers (need REX.R or REX.B bit set)
    case REG_R8:
    case REG_R8B:
    case REG_R8W:
    case REG_R8D:
        return 0; // R8 = ModR/M 0 + REX.R/B bit
    case REG_R9:
    case REG_R9B:
    case REG_R9W:
    case REG_R9D:
        return 1; // R9 = ModR/M 1 + REX.R/B bit
    case REG_R10:
    case REG_R10B:
    case REG_R10W:
    case REG_R10D:
        return 2; // R10 = ModR/M 2 + REX.R/B bit
    case REG_R11:
    case REG_R11B:
    case REG_R11W:
    case REG_R11D:
        return 3; // R11 = ModR/M 3 + REX.R/B bit
    case REG_R12:
    case REG_R12B:
    case REG_R12W:
    case REG_R12D:
        return 4; // R12 = ModR/M 4 + REX.R/B bit
    case REG_R13:
    case REG_R13B:
    case REG_R13W:
    case REG_R13D:
        return 5; // R13 = ModR/M 5 + REX.R/B bit
    case REG_R14:
    case REG_R14B:
    case REG_R14W:
    case REG_R14D:
        return 6; // R14 = ModR/M 6 + REX.R/B bit
    case REG_R15:
    case REG_R15B:
    case REG_R15W:
    case REG_R15D:
        return 7; // R15 = ModR/M 7 + REX.R/B bit// Segment registers
    case REG_ES:
        return 0;
    case REG_CS:
        return 1;
    case REG_SS:
        return 2;
    case REG_DS:
        return 3;
    case REG_FS:
        return 4;
    case REG_GS:
        return 5;
    // Control registers
    case REG_CR0:
        return 0;
    case REG_CR1:
        return 1;
    case REG_CR2:
        return 2;
    case REG_CR3:
        return 3;
    case REG_CR4:
        return 4;
    case REG_CR5:
        return 5;
    case REG_CR6:
        return 6;
    case REG_CR7:
        return 7;
    default:
        return 0;
    }
}

int get_register_size(register_t reg)
{
    switch (reg)
    {
    case REG_AL:
    case REG_AH:
    case REG_BL:
    case REG_BH:
    case REG_CL:
    case REG_CH:
    case REG_DL:
    case REG_DH:
    case REG_SIL:
    case REG_DIL:
    case REG_BPL:
    case REG_SPL:
    case REG_R8B:
    case REG_R9B:
    case REG_R10B:
    case REG_R11B:
    case REG_R12B:
    case REG_R13B:
    case REG_R14B:
    case REG_R15B:
        return 8;
    case REG_AX:
    case REG_BX:
    case REG_CX:
    case REG_DX:
    case REG_SI:
    case REG_DI:
    case REG_BP:
    case REG_SP:
    case REG_CS:
    case REG_DS:
    case REG_ES:
    case REG_SS:
    case REG_FS:
    case REG_GS:
    case REG_R8W:
    case REG_R9W:
    case REG_R10W:
    case REG_R11W:
    case REG_R12W:
    case REG_R13W:
    case REG_R14W:
    case REG_R15W:
        return 16;
    case REG_EAX:
    case REG_EBX:
    case REG_ECX:
    case REG_EDX:
    case REG_ESI:
    case REG_EDI:
    case REG_EBP:
    case REG_ESP:
    case REG_R8D:
    case REG_R9D:
    case REG_R10D:
    case REG_R11D:
    case REG_R12D:
    case REG_R13D:
    case REG_R14D:
    case REG_R15D:
        return 32;
    case REG_RAX:
    case REG_RBX:
    case REG_RCX:
    case REG_RDX:
    case REG_RSI:
    case REG_RDI:
    case REG_RBP:
    case REG_RSP:
    case REG_R8:
    case REG_R9:
    case REG_R10:
    case REG_R11:
    case REG_R12:
    case REG_R13:
    case REG_R14:
    case REG_R15:
        return 64;
    // Control registers (32-bit)
    case REG_CR0:
    case REG_CR1:
    case REG_CR2:
    case REG_CR3:
    case REG_CR4:
    case REG_CR5:
    case REG_CR6:
    case REG_CR7:
        return 32;
    default:
        return 0;
    }
}

// REX prefix functions
bool is_extended_register(register_t reg)
{
    switch (reg)
    {
    case REG_R8:
    case REG_R9:
    case REG_R10:
    case REG_R11:
    case REG_R12:
    case REG_R13:
    case REG_R14:
    case REG_R15:
    case REG_R8B:
    case REG_R9B:
    case REG_R10B:
    case REG_R11B:
    case REG_R12B:
    case REG_R13B:
    case REG_R14B:
    case REG_R15B:
    case REG_R8W:
    case REG_R9W:
    case REG_R10W:
    case REG_R11W:
    case REG_R12W:
    case REG_R13W:
    case REG_R14W:
    case REG_R15W:
    case REG_R8D:
    case REG_R9D:
    case REG_R10D:
    case REG_R11D:
    case REG_R12D:
    case REG_R13D:
    case REG_R14D:
    case REG_R15D:
        return true;
    default:
        return false;
    }
}

bool is_64bit_register(register_t reg)
{
    switch (reg)
    {
    case REG_RAX:
    case REG_RBX:
    case REG_RCX:
    case REG_RDX:
    case REG_RSI:
    case REG_RDI:
    case REG_RBP:
    case REG_RSP:
    case REG_R8:
    case REG_R9:
    case REG_R10:
    case REG_R11:
    case REG_R12:
    case REG_R13:
    case REG_R14:
    case REG_R15:
        return true;
    default:
        return false;
    }
}

bool needs_rex_prefix(register_t reg1, register_t reg2, register_t reg3, asm_mode_t mode)
{
    if (mode != MODE_64BIT)
        return false;

    return is_64bit_register(reg1) || is_extended_register(reg1) ||
           is_64bit_register(reg2) || is_extended_register(reg2) ||
           is_64bit_register(reg3) || is_extended_register(reg3) ||
           reg1 == REG_SIL || reg1 == REG_DIL || reg1 == REG_BPL || reg1 == REG_SPL ||
           reg2 == REG_SIL || reg2 == REG_DIL || reg2 == REG_BPL || reg2 == REG_SPL ||
           reg3 == REG_SIL || reg3 == REG_DIL || reg3 == REG_BPL || reg3 == REG_SPL;
}

rex_prefix_t calculate_rex_prefix(register_t reg1, register_t reg2, register_t reg3, asm_mode_t mode)
{
    rex_prefix_t rex = {false, false, false, false, false};

    if (mode != MODE_64BIT)
        return rex;

    rex.present = needs_rex_prefix(reg1, reg2, reg3, mode);

    if (!rex.present)
        return rex;

    rex.w = is_64bit_register(reg1) || is_64bit_register(reg2) || is_64bit_register(reg3);
    rex.r = is_extended_register(reg1);
    rex.x = is_extended_register(reg3);
    rex.b = is_extended_register(reg2);

    return rex;
}

uint8_t encode_rex_prefix(const rex_prefix_t *rex)
{
    if (!rex->present)
        return 0;

    uint8_t prefix = REX_PREFIX_BASE;

    if (rex->w)
        prefix |= 0x08;
    if (rex->r)
        prefix |= 0x04;
    if (rex->x)
        prefix |= 0x02;
    if (rex->b)
        prefix |= 0x01;

    return prefix;
}

static bool encode_single_byte(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    const instruction_def_t *def = find_instruction(instr->mnemonic);
    if (!def)
        return false;

    buffer[0] = def->opcode;
    *size = 1;
    return true;
}

static bool encode_push_reg(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 1 || instr->operands[0].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t reg = instr->operands[0].value.reg;
    uint8_t reg_code = register_to_modrm(reg);

    buffer[0] = 0x50 + reg_code; // PUSH reg
    *size = 1;
    return true;
}

static bool encode_push_imm(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 1 || instr->operands[0].type != OPERAND_IMMEDIATE)
    {
        return false;
    }

    int32_t value = instr->operands[0].value.immediate;

    if (value >= -128 && value <= 127)
    {
        // Push byte (sign extended)
        buffer[0] = 0x6A;
        buffer[1] = (uint8_t)value;
        *size = 2;
    }
    else
    { // Push immediate - size depends on mode
        buffer[0] = 0x68;
        if (asm_ctx->mode == MODE_32BIT)
        {
            // 32-bit mode: use 32-bit immediate (5 bytes total)
            buffer[1] = (uint8_t)(value & 0xFF);
            buffer[2] = (uint8_t)((value >> 8) & 0xFF);
            buffer[3] = (uint8_t)((value >> 16) & 0xFF);
            buffer[4] = (uint8_t)((value >> 24) & 0xFF);
            *size = 5;
        }
        else if (asm_ctx->mode == MODE_64BIT)
        {
            // 64-bit mode: also use 32-bit immediate (sign-extended)
            buffer[1] = (uint8_t)(value & 0xFF);
            buffer[2] = (uint8_t)((value >> 8) & 0xFF);
            buffer[3] = (uint8_t)((value >> 16) & 0xFF);
            buffer[4] = (uint8_t)((value >> 24) & 0xFF);
            *size = 5;
        }
        else
        {
            // 16-bit mode: use 16-bit immediate (3 bytes total)
            buffer[1] = (uint8_t)(value & 0xFF);
            buffer[2] = (uint8_t)((value >> 8) & 0xFF);
            *size = 3;
        }
    }
    return true;
}

static bool encode_push_mem(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 1 || instr->operands[0].type != OPERAND_MEMORY)
    {
        return false;
    }

    register_t base_reg = instr->operands[0].value.memory.base;
    register_t index_reg = instr->operands[0].value.memory.index;
    int32_t displacement = instr->operands[0].value.memory.displacement;

    // PUSH r/m16/32 uses opcode 0xFF with ModR/M reg field = 6
    buffer[0] = 0xFF;

    // Check for different memory addressing modes
    if (base_reg == REG_NONE)
    {
        // Direct memory addressing [immediate]: mod=00, r/m=6
        buffer[1] = make_modrm(0, 6, 6);
        buffer[2] = (uint8_t)(displacement & 0xFF);
        buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
        *size = 4;
    }
    else if (index_reg != REG_NONE)
    {
        // Base+index addressing [base+index], [base+index+disp]
        uint8_t rm_code = get_base_index_rm(base_reg, index_reg);

        if (displacement == 0 && base_reg != REG_BP)
        {
            // [base+index] - mod=00
            buffer[1] = make_modrm(0, 6, rm_code);
            *size = 2;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [base+index+disp8] - mod=01
            buffer[1] = make_modrm(1, 6, rm_code);
            buffer[2] = (uint8_t)displacement;
            *size = 3;
        }
        else
        {
            // [base+index+disp16] - mod=10
            buffer[1] = make_modrm(2, 6, rm_code);
            buffer[2] = (uint8_t)(displacement & 0xFF);
            buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
            *size = 4;
        }
    }
    else
    {
        // Single base register addressing [reg], [reg+disp]
        uint8_t base_code = register_to_rm(base_reg, asm_ctx->mode);

        if (displacement == 0 && base_reg != REG_BP)
        {
            // [reg] - mod=00 (except BP which always needs displacement)
            buffer[1] = make_modrm(0, 6, base_code);
            *size = 2;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [reg+disp8] - mod=01
            buffer[1] = make_modrm(1, 6, base_code);
            buffer[2] = (uint8_t)displacement;
            *size = 3;
        }
        else
        {
            // [reg+disp16] - mod=10
            buffer[1] = make_modrm(2, 6, base_code);
            buffer[2] = (uint8_t)(displacement & 0xFF);
            buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
            *size = 4;
        }
    }

    return true;
}

static bool encode_pop_reg(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 1 || instr->operands[0].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t reg = instr->operands[0].value.reg;
    uint8_t reg_code = register_to_modrm(reg);

    buffer[0] = 0x58 + reg_code; // POP reg
    *size = 1;
    return true;
}

static bool encode_xchg_reg_reg(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_REGISTER ||
        instr->operands[1].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t reg1 = instr->operands[0].value.reg;
    register_t reg2 = instr->operands[1].value.reg;

    uint8_t reg1_code = register_to_modrm(reg1);
    uint8_t reg2_code = register_to_modrm(reg2);

    buffer[0] = 0x87; // XCHG r/m16/32, r16/32
    buffer[1] = make_modrm(3, reg1_code, reg2_code); // mod=11 (register), reg=reg1, r/m=reg2
    *size = 2;
    return true;
}

static bool encode_xchg_reg_mem(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_REGISTER ||
        instr->operands[1].type != OPERAND_MEMORY)
    {
        return false;
    }

    register_t reg = instr->operands[0].value.reg;
    uint8_t reg_code = register_to_modrm(reg);

    buffer[0] = 0x87; // XCHG r/m16/32, r16/32
    buffer[1] = make_modrm(0, reg_code, 0); // mod=00 (memory), reg=reg, r/m=0
    *size = 2;
    return true;
}

static bool encode_xchg_mem_reg(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_MEMORY ||
        instr->operands[1].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t reg = instr->operands[1].value.reg;
    uint8_t reg_code = register_to_modrm(reg);

    buffer[0] = 0x87; // XCHG r/m16/32, r16/32
    buffer[1] = make_modrm(0, reg_code, 0); // mod=00 (memory), reg=reg, r/m=0
    *size = 2;
    return true;
}



static bool is_segment_register(register_t reg)
{
    return (reg == REG_ES || reg == REG_CS || reg == REG_SS || reg == REG_DS || reg == REG_FS || reg == REG_GS);
}

static bool is_control_register(register_t reg)
{
    return (reg >= REG_CR0 && reg <= REG_CR7);
}

static bool encode_mov_reg_reg(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_REGISTER ||
        instr->operands[1].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t dst = instr->operands[0].value.reg;
    register_t src = instr->operands[1].value.reg;

    uint8_t dst_code = register_to_modrm(dst);
    uint8_t src_code = register_to_modrm(src);

    // Handle segment register moves
    if (is_segment_register(dst) && !is_segment_register(src))
    {
        // MOV Sreg, r/m16 (move to segment register)
        buffer[0] = 0x8E;
        buffer[1] = make_modrm(3, dst_code, src_code);
        *size = 2;
        return true;
    }
    else if (!is_segment_register(dst) && is_segment_register(src))
    {
        // MOV r/m16, Sreg (move from segment register)
        buffer[0] = 0x8C;
        buffer[1] = make_modrm(3, src_code, dst_code);
        *size = 2;
        return true;
    }
    // Handle control register moves
    else if (is_control_register(dst) && !is_control_register(src) && !is_segment_register(src))
    {
        // MOV CRn, r32 (move to control register) - requires 0x0F 0x22 prefix
        buffer[0] = 0x0F;
        buffer[1] = 0x22;
        buffer[2] = make_modrm(3, dst_code, src_code);
        *size = 3;
        return true;
    }
    else if (!is_control_register(dst) && !is_segment_register(dst) && is_control_register(src))
    {
        // MOV r32, CRn (move from control register) - requires 0x0F 0x20 prefix
        buffer[0] = 0x0F;
        buffer[1] = 0x20;
        buffer[2] = make_modrm(3, src_code, dst_code);
        *size = 3;
        return true;
    }

    // Check if 8-bit or 16-bit operation
    int dst_size = get_register_size(dst);
    int src_size = get_register_size(src);

    if (dst_size != src_size)
    {
        return false; // Size mismatch
    }

    if (dst_size == 8)
    {
        buffer[0] = 0x88; // MOV r/m8, r8
    }
    else if (dst_size == 64)
    {
        buffer[0] = 0x89; // MOV r/m64, r64 (REX.W will be added by caller)
    }
    else
    {
        buffer[0] = 0x89; // MOV r/m16, r16 or MOV r/m32, r32
    }

    buffer[1] = make_modrm(3, src_code, dst_code); // mod=11 (register), reg=src, r/m=dst
    *size = 2;
    return true;
}

static bool encode_mov_reg_imm(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_REGISTER ||
        instr->operands[1].type != OPERAND_IMMEDIATE)
    {
        return false;
    }

    register_t reg = instr->operands[0].value.reg;
    int64_t value = instr->operands[1].value.immediate;
    uint8_t reg_code = register_to_modrm(reg);

    int reg_size = get_register_size(reg);

    if (reg_size == 8)
    {
        buffer[0] = 0xB0 + reg_code; // MOV r8, imm8
        buffer[1] = (uint8_t)value;
        *size = 2;
    }
    else if (reg_size == 32)
    {
        // Only add 0x66 prefix if we're in 16-bit mode and generating 32-bit instructions
        if (asm_ctx->mode == MODE_16BIT)
        {
            buffer[0] = 0x66;            // Operand size prefix for 32-bit operand in 16-bit mode
            buffer[1] = 0xB8 + reg_code; // MOV r32, imm32
            buffer[2] = (uint8_t)(value & 0xFF);
            buffer[3] = (uint8_t)((value >> 8) & 0xFF);
            buffer[4] = (uint8_t)((value >> 16) & 0xFF);
            buffer[5] = (uint8_t)((value >> 24) & 0xFF);
            *size = 6;
        }
        else
        {
            // In 32-bit mode, no prefix needed for 32-bit operations
            buffer[0] = 0xB8 + reg_code; // MOV r32, imm32
            buffer[1] = (uint8_t)(value & 0xFF);
            buffer[2] = (uint8_t)((value >> 8) & 0xFF);
            buffer[3] = (uint8_t)((value >> 16) & 0xFF);
            buffer[4] = (uint8_t)((value >> 24) & 0xFF);
            *size = 5;
        }
    }
    else if (reg_size == 64)
    {
        // 64-bit register - use REX.W prefix + MOV r64, imm64
        // Note: REX prefix is handled by the calling function
        buffer[0] = 0xB8 + reg_code; // MOV r64, imm64
        buffer[1] = (uint8_t)(value & 0xFF);
        buffer[2] = (uint8_t)((value >> 8) & 0xFF);
        buffer[3] = (uint8_t)((value >> 16) & 0xFF);
        buffer[4] = (uint8_t)((value >> 24) & 0xFF);
        buffer[5] = (uint8_t)((value >> 32) & 0xFF);
        buffer[6] = (uint8_t)((value >> 40) & 0xFF);
        buffer[7] = (uint8_t)((value >> 48) & 0xFF);
        buffer[8] = (uint8_t)((value >> 56) & 0xFF);
        *size = 9;
    }
    else
    {
        buffer[0] = 0xB8 + reg_code; // MOV r16, imm16
        buffer[1] = (uint8_t)(value & 0xFF);
        buffer[2] = (uint8_t)((value >> 8) & 0xFF);
        *size = 3;
    }
    return true;
}

static bool encode_reg_reg_generic(const instruction_t *instr, uint8_t *buffer, size_t *size, const instruction_def_t *def, assembler_t *asm_ctx)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_REGISTER ||
        instr->operands[1].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t dst = instr->operands[0].value.reg;
    register_t src = instr->operands[1].value.reg;

    uint8_t dst_code = register_to_modrm(dst);
    uint8_t src_code = register_to_modrm(src);

    // Check if 8-bit or 16-bit operation
    int dst_size = get_register_size(dst);
    int src_size = get_register_size(src);

    if (dst_size != src_size)
    {
        return false; // Size mismatch
    }
    if (dst_size == 8)
    {
        buffer[0] = def->opcode - 1; // 8-bit version is typically opcode - 1
    }
    else if (dst_size == 32)
    {
        // Only add 0x66 prefix if we're in 16-bit mode
        if (asm_ctx->mode == MODE_16BIT)
        {
            buffer[0] = 0x66;        // 32-bit operand prefix for 16-bit mode
            buffer[1] = def->opcode; // 32-bit version
            buffer[2] = make_modrm(3, src_code, dst_code);
            *size = 3;
        }
        else
        {
            // In 32-bit mode, no prefix needed for 32-bit operations
            buffer[0] = def->opcode; // 32-bit version
            buffer[1] = make_modrm(3, src_code, dst_code);
            *size = 2;
        }
        return true;
    }
    else
    {
        buffer[0] = def->opcode; // 16-bit version
    }

    buffer[1] = make_modrm(3, src_code, dst_code); // mod=11 (register), reg=src, r/m=dst
    *size = 2;
    return true;
}

uint8_t register_to_rm16(register_t reg)
{
    // 16-bit memory addressing mode r/m field encoding
    switch (reg)
    {
    case REG_BX:
        return 7; // [bx]
    case REG_BP:
        return 6; // [bp+disp] (note: [bp] alone is actually [bp+0])
    case REG_SI:
        return 4; // [si]
    case REG_DI:
        return 5; // [di]
    // Note: 16-bit addressing has limited base register options
    default:
        return 6; // Default to BP addressing
    }
}

uint8_t register_to_rm32(register_t reg)
{
    // 32-bit memory addressing mode r/m field encoding
    switch (reg)
    {
    case REG_EAX:
        return 0; // [eax]
    case REG_ECX:
        return 1; // [ecx]
    case REG_EDX:
        return 2; // [edx]
    case REG_EBX:
        return 3; // [ebx]
    case REG_ESP:
        return 4; // [esp] - requires SIB byte
    case REG_EBP:
        return 5; // [ebp+disp] (note: [ebp] alone is actually [ebp+0])
    case REG_ESI:
        return 6; // [esi]
    case REG_EDI:
        return 7; // [edi]
    default:
        return 5; // Default to EBP addressing
    }
}

uint8_t register_to_rm(register_t reg, asm_mode_t mode)
{
    if (mode == MODE_32BIT)
    {
        return register_to_rm32(reg);
    }
    else
    {
        return register_to_rm16(reg);
    }
}

static bool encode_arith_mem_reg(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_MEMORY ||
        instr->operands[1].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t base_reg = instr->operands[0].value.memory.base;
    register_t index_reg = instr->operands[0].value.memory.index;
    int32_t displacement = instr->operands[0].value.memory.displacement;
    register_t src_reg = instr->operands[1].value.reg;

    uint8_t src_code = register_to_modrm(src_reg);

    // Check if 8-bit, 16-bit, or 32-bit operation
    int src_size = get_register_size(src_reg);

    // Determine the opcode based on operation and size
    uint8_t opcode;
    if (strcasecmp(instr->mnemonic, "add") == 0)
    {
        opcode = (src_size == 8) ? 0x00 : 0x01; // ADD r/m8,r8 or ADD r/m16/32,r16/32
    }
    else if (strcasecmp(instr->mnemonic, "sub") == 0)
    {
        opcode = (src_size == 8) ? 0x28 : 0x29; // SUB r/m8,r8 or SUB r/m16/32,r16/32
    }
    else if (strcasecmp(instr->mnemonic, "and") == 0)
    {
        opcode = (src_size == 8) ? 0x20 : 0x21; // AND r/m8,r8 or AND r/m16/32,r16/32
    }
    else if (strcasecmp(instr->mnemonic, "or") == 0)
    {
        opcode = (src_size == 8) ? 0x08 : 0x09; // OR r/m8,r8 or OR r/m16/32,r16/32
    }
    else if (strcasecmp(instr->mnemonic, "xor") == 0)
    {
        opcode = (src_size == 8) ? 0x30 : 0x31; // XOR r/m8,r8 or XOR r/m16/32,r16/32
    }
    else if (strcasecmp(instr->mnemonic, "cmp") == 0)
    {
        opcode = (src_size == 8) ? 0x38 : 0x39; // CMP r/m8,r8 or CMP r/m16/32,r16/32
    }
    else if (strcasecmp(instr->mnemonic, "adc") == 0)
    {
        opcode = (src_size == 8) ? 0x10 : 0x11; // ADC r/m8,r8 or ADC r/m16/32,r16/32
    }
    else if (strcasecmp(instr->mnemonic, "sbb") == 0)
    {
        opcode = (src_size == 8) ? 0x18 : 0x19; // SBB r/m8,r8 or SBB r/m16/32,r16/32
    }
    else if (strcasecmp(instr->mnemonic, "test") == 0)
    {
        opcode = (src_size == 8) ? 0x84 : 0x85; // TEST r/m8,r8 or TEST r/m16/32,r16/32
    }
    else
    {
        return false; // Unsupported arithmetic instruction
    }
    size_t opcode_offset = 0;

    // Add operand size prefix for 32-bit operations only in 16-bit mode
    if (src_size == 32 && asm_ctx->mode == MODE_16BIT)
    {
        buffer[0] = 0x66; // Operand size prefix
        opcode_offset = 1;
    }

    buffer[opcode_offset] = opcode;

    // Check for different memory addressing modes
    if (base_reg == REG_NONE)
    {
        // Direct memory addressing: mod=00, r/m=6
        buffer[opcode_offset + 1] = make_modrm(0, src_code, 6);
        buffer[opcode_offset + 2] = (uint8_t)(displacement & 0xFF);
        buffer[opcode_offset + 3] = (uint8_t)((displacement >> 8) & 0xFF);
        *size = opcode_offset + 4;
        return true;
    }

    // Handle base+index addressing
    if (index_reg != REG_NONE)
    {
        // Base+index addressing using the helper function
        uint8_t rm_code = get_base_index_rm(base_reg, index_reg);

        // Determine addressing mode based on displacement
        if (displacement == 0 && base_reg != REG_BP)
        {
            // [base+index] - mod=00 (except BP which always needs displacement)
            buffer[opcode_offset + 1] = make_modrm(0, src_code, rm_code);
            *size = opcode_offset + 2;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [base+index+disp8] - mod=01
            buffer[opcode_offset + 1] = make_modrm(1, src_code, rm_code);
            buffer[opcode_offset + 2] = (uint8_t)displacement;
            *size = opcode_offset + 3;
        }
        else
        {
            // [base+index+disp16] - mod=10
            buffer[opcode_offset + 1] = make_modrm(2, src_code, rm_code);
            buffer[opcode_offset + 2] = (uint8_t)(displacement & 0xFF);
            buffer[opcode_offset + 3] = (uint8_t)((displacement >> 8) & 0xFF);
            *size = opcode_offset + 4;
        }
        return true;
    }

    // Single base register addressing
    uint8_t base_code = register_to_rm(base_reg, asm_ctx->mode); // Use mode-appropriate addressing

    // Determine addressing mode based on displacement
    if (displacement == 0 && base_reg != REG_BP)
    {
        // [reg] - mod=00 (except BP which always needs displacement)
        buffer[opcode_offset + 1] = make_modrm(0, src_code, base_code);
        *size = opcode_offset + 2;
    }
    else if (displacement >= -128 && displacement <= 127)
    {
        // [reg+disp8] - mod=01
        buffer[opcode_offset + 1] = make_modrm(1, src_code, base_code);
        buffer[opcode_offset + 2] = (uint8_t)displacement;
        *size = opcode_offset + 3;
    }
    else
    {
        // [reg+disp16] - mod=10
        buffer[opcode_offset + 1] = make_modrm(2, src_code, base_code);
        buffer[opcode_offset + 2] = (uint8_t)(displacement & 0xFF);
        buffer[opcode_offset + 3] = (uint8_t)((displacement >> 8) & 0xFF);
        *size = opcode_offset + 4;
    }

    return true;
}

static bool encode_mov_reg_mem(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_REGISTER ||
        instr->operands[1].type != OPERAND_MEMORY)
    {
        return false;
    }

    register_t dst_reg = instr->operands[0].value.reg;
    register_t base_reg = instr->operands[1].value.memory.base;
    register_t index_reg = instr->operands[1].value.memory.index;
    int32_t displacement = instr->operands[1].value.memory.displacement;

    uint8_t dst_code = register_to_modrm(dst_reg);

    // Check if 8-bit or 16-bit operation
    int dst_size = get_register_size(dst_reg);

    if (dst_size == 8)
    {
        buffer[0] = 0x8A; // MOV r8, r/m8
    }
    else
    {
        buffer[0] = 0x8B; // MOV r16, r/m16
    }

    // Check for direct memory addressing (immediate memory operand like [0x7C00])
    if (base_reg == REG_NONE)
    {
        // Direct memory addressing: mod=00, r/m=6
        buffer[1] = make_modrm(0, dst_code, 6);
        buffer[2] = (uint8_t)(displacement & 0xFF);
        buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
        *size = 4;
        return true;
    }

    // Handle base+index addressing
    if (index_reg != REG_NONE)
    {
        // Base+index addressing using the helper function
        uint8_t rm_code = get_base_index_rm(base_reg, index_reg);

        // Determine addressing mode based on displacement
        if (displacement == 0 && base_reg != REG_BP)
        {
            // [base+index] - mod=00 (except BP which always needs displacement)
            buffer[1] = make_modrm(0, dst_code, rm_code);
            *size = 2;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [base+index+disp8] - mod=01
            buffer[1] = make_modrm(1, dst_code, rm_code);
            buffer[2] = (uint8_t)displacement;
            *size = 3;
        }
        else
        {
            // [base+index+disp16] - mod=10
            buffer[1] = make_modrm(2, dst_code, rm_code);
            buffer[2] = (uint8_t)(displacement & 0xFF);
            buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
            *size = 4;
        }
        return true;
    }

    // Single base register addressing
    uint8_t base_code = register_to_rm(base_reg, asm_ctx->mode); // Use mode-appropriate addressing

    // Determine addressing mode based on displacement
    if (displacement == 0 && base_reg != REG_BP)
    {
        // [reg] - mod=00 (except BP which always needs displacement)
        buffer[1] = make_modrm(0, dst_code, base_code);
        *size = 2;
    }
    else if (displacement >= -128 && displacement <= 127)
    {
        // [reg+disp8] - mod=01
        buffer[1] = make_modrm(1, dst_code, base_code);
        buffer[2] = (uint8_t)displacement;
        *size = 3;
    }
    else
    {
        // [reg+disp16] - mod=10
        buffer[1] = make_modrm(2, dst_code, base_code);
        buffer[2] = (uint8_t)(displacement & 0xFF);
        buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
        *size = 4;
    }

    return true;
}

static bool encode_mov_mem_reg(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_MEMORY ||
        instr->operands[1].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t base_reg = instr->operands[0].value.memory.base;
    register_t index_reg = instr->operands[0].value.memory.index;
    int32_t displacement = instr->operands[0].value.memory.displacement;
    register_t src_reg = instr->operands[1].value.reg;

    uint8_t src_code = register_to_modrm(src_reg);

    // Check if 8-bit or 16-bit operation
    int src_size = get_register_size(src_reg);

    if (src_size == 8)
    {
        buffer[0] = 0x88; // MOV r/m8, r8
    }
    else
    {
        buffer[0] = 0x89; // MOV r/m16, r16
    }

    // Check for direct memory addressing (immediate memory operand like [0x7C00])
    if (base_reg == REG_NONE)
    {
        // Direct memory addressing: mod=00, r/m=6
        buffer[1] = make_modrm(0, src_code, 6);
        buffer[2] = (uint8_t)(displacement & 0xFF);
        buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
        *size = 4;
        return true;
    }

    // Handle base+index addressing
    if (index_reg != REG_NONE)
    {
        // Base+index addressing using the helper function
        uint8_t rm_code = get_base_index_rm(base_reg, index_reg);

        // Determine addressing mode based on displacement
        if (displacement == 0 && base_reg != REG_BP)
        {
            // [base+index] - mod=00 (except BP which always needs displacement)
            buffer[1] = make_modrm(0, src_code, rm_code);
            *size = 2;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [base+index+disp8] - mod=01
            buffer[1] = make_modrm(1, src_code, rm_code);
            buffer[2] = (uint8_t)displacement;
            *size = 3;
        }
        else
        {
            // [base+index+disp16] - mod=10
            buffer[1] = make_modrm(2, src_code, rm_code);
            buffer[2] = (uint8_t)(displacement & 0xFF);
            buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
            *size = 4;
        }
        return true;
    }

    // Single base register addressing
    uint8_t base_code = register_to_rm(base_reg, asm_ctx->mode); // Use mode-appropriate addressing

    // Determine addressing mode based on displacement
    if (displacement == 0 && base_reg != REG_BP)
    {
        // [reg] - mod=00 (except BP which always needs displacement)
        buffer[1] = make_modrm(0, src_code, base_code);
        *size = 2;
    }
    else if (displacement >= -128 && displacement <= 127)
    {
        // [reg+disp8] - mod=01
        buffer[1] = make_modrm(1, src_code, base_code);
        buffer[2] = (uint8_t)displacement;
        *size = 3;
    }
    else
    {
        // [reg+disp16] - mod=10
        buffer[1] = make_modrm(2, src_code, base_code);
        buffer[2] = (uint8_t)(displacement & 0xFF);
        buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
        *size = 4;
    }

    return true;
}

static bool encode_int_imm(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 1 || instr->operands[0].type != OPERAND_IMMEDIATE)
    {
        return false;
    }

    int32_t value = instr->operands[0].value.immediate;

    buffer[0] = 0xCD; // INT imm8
    buffer[1] = (uint8_t)value;
    *size = 2;
    return true;
}

static bool encode_arith_reg_imm(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_REGISTER ||
        instr->operands[1].type != OPERAND_IMMEDIATE)
    {
        return false;
    }

    register_t reg = instr->operands[0].value.reg;
    int64_t value = instr->operands[1].value.immediate;
    uint8_t reg_code = register_to_modrm(reg);
    int reg_size = get_register_size(reg);

    // Determine the ModR/M reg field based on instruction
    uint8_t modrm_reg;
    if (strcasecmp(instr->mnemonic, "add") == 0)
    {
        modrm_reg = 0; // ADD
    }
    else if (strcasecmp(instr->mnemonic, "or") == 0)
    {
        modrm_reg = 1; // OR
    }
    else if (strcasecmp(instr->mnemonic, "adc") == 0)
    {
        modrm_reg = 2; // ADC
    }
    else if (strcasecmp(instr->mnemonic, "sbb") == 0)
    {
        modrm_reg = 3; // SBB
    }
    else if (strcasecmp(instr->mnemonic, "and") == 0)
    {
        modrm_reg = 4; // AND
    }
    else if (strcasecmp(instr->mnemonic, "sub") == 0)
    {
        modrm_reg = 5; // SUB
    }
    else if (strcasecmp(instr->mnemonic, "xor") == 0)
    {
        modrm_reg = 6; // XOR
    }
    else if (strcasecmp(instr->mnemonic, "cmp") == 0)
    {
        modrm_reg = 7; // CMP
    }
    else
    {
        return false; // Unsupported arithmetic instruction
    }

    // Handle 64-bit operands (REX.W will be added by caller)
    if (reg_size == 64)
    {
        // Check if we can use 8-bit immediate (sign-extended)
        if (value >= -128 && value <= 127)
        {
            // Use 8-bit immediate (sign-extended) - opcode 0x83
            buffer[0] = 0x83;
            buffer[1] = make_modrm(3, modrm_reg, reg_code);
            buffer[2] = (uint8_t)value;
            *size = 3;
        }
        else if (value >= -2147483648LL && value <= 2147483647LL)
        {
            // 64-bit register with 32-bit immediate (sign-extended) - opcode 0x81
            buffer[0] = 0x81;
            buffer[1] = make_modrm(3, modrm_reg, reg_code);
            buffer[2] = (uint8_t)(value & 0xFF);
            buffer[3] = (uint8_t)((value >> 8) & 0xFF);
            buffer[4] = (uint8_t)((value >> 16) & 0xFF);
            buffer[5] = (uint8_t)((value >> 24) & 0xFF);
            *size = 6;
        }
        else
        {
            // Cannot fit in 32-bit immediate - this is an error for arithmetic instructions
            return false;
        }
    }
    // Handle 32-bit operands
    else if (reg_size == 32)
    {
        // Check if we can use 8-bit immediate (sign-extended)
        if (value >= -128 && value <= 127)
        {
            // Use 8-bit immediate (sign-extended) - opcode 0x83 with prefix only in 16-bit mode
            if (asm_ctx->mode == MODE_16BIT)
            {
                buffer[0] = 0x66; // Operand size prefix for 32-bit operand in 16-bit mode
                buffer[1] = 0x83;
                buffer[2] = make_modrm(3, modrm_reg, reg_code);
                buffer[3] = (uint8_t)value;
                *size = 4;
            }
            else
            {
                // In 32-bit mode, no prefix needed for 32-bit operations
                buffer[0] = 0x83;
                buffer[1] = make_modrm(3, modrm_reg, reg_code);
                buffer[2] = (uint8_t)value;
                *size = 3;
            }
        }
        else
        {
            // 32-bit register with 32-bit immediate - opcode 0x81 with prefix only in 16-bit mode
            if (asm_ctx->mode == MODE_16BIT)
            {
                buffer[0] = 0x66; // Operand size prefix for 32-bit operand in 16-bit mode
                buffer[1] = 0x81;
                buffer[2] = make_modrm(3, modrm_reg, reg_code);
                buffer[3] = (uint8_t)(value & 0xFF);
                buffer[4] = (uint8_t)((value >> 8) & 0xFF);
                buffer[5] = (uint8_t)((value >> 16) & 0xFF);
                buffer[6] = (uint8_t)((value >> 24) & 0xFF);
                *size = 7;
            }
            else
            {
                // In 32-bit mode, no prefix needed for 32-bit operations
                buffer[0] = 0x81;
                buffer[1] = make_modrm(3, modrm_reg, reg_code);
                buffer[2] = (uint8_t)(value & 0xFF);
                buffer[3] = (uint8_t)((value >> 8) & 0xFF);
                buffer[4] = (uint8_t)((value >> 16) & 0xFF);
                buffer[5] = (uint8_t)((value >> 24) & 0xFF);
                *size = 6;
            }
        }
    }
    // Check if we can use 8-bit immediate (sign-extended) for 16-bit
    else if (value >= -128 && value <= 127 && reg_size == 16)
    {
        // Use 8-bit immediate (sign-extended) - opcode 0x83
        buffer[0] = 0x83;
        buffer[1] = make_modrm(3, modrm_reg, reg_code); // mod=11 (register)
        buffer[2] = (uint8_t)value;
        *size = 3;
    }
    else if (reg_size == 8)
    {
        // 8-bit register with 8-bit immediate - opcode 0x80
        buffer[0] = 0x80;
        buffer[1] = make_modrm(3, modrm_reg, reg_code);
        buffer[2] = (uint8_t)value;
        *size = 3;
    }
    else
    {
        // 16-bit register with 16-bit immediate - opcode 0x81
        buffer[0] = 0x81;
        buffer[1] = make_modrm(3, modrm_reg, reg_code);
        buffer[2] = (uint8_t)(value & 0xFF);
        buffer[3] = (uint8_t)((value >> 8) & 0xFF);
        *size = 4;
    }

    return true;
}

static bool encode_jmp_rel(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    const instruction_def_t *def = find_instruction(instr->mnemonic);
    if (!def)
        return false;

    // Debug: Show operand details
    if (asm_ctx->verbose && strcasecmp(instr->mnemonic, "call") == 0)
    {
        printf("DEBUG: Pass %d - encode_jmp_rel for call: operand_count=%d, operand[0].type=%d (OPERAND_LABEL=%d)\n",
               asm_ctx->pass, instr->operand_count,
               instr->operand_count > 0 ? instr->operands[0].type : -1, OPERAND_LABEL);
    }
    // Check if this is a call/jmp to a label or immediate (defined symbol converted to immediate)
    if (instr->operand_count == 1)
    {
        uint32_t target_addr = 0;
        bool target_available = false;

        if (instr->operands[0].type == OPERAND_LABEL)
        {
            // Debug output
            if (asm_ctx->verbose)
            {
                printf("DEBUG: Pass %d - Looking up symbol '%s' for %s instruction\n",
                       asm_ctx->pass, instr->operands[0].value.label, instr->mnemonic);
            }

            // Look up the symbol
            symbol_t *symbol = symbol_lookup(asm_ctx, instr->operands[0].value.label);
            if (symbol && symbol->defined)
            {
                if (asm_ctx->verbose)
                {
                    printf("DEBUG: Found symbol '%s' at address 0x%04X\n",
                           symbol->name, symbol->address);
                }
                target_addr = symbol->address;
                target_available = true;
            }
            else
            {
                // Symbol not found or not defined - check if it's external
                if (asm_ctx->verbose)
                {
                    if (symbol)
                    {
                        printf("DEBUG: Symbol '%s' found but not defined (address=0x%04X, defined=%s, external=%s)\n",
                               symbol->name, symbol->address, symbol->defined ? "true" : "false",
                               symbol->external ? "true" : "false");
                    }
                    else
                    {
                        printf("DEBUG: Symbol '%s' not found in symbol table\n",
                               instr->operands[0].value.label);
                    }
                }
                // If this is an external symbol, we need to generate a relocation entry
                if (symbol && symbol->external && asm_ctx->pass == 2)
                {
                    // Generate relocation entry for external symbol
                    uint32_t current_addr = codegen_get_current_address(asm_ctx);
                    section_t *current_section = section_get_current(asm_ctx);
                    section_type_t section_type = current_section ? current_section->type : SECTION_TEXT;
                    uint32_t offset_in_section = current_addr - (current_section ? current_section->address : 0);

                    // Determine relocation type based on instruction and mode
                    int relocation_type;
                    if (asm_ctx->mode == MODE_64BIT)
                    {
                        // For 64-bit mode, use PLT32 for call instructions to external symbols
                        if (strcasecmp(instr->mnemonic, "call") == 0)
                        {
                            relocation_type = R_X86_64_PLT32; // Use PLT for external function calls
                        }
                        else
                        {
                            relocation_type = R_X86_64_PC32; // PC-relative for jumps
                        }
                    }
                    else
                    {
                        relocation_type = R_386_PC32; // PC-relative for x86
                    }

                    if (asm_ctx->verbose)
                    {
                        const char *reloc_type_str = "unknown";
                        if (asm_ctx->mode == MODE_64BIT)
                        {
                            reloc_type_str = (relocation_type == R_X86_64_PLT32) ? "R_X86_64_PLT32" : "R_X86_64_PC32";
                        }
                        else
                        {
                            reloc_type_str = "R_386_PC32";
                        }
                        printf("DEBUG: Adding relocation for external symbol '%s' at offset 0x%X in section %d, type %s\n",
                               symbol->name, offset_in_section + 1, section_type, reloc_type_str);
                    }

                    // Add relocation entry pointing to the displacement field (after opcode)
                    int64_t addend = (relocation_type == R_X86_64_PLT32) ? -4 : 0;
                    relocation_add(asm_ctx, offset_in_section + 1, symbol->name, relocation_type, section_type, addend);

                    // For external symbols, emit zero displacement (addend is in relocation record)
                    target_addr = current_addr + ((asm_ctx->mode == MODE_32BIT || asm_ctx->mode == MODE_64BIT) ? 5 : 3);
                    target_available = true;
                }
            }
        }
        else if (instr->operands[0].type == OPERAND_IMMEDIATE)
        {
            // This is a defined symbol that was converted to immediate - treat as absolute address
            if (asm_ctx->verbose)
            {
                printf("DEBUG: Pass %d - Using immediate value 0x%04X as target address for %s instruction\n",
                       asm_ctx->pass, (uint32_t)instr->operands[0].value.immediate, instr->mnemonic);
            }
            target_addr = (uint32_t)instr->operands[0].value.immediate;
            target_available = true; // fuck
        }

        if (target_available)
        {
            // Calculate relative displacement
            uint32_t current_addr = codegen_get_current_address(asm_ctx);
            if (def->opcode == 0xE8)
            { // CALL rel - size depends on mode
                uint32_t instruction_size;
                if (asm_ctx->mode == MODE_32BIT || asm_ctx->mode == MODE_64BIT)
                {
                    instruction_size = 5; // 32-bit and 64-bit modes: opcode + 32-bit displacement
                }
                else
                {
                    instruction_size = 3; // 16-bit mode: opcode + 16-bit displacement
                }

                int32_t displacement = (int32_t)(target_addr - current_addr - instruction_size); // Handle the case where target equals current address (call to itself)
                if (target_addr == current_addr)
                {
                    displacement = -(int32_t)instruction_size; // Call back to start of current instruction
                }

                if (asm_ctx->verbose)
                {
                    printf("DEBUG: CALL displacement calculation: target=0x%04X, current=0x%04X, size=%d, displacement=%d\n",
                           target_addr, current_addr, instruction_size, displacement);
                }

                buffer[0] = def->opcode;
                if (asm_ctx->mode == MODE_32BIT || asm_ctx->mode == MODE_64BIT)
                {
                    // 32-bit and 64-bit modes: emit 32-bit displacement (5 bytes total)
                    buffer[1] = (uint8_t)(displacement & 0xFF);
                    buffer[2] = (uint8_t)((displacement >> 8) & 0xFF);
                    buffer[3] = (uint8_t)((displacement >> 16) & 0xFF);
                    buffer[4] = (uint8_t)((displacement >> 24) & 0xFF);
                    *size = 5;
                }
                else
                {
                    // 16-bit mode: emit 16-bit displacement (3 bytes total)
                    buffer[1] = (uint8_t)(displacement & 0xFF);
                    buffer[2] = (uint8_t)((displacement >> 8) & 0xFF);
                    *size = 3;
                }
            }
            else
            { // Jump/conditional jump - determine optimal size first
                // Pre-calculate with both short and long jump sizes to determine optimal
                uint32_t short_size = 2;
                uint32_t long_size = (strcasecmp(instr->mnemonic, "jmp") == 0) ? 3 : 4;

                int32_t short_displacement = (int32_t)(target_addr - current_addr - short_size);
                bool needs_long_jump = (short_displacement < -128 || short_displacement > 127);

                uint32_t optimal_size = needs_long_jump ? long_size : short_size;
                int32_t displacement = (int32_t)(target_addr - current_addr - optimal_size); // Handle the case where target equals current address (jump to itself)
                if (target_addr == current_addr)
                {
                    displacement = -(int32_t)optimal_size; // Jump back to start of current instruction
                }

                if (asm_ctx->verbose)
                {
                    printf("DEBUG: JMP displacement calculation: target=0x%04X, current=0x%04X, optimal_size=%d, displacement=%d\n",
                           target_addr, current_addr, optimal_size, displacement);
                }

                if (needs_long_jump)
                {
                    // Only signal size change in pass 2+ if we were previously using short jump
                    // (in pass 1, we always assume short jumps for initial estimates)
                    if (asm_ctx->pass >= 2 && asm_ctx->pass == 2)
                    {
                        asm_ctx->sizes_changed = true;
                        if (asm_ctx->verbose)
                        {
                            printf("DEBUG: Instruction size change detected - short jump converted to long jump\n");
                        }
                    }

                    // Use long jump
                    if (strcasecmp(instr->mnemonic, "jmp") == 0)
                    {                     // For unconditional jumps, use near jump (0xE9) with 16-bit displacement
                        buffer[0] = 0xE9; // Near JMP opcode                        // Calculate displacement for near jump (3 bytes total)
                        uint32_t near_instruction_size = 3;
                        int32_t near_displacement = (int32_t)(target_addr - current_addr - near_instruction_size);

                        // Handle the case where target equals current address (jump to itself)
                        if (target_addr == current_addr)
                        {
                            near_displacement = -(int32_t)near_instruction_size; // Jump back to start of current instruction
                        }
                        buffer[1] = (uint8_t)(near_displacement & 0xFF);
                        buffer[2] = (uint8_t)((near_displacement >> 8) & 0xFF);
                        *size = 3;

                        if (asm_ctx->verbose)
                        {
                            printf("DEBUG: Long unconditional jump converted to near jump (size=3, displacement=%d)\n", near_displacement);
                        }
                    }
                    else
                    {
                        // For conditional jumps, use near conditional jump (0F 8x opcodes)
                        uint8_t near_opcode = get_near_condition_opcode(def->opcode);
                        if (near_opcode == 0)
                        {
                            if (asm_ctx->verbose)
                            {
                                printf("ERROR: Cannot find near condition for opcode 0x%02X\n", def->opcode);
                            }
                            return false;
                        } // Use 0F 8x near conditional jump (4 bytes total)
                        buffer[0] = 0x0F;        // Two-byte opcode prefix
                        buffer[1] = near_opcode; // Near conditional jump opcode                        // Calculate displacement for near conditional jump (4 bytes total)
                        uint32_t near_instruction_size = 4;
                        int32_t near_displacement = (int32_t)(target_addr - current_addr - near_instruction_size);

                        // Handle the case where target equals current address (jump to itself)
                        if (target_addr == current_addr)
                        {
                            near_displacement = -(int32_t)near_instruction_size; // Jump back to start of current instruction
                        }
                        buffer[2] = (uint8_t)(near_displacement & 0xFF);
                        buffer[3] = (uint8_t)((near_displacement >> 8) & 0xFF);
                        *size = 4;

                        if (asm_ctx->verbose)
                        {
                            printf("DEBUG: Long conditional jump converted to near conditional jump (0F %02X, size=4, displacement=%d)\n", near_opcode, near_displacement);
                        }
                    }
                }
                else
                {
                    buffer[0] = def->opcode;
                    buffer[1] = (uint8_t)displacement;
                    *size = 2;
                }
            }
            return true;
        }
        else
        { // Target not available - need to estimate instruction size conservatively
            // Use consistent size estimates across all passes to avoid cascading changes
            if (def->opcode == 0xE8)
            {
                // CALL instruction - size depends on mode
                buffer[0] = def->opcode;
                if (asm_ctx->mode == MODE_32BIT || asm_ctx->mode == MODE_64BIT)
                {
                    // 32-bit and 64-bit modes: emit 32-bit displacement placeholder (5 bytes total)
                    buffer[1] = 0x00; // Placeholder displacement byte 1
                    buffer[2] = 0x00; // Placeholder displacement byte 2
                    buffer[3] = 0x00; // Placeholder displacement byte 3
                    buffer[4] = 0x00; // Placeholder displacement byte 4
                    *size = 5;
                }
                else
                {
                    // 16-bit mode: emit 16-bit displacement placeholder (3 bytes total)
                    buffer[1] = 0x00; // Placeholder low byte
                    buffer[2] = 0x00; // Placeholder high byte
                    *size = 3;
                }
            }
            else if (strcasecmp(instr->mnemonic, "jmp") == 0)
            {
                // For unconditional jumps, start with short jump but be prepared to upgrade
                // In pass 1, always assume short jump for initial estimates
                if (asm_ctx->pass == 1)
                {
                    buffer[0] = def->opcode; // Short jump opcode (EB)
                    buffer[1] = 0x00;        // Placeholder displacement
                    *size = 2;
                }
                else
                {
                    // Pass 2+: Use conservative estimate (near jump) when target unknown
                    // This prevents size underestimation that causes cascading changes
                    buffer[0] = 0xE9; // Near JMP opcode
                    buffer[1] = 0x00; // Placeholder low byte
                    buffer[2] = 0x00; // Placeholder high byte
                    *size = 3;
                }
            }
            else
            {
                // For conditional jumps, start with short jump but be prepared to upgrade
                // In pass 1, always assume short jump for initial estimates
                if (asm_ctx->pass == 1)
                {
                    buffer[0] = def->opcode; // Short conditional jump opcode
                    buffer[1] = 0x00;        // Placeholder displacement
                    *size = 2;
                }
                else
                {
                    // Pass 2+: Use conservative estimate (near conditional jump) when target unknown
                    // This prevents size underestimation that causes cascading changes
                    uint8_t near_opcode = get_near_condition_opcode(def->opcode);
                    if (near_opcode != 0)
                    {
                        buffer[0] = 0x0F;        // Two-byte opcode prefix
                        buffer[1] = near_opcode; // Near conditional jump opcode
                        buffer[2] = 0x00;        // Placeholder low byte
                        buffer[3] = 0x00;        // Placeholder high byte
                        *size = 4;
                    }
                    else
                    {
                        // Fallback to short jump for unknown conditions
                        buffer[0] = def->opcode;
                        buffer[1] = 0x00; // Placeholder displacement
                        *size = 2;
                    }
                }
            }
            return true;
        }
    } // Default case with placeholder - use same logic as when target not available
    if (def->opcode == 0xE8)
    {
        // CALL instruction - size depends on mode
        buffer[0] = def->opcode;
        if (asm_ctx->mode == MODE_32BIT)
        {
            // 32-bit mode: emit 32-bit displacement placeholder (5 bytes total)
            buffer[1] = 0x00; // Placeholder displacement byte 1
            buffer[2] = 0x00; // Placeholder displacement byte 2
            buffer[3] = 0x00; // Placeholder displacement byte 3
            buffer[4] = 0x00; // Placeholder displacement byte 4
            *size = 5;
        }
        else
        {
            // 16-bit mode: emit 16-bit displacement placeholder (3 bytes total)
            buffer[1] = 0x00; // Placeholder low byte
            buffer[2] = 0x00; // Placeholder high byte
            *size = 3;
        }
    }
    else if (strcasecmp(instr->mnemonic, "jmp") == 0)
    {
        // For unconditional jumps, start with short jump in pass 1
        if (asm_ctx->pass == 1)
        {
            buffer[0] = def->opcode; // Short jump opcode (EB)
            buffer[1] = 0x00;        // Placeholder displacement
            *size = 2;
        }
        else
        {
            // Pass 2+: Use conservative estimate (near jump) when target unknown
            buffer[0] = 0xE9; // Near JMP opcode
            buffer[1] = 0x00; // Placeholder low byte
            buffer[2] = 0x00; // Placeholder high byte
            *size = 3;
        }
    }
    else
    {
        // For conditional jumps, start with short jump in pass 1
        if (asm_ctx->pass == 1)
        {
            buffer[0] = def->opcode; // Short conditional jump opcode
            buffer[1] = 0x00;        // Placeholder displacement
            *size = 2;
        }
        else
        {
            // Pass 2+: Use conservative estimate (near conditional jump) when target unknown
            uint8_t near_opcode = get_near_condition_opcode(def->opcode);
            if (near_opcode != 0)
            {
                buffer[0] = 0x0F;        // Two-byte opcode prefix
                buffer[1] = near_opcode; // Near conditional jump opcode
                buffer[2] = 0x00;        // Placeholder low byte
                buffer[3] = 0x00;        // Placeholder high byte
                *size = 4;
            }
            else
            {
                // Fallback to short jump for unknown conditions
                buffer[0] = def->opcode;
                buffer[1] = 0x00; // Placeholder displacement
                *size = 2;
            }
        }
    }
    return true;
}

static bool encode_inc_dec(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 1)
    {
        return false;
    }

    if (instr->operands[0].type == OPERAND_REGISTER)
    {
        // Handle register operands
        register_t reg = instr->operands[0].value.reg;
        uint8_t reg_code = register_to_modrm(reg);
        int reg_size = get_register_size(reg);

        // In 64-bit mode, the one-byte INC/DEC opcodes (0x40-0x4F) are repurposed as REX prefixes
        // So we must use the longer form with ModR/M byte for all register sizes in 64-bit mode
        if (reg_size == 16 && asm_ctx->mode != MODE_64BIT)
        {
            // For 16-bit registers in 16-bit or 32-bit mode, use short form (INC/DEC reg16)
            if (strcasecmp(instr->mnemonic, "inc") == 0)
            {
                buffer[0] = 0x40 + reg_code; // INC reg16
            }
            else
            {
                buffer[0] = 0x48 + reg_code; // DEC reg16
            }
            *size = 1;
        }
        else
        {
            // For all other cases, use ModR/M form
            uint8_t modrm_reg = strcasecmp(instr->mnemonic, "inc") == 0 ? 0 : 1; // INC=0, DEC=1

            if (reg_size == 8)
            {
                buffer[0] = 0xFE; // INC/DEC r/m8
            }
            else
            {
                buffer[0] = 0xFF; // INC/DEC r/m16/32/64
            }

            buffer[1] = make_modrm(3, modrm_reg, reg_code);
            *size = 2;
        }
        return true;
    }
    else if (instr->operands[0].type == OPERAND_MEMORY)
    {
        // Handle memory operands: INC/DEC r/m16 or r/m8
        int operand_size = instr->operands[0].size; // Use explicit size (8 or 16)

        if (operand_size == 8)
        {
            buffer[0] = 0xFE; // INC/DEC r/m8
        }
        else
        {
            buffer[0] = 0xFF; // INC/DEC r/m16
        }

        uint8_t modrm_reg = strcasecmp(instr->mnemonic, "inc") == 0 ? 0 : 1; // INC=0, DEC=1        // Handle different memory addressing modes
        if (instr->operands[0].value.memory.has_label)
        {
            // Direct memory addressing [label]: mod=00, r/m=6
            buffer[1] = make_modrm(0, modrm_reg, 6);

            // Lookup symbol address during pass 2
            symbol_t *sym = symbol_lookup(asm_ctx, instr->operands[0].value.memory.label);
            uint16_t addr = sym && sym->defined ? sym->address : 0;

            buffer[2] = (uint8_t)(addr & 0xFF);        // Address low byte
            buffer[3] = (uint8_t)((addr >> 8) & 0xFF); // Address high byte
            *size = 4;
        }
        else if (instr->operands[0].value.memory.base == REG_NONE)
        {
            // Direct memory addressing [immediate]: mod=00, r/m=6
            buffer[1] = make_modrm(0, modrm_reg, 6);
            buffer[2] = (uint8_t)(instr->operands[0].value.memory.displacement & 0xFF);
            buffer[3] = (uint8_t)((instr->operands[0].value.memory.displacement >> 8) & 0xFF);
            *size = 4;
        }
        else if (instr->operands[0].value.memory.index != REG_NONE)
        {
            // Base+index addressing [base+index], [base+index+disp]
            register_t base_reg = instr->operands[0].value.memory.base;
            register_t index_reg = instr->operands[0].value.memory.index;
            int32_t displacement = instr->operands[0].value.memory.displacement;

            uint8_t rm_code = get_base_index_rm(base_reg, index_reg);

            if (displacement == 0 && base_reg != REG_BP)
            {
                // [base+index] - mod=00
                buffer[1] = make_modrm(0, modrm_reg, rm_code);
                *size = 2;
            }
            else if (displacement >= -128 && displacement <= 127)
            {
                // [base+index+disp8] - mod=01
                buffer[1] = make_modrm(1, modrm_reg, rm_code);
                buffer[2] = (uint8_t)displacement;
                *size = 3;
            }
            else
            {
                // [base+index+disp16] - mod=10
                buffer[1] = make_modrm(2, modrm_reg, rm_code);
                buffer[2] = (uint8_t)(displacement & 0xFF);
                buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
                *size = 4;
            }
        }
        else
        {
            // Single register-based addressing [reg], [reg+disp]
            uint8_t base_code = register_to_rm(instr->operands[0].value.memory.base, asm_ctx->mode);

            if (instr->operands[0].value.memory.displacement == 0 && instr->operands[0].value.memory.base != REG_BP)
            {
                // [reg] - mod=00
                buffer[1] = make_modrm(0, modrm_reg, base_code);
                *size = 2;
            }
            else if (instr->operands[0].value.memory.displacement >= -128 && instr->operands[0].value.memory.displacement <= 127)
            {
                // [reg+disp8] - mod=01
                buffer[1] = make_modrm(1, modrm_reg, base_code);
                buffer[2] = (uint8_t)instr->operands[0].value.memory.displacement;
                *size = 3;
            }
            else
            {
                // [reg+disp16] - mod=10
                buffer[1] = make_modrm(2, modrm_reg, base_code);
                buffer[2] = (uint8_t)(instr->operands[0].value.memory.displacement & 0xFF);
                buffer[3] = (uint8_t)((instr->operands[0].value.memory.displacement >> 8) & 0xFF);
                *size = 4;
            }
        }
        return true;
    }

    return false; // Unsupported operand type
}

static bool encode_shift_rotate(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count < 1 || instr->operands[0].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t reg = instr->operands[0].value.reg;
    uint8_t reg_code = register_to_modrm(reg);
    int reg_size = get_register_size(reg);

    const instruction_def_t *def = find_instruction(instr->mnemonic);
    if (!def)
        return false;

    if (instr->operand_count == 1)
    {
        // Shift by 1 (implicit)
        if (reg_size == 8)
        {
            buffer[0] = 0xD0;
        }
        else
        {
            buffer[0] = 0xD1;
        }
        buffer[1] = make_modrm(3, def->modrm_reg, reg_code);
        *size = 2;
    }
    else if (instr->operand_count == 2)
    {
        if (instr->operands[1].type == OPERAND_REGISTER &&
            instr->operands[1].value.reg == REG_CL)
        {
            // Shift by CL
            if (reg_size == 8)
            {
                buffer[0] = 0xD2;
            }
            else
            {
                buffer[0] = 0xD3;
            }
            buffer[1] = make_modrm(3, def->modrm_reg, reg_code);
            *size = 2;
        }
        else if (instr->operands[1].type == OPERAND_IMMEDIATE)
        {
            // Shift by immediate (386+ feature, but we'll support it)
            int32_t count = instr->operands[1].value.immediate;
            if (count == 1)
            {
                // Use single-bit shift
                if (reg_size == 8)
                {
                    buffer[0] = 0xD0;
                }
                else
                {
                    buffer[0] = 0xD1;
                }
                buffer[1] = make_modrm(3, def->modrm_reg, reg_code);
                *size = 2;
            }
            else
            {
                // Use immediate shift
                if (reg_size == 8)
                {
                    buffer[0] = 0xC0;
                }
                else
                {
                    buffer[0] = 0xC1;
                }
                buffer[1] = make_modrm(3, def->modrm_reg, reg_code);
                buffer[2] = (uint8_t)count;
                *size = 3;
            }
        }
    }
    return true;
}

static bool encode_mul_div(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 1 || instr->operands[0].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t reg = instr->operands[0].value.reg;
    uint8_t reg_code = register_to_modrm(reg);
    int reg_size = get_register_size(reg);

    const instruction_def_t *def = find_instruction(instr->mnemonic);
    if (!def)
        return false;

    if (reg_size == 8)
    {
        buffer[0] = 0xF6;
    }
    else
    {
        buffer[0] = 0xF7;
    }
    buffer[1] = make_modrm(3, def->modrm_reg, reg_code);
    *size = 2;
    return true;
}

static bool encode_unary_ops(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 1 || instr->operands[0].type != OPERAND_REGISTER)
    {
        return false;
    }

    register_t reg = instr->operands[0].value.reg;
    uint8_t reg_code = register_to_modrm(reg);
    int reg_size = get_register_size(reg);

    const instruction_def_t *def = find_instruction(instr->mnemonic);
    if (!def)
        return false;

    if (reg_size == 8)
    {
        buffer[0] = 0xF6;
    }
    else
    {
        buffer[0] = 0xF7;
    }
    buffer[1] = make_modrm(3, def->modrm_reg, reg_code);
    *size = 2;
    return true;
}

static bool encode_io_ops(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 2)
    {
        return false;
    }

    if (strcasecmp(instr->mnemonic, "in") == 0)
    {
        // IN AL/AX, imm8 or IN AL/AX, DX
        if (instr->operands[0].type == OPERAND_REGISTER &&
            (instr->operands[0].value.reg == REG_AL || instr->operands[0].value.reg == REG_AX))
        {

            if (instr->operands[1].type == OPERAND_IMMEDIATE)
            {
                // IN AL/AX, imm8
                if (instr->operands[0].value.reg == REG_AL)
                {
                    buffer[0] = 0xE4; // IN AL, imm8
                }
                else
                {
                    buffer[0] = 0xE5; // IN AX, imm8
                }
                buffer[1] = (uint8_t)instr->operands[1].value.immediate;
                *size = 2;
                return true;
            }
            else if (instr->operands[1].type == OPERAND_REGISTER &&
                     instr->operands[1].value.reg == REG_DX)
            {
                // IN AL/AX, DX
                if (instr->operands[0].value.reg == REG_AL)
                {
                    buffer[0] = 0xEC; // IN AL, DX
                }
                else
                {
                    buffer[0] = 0xED; // IN AX, DX
                }
                *size = 1;
                return true;
            }
        }
    }
    else if (strcasecmp(instr->mnemonic, "out") == 0)
    {
        // OUT imm8, AL/AX or OUT DX, AL/AX
        if (instr->operands[1].type == OPERAND_REGISTER &&
            (instr->operands[1].value.reg == REG_AL || instr->operands[1].value.reg == REG_AX))
        {

            if (instr->operands[0].type == OPERAND_IMMEDIATE)
            {
                // OUT imm8, AL/AX
                if (instr->operands[1].value.reg == REG_AL)
                {
                    buffer[0] = 0xE6; // OUT imm8, AL
                }
                else
                {
                    buffer[0] = 0xE7; // OUT imm8, AX
                }
                buffer[1] = (uint8_t)instr->operands[0].value.immediate;
                *size = 2;
                return true;
            }
            else if (instr->operands[0].type == OPERAND_REGISTER &&
                     instr->operands[0].value.reg == REG_DX)
            {
                // OUT DX, AL/AX
                if (instr->operands[1].value.reg == REG_AL)
                {
                    buffer[0] = 0xEE; // OUT DX, AL
                }
                else
                {
                    buffer[0] = 0xEF; // OUT DX, AX
                }
                *size = 1;
                return true;
            }
        }
    }
    return false;
}

static bool encode_ret_imm(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 1 || instr->operands[0].type != OPERAND_IMMEDIATE)
    {
        return false;
    }

    int32_t value = instr->operands[0].value.immediate;
    buffer[0] = 0xC2; // RET imm16
    buffer[1] = (uint8_t)(value & 0xFF);
    buffer[2] = (uint8_t)((value >> 8) & 0xFF);
    *size = 3;
    return true;
}

static bool encode_aam_aad(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 0)
    {
        return false; // These are no-operand instructions
    }

    if (strcasecmp(instr->mnemonic, "aam") == 0)
    {
        buffer[0] = 0xD4;
        buffer[1] = 0x0A;
        *size = 2;
    }
    else if (strcasecmp(instr->mnemonic, "aad") == 0)
    {
        buffer[0] = 0xD5;
        buffer[1] = 0x0A;
        *size = 2;
    }
    else
    {
        return false;
    }
    return true;
}

static bool encode_syscall(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 0)
    {
        return false; // SYSCALL has no operands
    }

    if (strcasecmp(instr->mnemonic, "syscall") == 0)
    {
        buffer[0] = 0x0F; // Two-byte opcode prefix
        buffer[1] = 0x05; // SYSCALL opcode
        *size = 2;
        return true;
    }
    return false;
}

static bool encode_sysret(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 0)
    {
        return false; // SYSRET has no operands
    }

    if (strcasecmp(instr->mnemonic, "sysret") == 0)
    {
        buffer[0] = 0x0F; // Two-byte opcode prefix
        buffer[1] = 0x07; // SYSRET opcode
        *size = 2;
        return true;
    }
    return false;
}

static bool encode_sysenter(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 0)
    {
        return false; // SYSENTER has no operands
    }

    if (strcasecmp(instr->mnemonic, "sysenter") == 0)
    {
        buffer[0] = 0x0F; // Two-byte opcode prefix
        buffer[1] = 0x34; // SYSENTER opcode
        *size = 2;
        return true;
    }
    return false;
}

static bool encode_sysexit(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 0)
    {
        return false; // SYSEXIT has no operands
    }

    if (strcasecmp(instr->mnemonic, "sysexit") == 0)
    {
        buffer[0] = 0x0F; // Two-byte opcode prefix
        buffer[1] = 0x35; // SYSEXIT opcode
        *size = 2;
        return true;
    }
    return false;
}

static bool encode_memory_addressing(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 1 || instr->operands[0].type != OPERAND_MEMORY)
    {
        return false;
    }

    const instruction_def_t *def = find_instruction(instr->mnemonic);
    if (!def)
        return false;

    // For memory addressing, we need to handle different modes
    register_t base_reg = instr->operands[0].value.memory.base;
    register_t index_reg = instr->operands[0].value.memory.index;
    int32_t displacement = instr->operands[0].value.memory.displacement;

    // Determine ModR/M byte
    uint8_t modrm_byte = 0;
    if (base_reg == REG_NONE && index_reg == REG_NONE)
    {
        // Direct memory addressing [disp16]
        modrm_byte = make_modrm(0, def->modrm_reg, 6); // mod=00, r/m=110
        buffer[0] = def->opcode;                       // Opcode for memory operation
        buffer[1] = (uint8_t)(displacement & 0xFF);   // Low byte of displacement
        buffer[2] = (uint8_t)((displacement >> 8) & 0xFF); // High byte of displacement
        *size = 3;
    }
    else if (base_reg != REG_NONE && index_reg == REG_NONE)
    {
        // Base addressing [base+disp16]
        uint8_t base_code = register_to_rm(base_reg, asm_ctx->mode);
        if (displacement == 0 && base_reg != REG_BP)
        {
            modrm_byte = make_modrm(0, def->modrm_reg, base_code); // mod=00
            buffer[0] = def->opcode;                                // Opcode for memory operation
            buffer[1] = modrm_byte;                                // ModR/M byte
            *size = 2;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            modrm_byte = make_modrm(1, def->modrm_reg, base_code); // mod=01
            buffer[0] = def->opcode;                                // Opcode for memory operation
            buffer[1] = modrm_byte;                                // ModR/M byte
            buffer[2] = (uint8_t)displacement;                     // 8-bit
            *size = 3;
        }
        else
        {
            modrm_byte = make_modrm(2, def->modrm_reg, base_code); // mod=10
            buffer[0] = def->opcode;                                // Opcode for memory operation
            buffer[1] = modrm_byte;                                // ModR/M byte
            buffer[2] = (uint8_t)(displacement & 0xFF);            // Low byte of displacement
            buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);     // High byte of displacement
            *size = 4;
        }
    }
    else if (base_reg != REG_NONE && index_reg != REG_NONE)
    {
        // Indexed addressing [base+index*scale+disp32]
        uint8_t base_code = register_to_rm(base_reg, asm_ctx->mode);
        uint8_t index_code = register_to_rm(index_reg, asm_ctx->mode);
        uint8_t scale = instr->operands[0].value.memory.scale;

        modrm_byte = make_modrm(2, def->modrm_reg, base_code); // mod=10
        buffer[0] = def->opcode;                                // Opcode for memory operation
        buffer[1] = modrm_byte;                                // ModR/M byte
        buffer[2] = (uint8_t)(displacement & 0xFF);            // Low byte of displacement
        buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);     // High byte of displacement
        buffer[4] = scale;                                      // Scale
        *size = 5;
    }
    else
    {
        // Unsupported addressing mode
        return false;
    }
    // Store ModR/M byte in the buffer
    buffer[0] = def->opcode; // Opcode for memory operation
    buffer[1] = modrm_byte;  // ModR/M byte
    if (def->opcode == 0x0F) // Two-byte opcode prefix
    {
        // If the instruction uses a two-byte opcode, we need to handle that
        buffer[0] = 0x0F; // Two-byte prefix
        buffer[1] = def->opcode; // Second byte of the opcode
        *size += 1; // Adjust size for two-byte opcode
    }
    else
    {
        *size = 2; // Size for single-byte opcode + ModR/M byte
    }
    return true;
}


static bool encode_rep_string(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    const instruction_def_t *def = find_instruction(instr->mnemonic);
    if (!def)
        return false;

    // REP + string operation: emit prefix byte followed by string operation byte
    // The opcode is stored as a 16-bit value: high byte is prefix, low byte is string op
    uint16_t combined_opcode = def->opcode;
    buffer[0] = (uint8_t)((combined_opcode >> 8) & 0xFF); // Prefix byte (0xF2 or 0xF3)
    buffer[1] = (uint8_t)(combined_opcode & 0xFF);        // String operation byte
    *size = 2;
    return true;
}

static bool encode_test_reg_imm(const instruction_t *instr, uint8_t *buffer, size_t *size)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_REGISTER ||
        instr->operands[1].type != OPERAND_IMMEDIATE)
    {
        return false;
    }

    register_t reg = instr->operands[0].value.reg;
    int32_t value = instr->operands[1].value.immediate;
    uint8_t reg_code = register_to_modrm(reg);
    int reg_size = get_register_size(reg);

    if (reg_size == 8)
    {
        // 8-bit register with 8-bit immediate - opcode 0xF6
        buffer[0] = 0xF6;
        buffer[1] = make_modrm(3, 0, reg_code); // ModR/M reg field = 0 for TEST
        buffer[2] = (uint8_t)value;
        *size = 3;
    }
    else
    {
        // 16-bit register with 16-bit immediate - opcode 0xF7
        buffer[0] = 0xF7;
        buffer[1] = make_modrm(3, 0, reg_code); // ModR/M reg field = 0 for TEST
        buffer[2] = (uint8_t)(value & 0xFF);
        buffer[3] = (uint8_t)((value >> 8) & 0xFF);
        *size = 4;
    }

    return true;
}

static bool encode_two_byte_mem(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 1 || instr->operands[0].type != OPERAND_MEMORY)
    {
        return false;
    }

    const instruction_def_t *def = find_instruction(instr->mnemonic);
    if (!def)
        return false;

    // For LGDT: 0x0F 0x01 /2 m16&32
    buffer[0] = 0x0F;        // Two-byte instruction prefix
    buffer[1] = def->opcode; // Second byte (0x01 for LGDT)

    register_t base_reg = instr->operands[0].value.memory.base;
    register_t index_reg = instr->operands[0].value.memory.index;
    int32_t displacement = instr->operands[0].value.memory.displacement;
    uint8_t modrm_reg = def->modrm_reg; // reg field from instruction definition (2 for LGDT)

    size_t bytes_used = 2; // Start after 0x0F and opcode

    // Handle different memory addressing modes
    if (instr->operands[0].value.memory.has_label)
    {
        // Direct memory addressing [label]: mod=00, r/m=6
        buffer[2] = make_modrm(0, modrm_reg, 6);

        // Lookup symbol address during pass 2
        symbol_t *sym = symbol_lookup(asm_ctx, instr->operands[0].value.memory.label);
        uint16_t addr = sym && sym->defined ? sym->address : 0;

        buffer[3] = (uint8_t)(addr & 0xFF);        // Address low byte
        buffer[4] = (uint8_t)((addr >> 8) & 0xFF); // Address high byte
        bytes_used = 5;
    }
    else if (base_reg == REG_NONE)
    {
        // Direct memory addressing [immediate]: mod=00, r/m=6
        buffer[2] = make_modrm(0, modrm_reg, 6);
        buffer[3] = (uint8_t)(displacement & 0xFF);
        buffer[4] = (uint8_t)((displacement >> 8) & 0xFF);
        bytes_used = 5;
    }
    else if (index_reg != REG_NONE)
    {
        // Base+index addressing [base+index], [base+index+disp]
        uint8_t rm_code = get_base_index_rm(base_reg, index_reg);

        if (displacement == 0 && base_reg != REG_BP)
        {
            // [base+index] - mod=00
            buffer[2] = make_modrm(0, modrm_reg, rm_code);
            bytes_used = 3;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [base+index+disp8] - mod=01
            buffer[2] = make_modrm(1, modrm_reg, rm_code);
            buffer[3] = (uint8_t)displacement;
            bytes_used = 4;
        }
        else
        {
            // [base+index+disp16] - mod=10
            buffer[2] = make_modrm(2, modrm_reg, rm_code);
            buffer[3] = (uint8_t)(displacement & 0xFF);
            buffer[4] = (uint8_t)((displacement >> 8) & 0xFF);
            bytes_used = 5;
        }
    }
    else
    {
        // Single base register addressing [reg], [reg+disp]
        uint8_t base_code = register_to_rm(base_reg, asm_ctx->mode);

        if (displacement == 0 && base_reg != REG_BP)
        {
            // [reg] - mod=00
            buffer[2] = make_modrm(0, modrm_reg, base_code);
            bytes_used = 3;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [reg+disp8] - mod=01
            buffer[2] = make_modrm(1, modrm_reg, base_code);
            buffer[3] = (uint8_t)displacement;
            bytes_used = 4;
        }
        else
        {
            // [reg+disp16] - mod=10
            buffer[2] = make_modrm(2, modrm_reg, base_code);
            buffer[3] = (uint8_t)(displacement & 0xFF);
            buffer[4] = (uint8_t)((displacement >> 8) & 0xFF);
            bytes_used = 5;
        }
    }

    *size = bytes_used;
    return true;
}

// Helper function to get segment override prefix
static uint8_t get_segment_override_prefix(register_t segment)
{
    switch (segment)
    {
    case REG_ES:
        return 0x26;
    case REG_CS:
        return 0x2E;
    case REG_SS:
        return 0x36;
    case REG_DS:
        return 0x3E;
    case REG_FS:
        return 0x64;
    case REG_GS:
        return 0x65;
    default:
        return 0x00; // No prefix
    }
}

// Helper function to check if instruction has segment override
static bool has_segment_override(const instruction_t *instr)
{
    for (int i = 0; i < instr->operand_count; i++)
    {
        if (instr->operands[i].type == OPERAND_MEMORY &&
            instr->operands[i].value.memory.segment != REG_NONE)
        {
            return true;
        }
    }
    return false;
}

bool generate_opcode(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (asm_ctx->verbose)
    {
        printf("DEBUG: generate_opcode called for '%s' in pass %d\n", instr->mnemonic, asm_ctx->pass);
    }

    // Check for segment override and emit prefix if needed
    size_t prefix_size = 0;
    if (has_segment_override(instr))
    {
        for (int i = 0; i < instr->operand_count; i++)
        {
            if (instr->operands[i].type == OPERAND_MEMORY &&
                instr->operands[i].value.memory.segment != REG_NONE)
            {
                uint8_t prefix = get_segment_override_prefix(instr->operands[i].value.memory.segment);
                if (prefix != 0x00)
                {
                    buffer[0] = prefix;
                    prefix_size = 1;
                    if (asm_ctx->verbose)
                    {
                        printf("DEBUG: Emitting segment override prefix 0x%02X for segment %d\n",
                               prefix, instr->operands[i].value.memory.segment);
                    }
                    break; // Only one segment override per instruction
                }
            }
        }
    }

    // Handle operand size override for 16-bit operations in 64-bit mode
    bool needs_operand_size_override = false;
    if (asm_ctx->mode == MODE_64BIT)
    {
        // Check for 16-bit string operations
        if (strcasecmp(instr->mnemonic, "movsw") == 0 ||
            strcasecmp(instr->mnemonic, "cmpsw") == 0 ||
            strcasecmp(instr->mnemonic, "scasw") == 0 ||
            strcasecmp(instr->mnemonic, "lodsw") == 0 ||
            strcasecmp(instr->mnemonic, "stosw") == 0)
        {
            needs_operand_size_override = true;
        }
        // Check if any operand is a 16-bit register
        else if (instr->operand_count >= 1)
        {
            for (int i = 0; i < instr->operand_count; i++)
            {
                if (instr->operands[i].type == OPERAND_REGISTER)
                {
                    int reg_size = get_register_size(instr->operands[i].value.reg);
                    if (reg_size == 16)
                    {
                        needs_operand_size_override = true;
                        break;
                    }
                }
            }
        }
    }

    if (needs_operand_size_override)
    {
        buffer[prefix_size] = 0x66; // Operand size override prefix
        prefix_size++;
        if (asm_ctx->verbose)
        {
            printf("DEBUG: Emitting operand size override prefix 0x66\n");
        }
    }

    // Handle REX prefix for 64-bit mode
    size_t rex_offset = prefix_size;
    if (asm_ctx->mode == MODE_64BIT)
    {
        register_t reg1 = REG_NONE, reg2 = REG_NONE, reg3 = REG_NONE;

        // Extract registers from operands for REX calculation
        // For MOV reg, reg: reg1 = source (REX.R), reg2 = destination (REX.B)
        if (instr->operand_count >= 2 && instr->operands[1].type == OPERAND_REGISTER)
            reg1 = instr->operands[1].value.reg; // source register (REX.R)
        if (instr->operand_count >= 1 && instr->operands[0].type == OPERAND_REGISTER)
            reg2 = instr->operands[0].value.reg; // destination register (REX.B)
        if (instr->operand_count >= 1 && instr->operands[0].type == OPERAND_MEMORY)
        {
            reg2 = instr->operands[0].value.memory.base;
            reg3 = instr->operands[0].value.memory.index;
        }

        // Check for 64-bit string operations that need REX.W
        bool needs_rex_w = false;
        if (strcasecmp(instr->mnemonic, "movsq") == 0 ||
            strcasecmp(instr->mnemonic, "cmpsq") == 0 ||
            strcasecmp(instr->mnemonic, "scasq") == 0 ||
            strcasecmp(instr->mnemonic, "lodsq") == 0 ||
            strcasecmp(instr->mnemonic, "stosq") == 0)
        {
            needs_rex_w = true;
        }

        rex_prefix_t rex = calculate_rex_prefix(reg1, reg2, reg3, asm_ctx->mode);
        if (needs_rex_w)
        {
            rex.w = true;
            rex.present = true; // Force REX prefix for 64-bit operations
        }

        if (rex.present)
        {
            buffer[rex_offset] = encode_rex_prefix(&rex);
            prefix_size++;
            if (asm_ctx->verbose)
            {
                printf("DEBUG: Emitting REX prefix 0x%02X\n", buffer[rex_offset]);
            }
        }
    }

    // Use a temporary buffer for the main instruction, then copy to final buffer with prefix
    uint8_t temp_buffer[16];
    size_t temp_size = 0; // Handle far pointer calls and jumps: jmp seg:off, call seg:off
    if (instr->operand_count == 1 && instr->operands[0].type == OPERAND_FARPTR)
    {
        uint16_t offset = instr->operands[0].value.far_ptr.offset;
        uint16_t segment = instr->operands[0].value.far_ptr.segment;

        // If offset is a label, resolve it
        if (instr->operands[0].value.far_ptr.has_label_offset)
        {
            symbol_t *sym = symbol_lookup(asm_ctx, instr->operands[0].value.far_ptr.offset_label);
            if (sym && sym->defined)
            {
                offset = (uint16_t)sym->address;
            }
            else
            {
                // Label not defined, set offset to 0 (will be resolved in later pass)
                offset = 0;
            }
        }

        if (strcasecmp(instr->mnemonic, "jmp") == 0)
        {
            temp_buffer[0] = 0xEA; // FAR JMP ptr16:16
        }
        else if (strcasecmp(instr->mnemonic, "call") == 0)
        {
            temp_buffer[0] = 0x9A; // FAR CALL ptr16:16
        }
        else
        {
            return false;
        }
        temp_buffer[1] = (uint8_t)(offset & 0xFF);
        temp_buffer[2] = (uint8_t)(offset >> 8);
        temp_buffer[3] = (uint8_t)(segment & 0xFF);
        temp_buffer[4] = (uint8_t)(segment >> 8);
        temp_size = 5;

        // Copy to final buffer with prefix
        memcpy(buffer + prefix_size, temp_buffer, temp_size);
        *size = prefix_size + temp_size;
        return true;
    } // Handle MOV reg, [label] and MOV [label], reg (direct memory by label)
    if (strcasecmp(instr->mnemonic, "mov") == 0 && instr->operand_count == 2)
    {
        // MOV reg16, [label]
        if (instr->operands[0].type == OPERAND_REGISTER &&
            instr->operands[1].type == OPERAND_MEMORY && instr->operands[1].value.memory.has_label)
        {
            // Lookup symbol address
            symbol_t *sym = symbol_lookup(asm_ctx, instr->operands[1].value.memory.label);
            uint16_t addr = sym && sym->defined ? sym->address : 0;
            uint8_t reg_code = register_to_modrm(instr->operands[0].value.reg);
            int reg_size = get_register_size(instr->operands[0].value.reg);
            // Opcode: MOV r/m16, r16 reversed since reg->mem
            temp_buffer[0] = reg_size == 8 ? 0x8A : 0x8B; // r8,r/m8 or r16,r/m16
            temp_buffer[1] = make_modrm(0, reg_code, 6);  // mod=00, r/m=6 for direct mem
            temp_buffer[2] = addr & 0xFF;
            temp_buffer[3] = addr >> 8;
            temp_size = 4;

            // Copy to final buffer with prefix
            memcpy(buffer + prefix_size, temp_buffer, temp_size);
            *size = prefix_size + temp_size;
            return true;
        }
        // MOV [label], reg16
        if (instr->operands[0].type == OPERAND_MEMORY && instr->operands[0].value.memory.has_label &&
            instr->operands[1].type == OPERAND_REGISTER)
        {
            symbol_t *sym = symbol_lookup(asm_ctx, instr->operands[0].value.memory.label);
            uint16_t addr = sym && sym->defined ? sym->address : 0;
            uint8_t reg_code = register_to_modrm(instr->operands[1].value.reg);
            int reg_size = get_register_size(instr->operands[1].value.reg);
            temp_buffer[0] = reg_size == 8 ? 0x88 : 0x89; // MOV r/m8,r8 or r/m16,r16
            temp_buffer[1] = make_modrm(0, reg_code, 6);
            temp_buffer[2] = addr & 0xFF;
            temp_buffer[3] = addr >> 8;
            temp_size = 4;

            // Copy to final buffer with prefix
            memcpy(buffer + prefix_size, temp_buffer, temp_size);
            *size = prefix_size + temp_size;
            return true;
        }
    } // Handle MOV instruction with different operand combinations
    if (strcasecmp(instr->mnemonic, "mov") == 0)
    {
        if (instr->operand_count == 2)
        {
            bool result = false;
            if (instr->operands[0].type == OPERAND_REGISTER &&
                instr->operands[1].type == OPERAND_REGISTER)
            {
                result = encode_mov_reg_reg(instr, temp_buffer, &temp_size);
            }
            else if (instr->operands[0].type == OPERAND_REGISTER &&
                     instr->operands[1].type == OPERAND_IMMEDIATE)
            {
                result = encode_mov_reg_imm(instr, temp_buffer, &temp_size, asm_ctx);
            }
            else if (instr->operands[0].type == OPERAND_REGISTER &&
                     instr->operands[1].type == OPERAND_LABEL)
            {
                // In pass 1, labels will be converted to immediates in pass 2
                // So we need to calculate the size as if it were an immediate
                instruction_t temp_instr = *instr;
                temp_instr.operands[1].type = OPERAND_IMMEDIATE;
                temp_instr.operands[1].value.immediate = 0; // Placeholder value for size calculation
                result = encode_mov_reg_imm(&temp_instr, temp_buffer, &temp_size, asm_ctx);
            }
            else if (instr->operands[0].type == OPERAND_REGISTER &&
                     instr->operands[1].type == OPERAND_MEMORY)
            {
                result = encode_mov_reg_mem(instr, temp_buffer, &temp_size, asm_ctx);
            }
            else if (instr->operands[0].type == OPERAND_MEMORY &&
                     instr->operands[1].type == OPERAND_REGISTER)
            {
                result = encode_mov_mem_reg(instr, temp_buffer, &temp_size, asm_ctx);
            }
            else if (instr->operands[0].type == OPERAND_MEMORY &&
                     instr->operands[1].type == OPERAND_IMMEDIATE)
            {
                result = encode_mov_mem_imm(instr, temp_buffer, &temp_size, asm_ctx);
            }

            if (result)
            {
                // Copy to final buffer with prefix
                memcpy(buffer + prefix_size, temp_buffer, temp_size);
                *size = prefix_size + temp_size;
                return true;
            }
        }
        return false; // Unsupported MOV combination
    } // Handle LEA REG, [MEMORY] instruction
    if (strcasecmp(instr->mnemonic, "lea") == 0 && instr->operand_count == 2 &&
        instr->operands[0].type == OPERAND_REGISTER && instr->operands[1].type == OPERAND_MEMORY)
    {
        // LEA reg, [mem] - load effective address
        uint8_t reg_code = register_to_modrm(instr->operands[0].value.reg);
        if (instr->operands[1].value.memory.has_label)
        {
            // Direct memory addressing with label
            symbol_t *sym = symbol_lookup(asm_ctx, instr->operands[1].value.memory.label);
            temp_buffer[0] = 0x8D; // LEA opcode
            
            if (asm_ctx->mode == MODE_64BIT)
            {
                // In 64-bit mode, use RIP-relative addressing
                temp_buffer[1] = make_modrm(0, reg_code, 5); // mod=00, r/m=101 for RIP-relative
                
                // Calculate RIP-relative displacement
                uint32_t addr = sym && sym->defined ? sym->address : 0;
                // LEA instruction with REX prefix is 7 bytes: REX(1) + opcode(1) + ModR/M(1) + disp32(4)
                uint32_t next_instr_addr = asm_ctx->current_address + 7;
                int32_t displacement = (int32_t)(addr - next_instr_addr);
                
                temp_buffer[2] = displacement & 0xFF;
                temp_buffer[3] = (displacement >> 8) & 0xFF;
                temp_buffer[4] = (displacement >> 16) & 0xFF;
                temp_buffer[5] = (displacement >> 24) & 0xFF;
                temp_size = 6;
            }
            else
            {
                // In 16-bit/32-bit mode, use direct addressing
                temp_buffer[1] = make_modrm(0, reg_code, 6); // mod=00, r/m=110 for direct mem
                uint16_t addr = sym && sym->defined ? sym->address : 0;
                temp_buffer[2] = addr & 0xFF;
                temp_buffer[3] = addr >> 8;
                temp_size = 4;
            }
        }
        else
        {
            // Memory addressing without label
            if (!encode_memory_addressing(instr, temp_buffer + 1, &temp_size, asm_ctx))
                return false; // Invalid memory addressing

            temp_buffer[0] = 0x8D; // LEA opcode
            temp_buffer[1] = make_modrm(2, reg_code, 0); // mod=10 for memory with displacement
        }

        // Copy to final buffer with prefix
        memcpy(buffer + prefix_size, temp_buffer, temp_size);
        *size = prefix_size + temp_size;
        return true;
    } // Handle XCHG instruction with different operand types
    if (strcasecmp(instr->mnemonic, "xchg") == 0)
    {
        if (instr->operand_count == 2)
        {
            bool result = false;
            if (instr->operands[0].type == OPERAND_REGISTER &&
                instr->operands[1].type == OPERAND_REGISTER)
            {
                result = encode_xchg_reg_reg(instr, temp_buffer, &temp_size);
            }
            else if (instr->operands[0].type == OPERAND_REGISTER &&
                     instr->operands[1].type == OPERAND_MEMORY)
            {
                result = encode_xchg_reg_mem(instr, temp_buffer, &temp_size);
            }
            else if (instr->operands[0].type == OPERAND_MEMORY &&
                     instr->operands[1].type == OPERAND_REGISTER)
            {
                result = encode_xchg_mem_reg(instr, temp_buffer, &temp_size);
            }

            if (result)
            {
                // Copy to final buffer with prefix
                memcpy(buffer + prefix_size, temp_buffer, temp_size);
                *size = prefix_size + temp_size;
                return true;
            }
        }
        return false; // Unsupported XCHG combination
    } // Handle PUSH instruction with different operand types
    if (strcasecmp(instr->mnemonic, "push") == 0)
    {
        if (instr->operand_count == 1)
        {
            bool result = false;
            if (instr->operands[0].type == OPERAND_REGISTER)
            {
                result = encode_push_reg(instr, temp_buffer, &temp_size);
            }
            else if (instr->operands[0].type == OPERAND_IMMEDIATE)
            {
                result = encode_push_imm(instr, temp_buffer, &temp_size, asm_ctx);
            }
            else if (instr->operands[0].type == OPERAND_MEMORY)
            {
                result = encode_push_mem(instr, temp_buffer, &temp_size, asm_ctx);
            }
            else if (instr->operands[0].type == OPERAND_LABEL)
            {
                // Handle external symbol labels - generate push imm32 with R_386_32 relocation
                symbol_t *symbol = symbol_lookup(asm_ctx, instr->operands[0].value.label);
                if (symbol && symbol->external)
                {
                    // Generate push imm32 instruction (opcode 0x68)
                    temp_buffer[0] = 0x68;
                    temp_buffer[1] = 0x00; // Placeholder for 32-bit immediate
                    temp_buffer[2] = 0x00;
                    temp_buffer[3] = 0x00;
                    temp_buffer[4] = 0x00;
                    temp_size = 5;

                    // Get current section for relocation
                    section_t *current_section = section_get_current(asm_ctx);
                    section_type_t section_type = current_section ? current_section->type : SECTION_TEXT;
                    uint32_t section_offset = asm_ctx->current_address - (current_section ? current_section->address : 0);

                    // Add relocation for absolute addressing (pointing to immediate field after opcode)
                    int relocation_type = (asm_ctx->mode == MODE_64BIT) ? R_X86_64_32S : R_386_32;
                    relocation_add(asm_ctx, section_offset + prefix_size + 1,
                                   instr->operands[0].value.label, relocation_type, section_type, 0);
                    result = true;
                }
            }

            if (result)
            {
                // Copy to final buffer with prefix
                memcpy(buffer + prefix_size, temp_buffer, temp_size);
                *size = prefix_size + temp_size;
                return true;
            }
        }
        return false; // Unsupported PUSH combination
    } // Handle arithmetic instructions (ADD, SUB, XOR, CMP, AND, OR, ADC, SBB, TEST) with different operand combinations
    if (strcasecmp(instr->mnemonic, "add") == 0 ||
        strcasecmp(instr->mnemonic, "sub") == 0 ||
        strcasecmp(instr->mnemonic, "xor") == 0 ||
        strcasecmp(instr->mnemonic, "cmp") == 0 ||
        strcasecmp(instr->mnemonic, "and") == 0 ||
        strcasecmp(instr->mnemonic, "or") == 0 ||
        strcasecmp(instr->mnemonic, "adc") == 0 ||
        strcasecmp(instr->mnemonic, "sbb") == 0 ||
        strcasecmp(instr->mnemonic, "test") == 0)
    {
        if (instr->operand_count == 2)
        {
            bool result = false;
            if (instr->operands[0].type == OPERAND_REGISTER &&
                instr->operands[1].type == OPERAND_REGISTER)
            {
                // Use register-register encoding
                const instruction_def_t *def = find_instruction(instr->mnemonic);
                if (def && def->encoding == ENC_REG_REG)
                {
                    result = encode_reg_reg_generic(instr, temp_buffer, &temp_size, def, asm_ctx);
                }
            }
            else if (instr->operands[0].type == OPERAND_REGISTER &&
                     instr->operands[1].type == OPERAND_IMMEDIATE)
            {
                // Special handling for TEST instruction
                if (strcasecmp(instr->mnemonic, "test") == 0)
                {
                    result = encode_test_reg_imm(instr, temp_buffer, &temp_size);
                }
                else
                { // Use register-immediate encoding for other arithmetic instructions
                    result = encode_arith_reg_imm(instr, temp_buffer, &temp_size, asm_ctx);
                }
            }
            else if (instr->operands[0].type == OPERAND_MEMORY &&
                     instr->operands[1].type == OPERAND_REGISTER)
            {
                // Memory-register combination
                result = encode_arith_mem_reg(instr, temp_buffer, &temp_size, asm_ctx);
            }
            else if (instr->operands[0].type == OPERAND_MEMORY &&
                     instr->operands[1].type == OPERAND_IMMEDIATE)
            {
                // Memory-immediate combination
                result = encode_arith_mem_imm(instr, temp_buffer, &temp_size, asm_ctx);
            }

            if (result)
            {
                // Copy to final buffer with prefix
                memcpy(buffer + prefix_size, temp_buffer, temp_size);
                *size = prefix_size + temp_size;
                return true;
            }
        }
        return false; // Unsupported arithmetic combination
    } // For other instructions, use the original table-based approach
    const instruction_def_t *def = find_instruction(instr->mnemonic);
    if (!def)
        return false;

    if (asm_ctx->verbose && (strcasecmp(instr->mnemonic, "call") == 0 || strcasecmp(instr->mnemonic, "jmp") == 0))
    {
        printf("DEBUG: Found instruction def for '%s', encoding=%d (ENC_CALL_REL=%d, ENC_JMP_REL=%d)\n",
               instr->mnemonic, def->encoding, ENC_CALL_REL, ENC_JMP_REL);
    }

    bool result = false;
    switch (def->encoding)
    {
    case ENC_SINGLE:
        result = encode_single_byte(instr, temp_buffer, &temp_size);
        break;
    case ENC_POP_REG:
        result = encode_pop_reg(instr, temp_buffer, &temp_size);
        break;
    case ENC_PUSH_MEM:
        result = encode_push_mem(instr, temp_buffer, &temp_size, asm_ctx);
        break;
    case ENC_REG_REG:
        // Handle other register-register instructions (non-arithmetic)
        result = encode_reg_reg_generic(instr, temp_buffer, &temp_size, def, asm_ctx);
        break;

    case ENC_REG_IMM:
        // Handle register-immediate instructions (non-arithmetic handled explicitly above)
        if (strcasecmp(instr->mnemonic, "mov") == 0)
        {
            result = encode_mov_reg_imm(instr, temp_buffer, &temp_size, asm_ctx);
        }
        break;

    case ENC_INT_IMM:
        result = encode_int_imm(instr, temp_buffer, &temp_size);
        break;
    case ENC_JMP_REL:
    case ENC_CALL_REL:
        // Special-case: jmp/call to '$' (current address)
        if (instr->operand_count == 1 && instr->operands[0].type == OPERAND_LABEL &&
            strcmp(instr->operands[0].value.label, "$") == 0)
        {
            // Emit short jump/call to current instruction address (2-byte instruction, so displacement = -2)
            temp_buffer[0] = def->opcode;
            temp_buffer[1] = (uint8_t)0xFE; // -2 in two's complement
            temp_size = 2;
            result = true;
            if (asm_ctx->verbose)
            {
                printf("DEBUG: Special case handling for %s $ - emitting 2-byte instruction with -2 displacement\n", instr->mnemonic);
            }
        }
        else
        {
            if (asm_ctx->verbose)
            {
                printf("DEBUG: Calling encode_jmp_rel for %s\n", instr->mnemonic);
            }
            result = encode_jmp_rel(instr, temp_buffer, &temp_size, asm_ctx);
        }
        break;
    case ENC_REP_STRING:
        result = encode_rep_string(instr, temp_buffer, &temp_size);
        break;

    case ENC_TWO_BYTE_MEM:
        result = encode_two_byte_mem(instr, temp_buffer, &temp_size, asm_ctx);
        break;

    case ENC_SPECIAL:
        // Handle special encoding cases
        if (strcasecmp(instr->mnemonic, "inc") == 0 ||
            strcasecmp(instr->mnemonic, "dec") == 0)
        {
            result = encode_inc_dec(instr, temp_buffer, &temp_size, asm_ctx);
        }
        else if (strcasecmp(instr->mnemonic, "shl") == 0 ||
                 strcasecmp(instr->mnemonic, "shr") == 0 ||
                 strcasecmp(instr->mnemonic, "sal") == 0 ||
                 strcasecmp(instr->mnemonic, "sar") == 0 ||
                 strcasecmp(instr->mnemonic, "rol") == 0 ||
                 strcasecmp(instr->mnemonic, "ror") == 0 ||
                 strcasecmp(instr->mnemonic, "rcl") == 0 ||
                 strcasecmp(instr->mnemonic, "rcr") == 0)
        {
            result = encode_shift_rotate(instr, temp_buffer, &temp_size);
        }
        else if (strcasecmp(instr->mnemonic, "mul") == 0 ||
                 strcasecmp(instr->mnemonic, "imul") == 0 ||
                 strcasecmp(instr->mnemonic, "div") == 0 ||
                 strcasecmp(instr->mnemonic, "idiv") == 0)
        {
            result = encode_mul_div(instr, temp_buffer, &temp_size);
        }
        else if (strcasecmp(instr->mnemonic, "not") == 0 ||
                 strcasecmp(instr->mnemonic, "neg") == 0)
        {
            result = encode_unary_ops(instr, temp_buffer, &temp_size);
        }
        else if (strcasecmp(instr->mnemonic, "in") == 0 ||
                 strcasecmp(instr->mnemonic, "out") == 0)
        {
            result = encode_io_ops(instr, temp_buffer, &temp_size);
        }
        else if (strcasecmp(instr->mnemonic, "retn") == 0)
        {
            result = encode_ret_imm(instr, temp_buffer, &temp_size);
        }
        else if (strcasecmp(instr->mnemonic, "aam") == 0 ||
                 strcasecmp(instr->mnemonic, "aad") == 0)
        {
            result = encode_aam_aad(instr, temp_buffer, &temp_size);
        }
        else if (strcasecmp(instr->mnemonic, "syscall") == 0)
        {
            result = encode_syscall(instr, temp_buffer, &temp_size);
        }
        else if (strcasecmp(instr->mnemonic, "sysret") == 0)
        {
            result = encode_sysret(instr, temp_buffer, &temp_size);
        }
        else if (strcasecmp(instr->mnemonic, "sysenter") == 0)
        {
            static bool warned = false;
            if (asm_ctx->mode == MODE_64BIT)
            {
                if (!warned)
                {
                    printf("\033[1;33m[WARN]\033[0m SYSENTER is not supported in 64-bit mode and may cause \033[1;31m#UD (Undefined Instruction Exception)\033[0m\n");
                    warned = true;
                }
            }
            result = encode_sysenter(instr, temp_buffer, &temp_size);
        }
        else if (strcasecmp(instr->mnemonic, "sysexit") == 0)
        {
            static bool warned = false;
            if (asm_ctx->mode == MODE_64BIT)
            {
                if (!warned)
                {
                    printf("\033[1;33m[WARN]\033[0m SYSEXIT is not supported in 64-bit mode and may cause \033[1;31m#UD (Undefined Instruction Exception)\033[0m\n");
                    warned = true;
                }
            }
            result = encode_sysexit(instr, temp_buffer, &temp_size);
        }
        break;

    default:
        if (asm_ctx->verbose)
        {
            printf("DEBUG: Unhandled encoding type %d for %s\n", def->encoding, instr->mnemonic);
        }
        break;
    }

    if (result)
    {
        // Copy to final buffer with prefix
        memcpy(buffer + prefix_size, temp_buffer, temp_size);
        *size = prefix_size + temp_size;
        return true;
    }

    return false;
}

static bool encode_arith_mem_imm(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_MEMORY ||
        instr->operands[1].type != OPERAND_IMMEDIATE)
    {
        return false;
    }

    register_t base_reg = instr->operands[0].value.memory.base;
    register_t index_reg = instr->operands[0].value.memory.index;
    int32_t displacement = instr->operands[0].value.memory.displacement;
    int32_t value = instr->operands[1].value.immediate;

    // Determine the ModR/M reg field based on instruction
    uint8_t modrm_reg;
    if (strcasecmp(instr->mnemonic, "add") == 0)
    {
        modrm_reg = 0; // ADD
    }
    else if (strcasecmp(instr->mnemonic, "or") == 0)
    {
        modrm_reg = 1; // OR
    }
    else if (strcasecmp(instr->mnemonic, "adc") == 0)
    {
        modrm_reg = 2; // ADC
    }
    else if (strcasecmp(instr->mnemonic, "sbb") == 0)
    {
        modrm_reg = 3; // SBB
    }
    else if (strcasecmp(instr->mnemonic, "and") == 0)
    {
        modrm_reg = 4; // AND
    }
    else if (strcasecmp(instr->mnemonic, "sub") == 0)
    {
        modrm_reg = 5; // SUB
    }
    else if (strcasecmp(instr->mnemonic, "xor") == 0)
    {
        modrm_reg = 6; // XOR
    }
    else if (strcasecmp(instr->mnemonic, "cmp") == 0)
    {
        modrm_reg = 7; // CMP
    }
    else if (strcasecmp(instr->mnemonic, "test") == 0)
    {
        modrm_reg = 0; // TEST
    }
    else
    {
        return false; // Unsupported arithmetic instruction
    }

    // Determine operand size from explicit size or default to 16-bit
    int operand_size = instr->operands[0].size; // Should be 8 or 16 from "byte [...]" or "word [...]"
    if (operand_size == 0)
    {
        operand_size = 16; // Default to 16-bit if no explicit size
    }
    // Choose opcode based on immediate value size and operand size
    uint8_t opcode;
    bool use_8bit_immediate = false;

    if (strcasecmp(instr->mnemonic, "test") == 0)
    {
        // TEST uses different opcodes and doesn't support sign-extended 8-bit immediate
        if (operand_size == 8)
        {
            opcode = 0xF6; // TEST byte
        }
        else
        {
            opcode = 0xF7; // TEST word
        }
    }
    else if (value >= -128 && value <= 127 && operand_size == 16)
    {
        // Use 8-bit immediate (sign-extended) for 16-bit operands - opcode 0x83
        opcode = 0x83;
        use_8bit_immediate = true;
    }
    else if (operand_size == 8)
    {
        // 8-bit memory operand with 8-bit immediate - opcode 0x80
        opcode = 0x80;
    }
    else
    {
        // 16-bit memory operand with 16-bit immediate - opcode 0x81
        opcode = 0x81;
    }

    buffer[0] = opcode;

    // Handle different memory addressing modes
    size_t bytes_used = 1; // Start after opcode

    if (instr->operands[0].value.memory.has_label)
    {
        // Direct memory addressing by label: mod=00, r/m=6
        buffer[1] = make_modrm(0, modrm_reg, 6);

        // Lookup symbol address
        symbol_t *sym = symbol_lookup(asm_ctx, instr->operands[0].value.memory.label);
        uint16_t addr = sym && sym->defined ? sym->address : 0;

        buffer[2] = (uint8_t)(addr & 0xFF);        // Address low byte
        buffer[3] = (uint8_t)((addr >> 8) & 0xFF); // Address high byte
        bytes_used = 4;
    }
    else if (base_reg == REG_NONE)
    {
        // Direct memory addressing [immediate]: mod=00, r/m=6
        buffer[1] = make_modrm(0, modrm_reg, 6);
        buffer[2] = (uint8_t)(displacement & 0xFF);
        buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
        bytes_used = 4;
    }
    else if (index_reg != REG_NONE)
    {
        // Base+index addressing
        uint8_t rm_code = get_base_index_rm(base_reg, index_reg);

        if (displacement == 0 && base_reg != REG_BP)
        {
            // [base+index] - mod=00
            buffer[1] = make_modrm(0, modrm_reg, rm_code);
            bytes_used = 2;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [base+index+disp8] - mod=01
            buffer[1] = make_modrm(1, modrm_reg, rm_code);
            buffer[2] = (uint8_t)displacement;
            bytes_used = 3;
        }
        else
        {
            // [base+index+disp16] - mod=10
            buffer[1] = make_modrm(2, modrm_reg, rm_code);
            buffer[2] = (uint8_t)(displacement & 0xFF);
            buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
            bytes_used = 4;
        }
    }
    else
    {
        // Single base register addressing
        uint8_t base_code = register_to_rm(base_reg, asm_ctx->mode);

        if (displacement == 0 && base_reg != REG_BP)
        {
            // [reg] - mod=00
            buffer[1] = make_modrm(0, modrm_reg, base_code);
            bytes_used = 2;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [reg+disp8] - mod=01
            buffer[1] = make_modrm(1, modrm_reg, base_code);
            buffer[2] = (uint8_t)displacement;
            bytes_used = 3;
        }
        else
        {
            // [reg+disp16] - mod=10
            buffer[1] = make_modrm(2, modrm_reg, base_code);
            buffer[2] = (uint8_t)(displacement & 0xFF);
            buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
            bytes_used = 4;
        }
    }

    // Add the immediate value at the end
    if (use_8bit_immediate)
    {
        buffer[bytes_used] = (uint8_t)value;
        *size = bytes_used + 1;
    }
    else if (operand_size == 8)
    {
        buffer[bytes_used] = (uint8_t)value;
        *size = bytes_used + 1;
    }
    else
    {
        buffer[bytes_used] = (uint8_t)(value & 0xFF);
        buffer[bytes_used + 1] = (uint8_t)((value >> 8) & 0xFF);
        *size = bytes_used + 2;
    }
    return true;
}

static bool encode_mov_mem_imm(const instruction_t *instr, uint8_t *buffer, size_t *size, assembler_t *asm_ctx)
{
    if (instr->operand_count != 2 ||
        instr->operands[0].type != OPERAND_MEMORY ||
        instr->operands[1].type != OPERAND_IMMEDIATE)
    {
        return false;
    }

    register_t base_reg = instr->operands[0].value.memory.base;
    register_t index_reg = instr->operands[0].value.memory.index;
    int32_t displacement = instr->operands[0].value.memory.displacement;
    int32_t value = instr->operands[1].value.immediate;

    // Determine operand size from explicit size or default to 16-bit
    int operand_size = instr->operands[0].size; // Should be 8 or 16 from "byte [...]" or "word [...]"
    if (operand_size == 0)
    {
        operand_size = 16; // Default to 16-bit if no explicit size
    }

    // Choose opcode based on operand size
    uint8_t opcode;
    if (operand_size == 8)
    {
        opcode = 0xC6; // MOV r/m8, imm8
    }
    else
    {
        opcode = 0xC7; // MOV r/m16, imm16
    }

    buffer[0] = opcode;

    // Handle different memory addressing modes
    size_t bytes_used = 1; // Start after opcode
    uint8_t modrm_reg = 0; // For MOV immediate, the reg field is always 0

    if (instr->operands[0].value.memory.has_label)
    {
        // Direct memory addressing by label: mod=00, r/m=6
        buffer[1] = make_modrm(0, modrm_reg, 6);

        // Lookup symbol address
        symbol_t *sym = symbol_lookup(asm_ctx, instr->operands[0].value.memory.label);
        uint16_t addr = sym && sym->defined ? sym->address : 0;

        buffer[2] = (uint8_t)(addr & 0xFF);        // Address low byte
        buffer[3] = (uint8_t)((addr >> 8) & 0xFF); // Address high byte
        bytes_used = 4;
    }
    else if (base_reg == REG_NONE)
    {
        // Direct memory addressing [immediate]: mod=00, r/m=6
        buffer[1] = make_modrm(0, modrm_reg, 6);
        buffer[2] = (uint8_t)(displacement & 0xFF);
        buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
        bytes_used = 4;
    }
    else if (index_reg != REG_NONE)
    {
        // Base+index addressing
        uint8_t rm_code = get_base_index_rm(base_reg, index_reg);

        if (displacement == 0 && base_reg != REG_BP)
        {
            // [base+index] - mod=00
            buffer[1] = make_modrm(0, modrm_reg, rm_code);
            bytes_used = 2;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [base+index+disp8] - mod=01
            buffer[1] = make_modrm(1, modrm_reg, rm_code);
            buffer[2] = (uint8_t)displacement;
            bytes_used = 3;
        }
        else
        {
            // [base+index+disp16] - mod=10
            buffer[1] = make_modrm(2, modrm_reg, rm_code);
            buffer[2] = (uint8_t)(displacement & 0xFF);
            buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
            bytes_used = 4;
        }
    }
    else
    {
        // Single base register addressing
        uint8_t base_code = register_to_rm(base_reg, asm_ctx->mode);

        if (displacement == 0 && base_reg != REG_BP)
        {
            // [reg] - mod=00
            buffer[1] = make_modrm(0, modrm_reg, base_code);
            bytes_used = 2;
        }
        else if (displacement >= -128 && displacement <= 127)
        {
            // [reg+disp8] - mod=01
            buffer[1] = make_modrm(1, modrm_reg, base_code);
            buffer[2] = (uint8_t)displacement;
            bytes_used = 3;
        }
        else
        {
            // [reg+disp16] - mod=10
            buffer[1] = make_modrm(2, modrm_reg, base_code);
            buffer[2] = (uint8_t)(displacement & 0xFF);
            buffer[3] = (uint8_t)((displacement >> 8) & 0xFF);
            bytes_used = 4;
        }
    }

    // Add the immediate value at the end
    if (operand_size == 8)
    {
        buffer[bytes_used] = (uint8_t)value;
        *size = bytes_used + 1;
    }
    else
    {
        buffer[bytes_used] = (uint8_t)(value & 0xFF);
        buffer[bytes_used + 1] = (uint8_t)((value >> 8) & 0xFF);
        *size = bytes_used + 2;
    }

    return true;
}
