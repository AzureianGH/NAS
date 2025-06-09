#ifndef NAS_H
#define NAS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// Common constants
#define MAX_LINE_LENGTH 1024
#define MAX_LABEL_LENGTH 256
#define MAX_OPERAND_LENGTH 128
#define MAX_TOKENS_PER_LINE 16

// Assembly modes
typedef enum
{
    MODE_16BIT = 16,
    MODE_32BIT = 32
} asm_mode_t;

// Output formats
typedef enum
{
    FORMAT_BIN,
    FORMAT_HEX,
    FORMAT_ELF
} output_format_t;

// Token types
typedef enum
{
    TOKEN_UNKNOWN,
    TOKEN_INSTRUCTION,
    TOKEN_REGISTER,
    TOKEN_IMMEDIATE,
    TOKEN_MEMORY,
    TOKEN_LABEL,
    TOKEN_DIRECTIVE,
    TOKEN_COMMENT,
    TOKEN_COMMA,
    TOKEN_PLUS,
    TOKEN_MINUS,
    TOKEN_MULTIPLY,
    TOKEN_DIVIDE,
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_LBRACKET,
    TOKEN_RBRACKET,
    TOKEN_COLON,
    TOKEN_BYTE,
    TOKEN_WORD,
    TOKEN_DWORD,
    TOKEN_STRING,
    TOKEN_NEWLINE,
    TOKEN_EOF
} token_type_t;

// Register enumeration
typedef enum
{
    REG_NONE = -1,
    // 16-bit registers
    REG_AX,
    REG_BX,
    REG_CX,
    REG_DX,
    REG_SI,
    REG_DI,
    REG_BP,
    REG_SP,    REG_CS,
    REG_DS,
    REG_ES,
    REG_SS,
    REG_FS,
    REG_GS,
    // 32-bit registers
    REG_EAX,
    REG_EBX,
    REG_ECX,
    REG_EDX,
    REG_ESI,
    REG_EDI,
    REG_EBP,
    REG_ESP,    // 8-bit registers
    REG_AL,
    REG_AH,
    REG_BL,
    REG_BH,
    REG_CL,
    REG_CH,
    REG_DL,
    REG_DH,
    // Control registers
    REG_CR0,
    REG_CR1,
    REG_CR2,
    REG_CR3,
    REG_CR4,
    REG_CR5,
    REG_CR6,
    REG_CR7
} register_t;

// Operand types
typedef enum
{
    OPERAND_NONE,
    OPERAND_REGISTER,
    OPERAND_IMMEDIATE,
    OPERAND_MEMORY,
    OPERAND_FARPTR, // Far pointer (segment:offset)
    OPERAND_LABEL
} operand_type_t;

// Token structure
typedef struct
{
    token_type_t type;
    char value[MAX_OPERAND_LENGTH];
    int line;
    int column;
} token_t;

// Operand structure
typedef struct
{
    operand_type_t type;
    union
    {
        register_t reg;
        int32_t immediate;
        struct
        {
            register_t base;
            register_t index;
            int32_t displacement;
            int scale;
            register_t segment;           // Segment override register (REG_NONE if no override)
            bool has_label;               // Indicates label-based memory operand
            char label[MAX_LABEL_LENGTH]; // Label for direct memory addressing
        } memory;        struct
        { // Far pointer value
            uint16_t segment;
            uint16_t offset;
            bool has_label_offset;                 // True if offset is a label
            char offset_label[MAX_LABEL_LENGTH];   // Label name for offset
        } far_ptr;
        char label[MAX_LABEL_LENGTH];
    } value;
    int size; // 8, 16, 32 bits
} operand_t;

// Instruction structure
typedef struct
{
    char mnemonic[16];
    operand_t operands[3];
    int operand_count;
    int line;
} instruction_t;

// Section types for ELF
typedef enum
{
    SECTION_TEXT,    // .text - executable code
    SECTION_DATA,    // .data - initialized data  
    SECTION_BSS      // .bss - uninitialized data
} section_type_t;

// Section information
typedef struct section
{
    section_type_t type;
    char name[MAX_LABEL_LENGTH];
    uint32_t address;
    uint32_t size;
    uint8_t *data;
    size_t data_capacity;
    struct section *next;
} section_t;

// Symbol table entry
typedef struct symbol
{
    char name[MAX_LABEL_LENGTH];
    uint32_t address;
    bool defined;
    bool global;     // Symbol is global (exported for linking)
    bool external;   // Symbol is external (imported from another object)
    section_type_t section; // Which section this symbol belongs to
    struct symbol *next;
} symbol_t;

// Assembler context
typedef struct
{
    FILE *input;
    FILE *output;
    char *input_filename;
    char *output_filename;
    asm_mode_t mode;
    asm_mode_t cmdline_mode; // Mode set via command line flags
    bool cmdline_mode_set;   // Whether command line mode was explicitly set
    bool directive_mode_set; // Whether #width directive was used
    bool bit_change_allowed; // Whether -bc flag was specified to allow bit width changes
    output_format_t format;
    uint32_t origin;
    uint32_t current_address;    
    symbol_t *symbols;
    uint8_t *code_buffer;
    size_t code_size;
    size_t code_capacity;
    bool verbose;
    bool error_occurred;
    int pass; // Current assembler pass
    bool sizes_changed; // Track if instruction sizes changed during pass
    // Section support
    section_t *sections;
    section_type_t current_section;
    section_t *current_section_ptr;
} assembler_t;

// Forward declarations
#include "lexer.h"
#include "parser.h"
#include "instruction_set.h"
#include "codegen.h"
#include "assembler.h"

#ifdef __linux__
bool strcasecmp(const char *s1, const char *s2);
#endif

#endif // NAS_H
