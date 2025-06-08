#include "nas.h"

// Helper functions
bool is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

bool is_digit(char c)
{
    return c >= '0' && c <= '9';
}

bool is_alnum(char c)
{
    return is_alpha(c) || is_digit(c);
}

bool is_whitespace(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

bool is_hex_digit(char c)
{
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// Register parsing
register_t parse_register(const char *str)
{
    if (strcasecmp(str, "ax") == 0)
        return REG_AX;
    if (strcasecmp(str, "bx") == 0)
        return REG_BX;
    if (strcasecmp(str, "cx") == 0)
        return REG_CX;
    if (strcasecmp(str, "dx") == 0)
        return REG_DX;
    if (strcasecmp(str, "si") == 0)
        return REG_SI;
    if (strcasecmp(str, "di") == 0)
        return REG_DI;
    if (strcasecmp(str, "bp") == 0)
        return REG_BP;
    if (strcasecmp(str, "sp") == 0)
        return REG_SP;
    if (strcasecmp(str, "cs") == 0)
        return REG_CS;
    if (strcasecmp(str, "ds") == 0)
        return REG_DS;
    if (strcasecmp(str, "es") == 0)
        return REG_ES;    if (strcasecmp(str, "ss") == 0)
        return REG_SS;
    if (strcasecmp(str, "fs") == 0)
        return REG_FS;
    if (strcasecmp(str, "gs") == 0)
        return REG_GS;
    // 32-bit registers
    if (strcasecmp(str, "eax") == 0)
        return REG_EAX;
    if (strcasecmp(str, "ebx") == 0)
        return REG_EBX;
    if (strcasecmp(str, "ecx") == 0)
        return REG_ECX;
    if (strcasecmp(str, "edx") == 0)
        return REG_EDX;
    if (strcasecmp(str, "esi") == 0)
        return REG_ESI;
    if (strcasecmp(str, "edi") == 0)
        return REG_EDI;
    if (strcasecmp(str, "ebp") == 0)
        return REG_EBP;
    if (strcasecmp(str, "esp") == 0)
        return REG_ESP;
    // 8-bit registers
    if (strcasecmp(str, "al") == 0)
        return REG_AL;
    if (strcasecmp(str, "ah") == 0)
        return REG_AH;
    if (strcasecmp(str, "bl") == 0)
        return REG_BL;
    if (strcasecmp(str, "bh") == 0)
        return REG_BH;
    if (strcasecmp(str, "cl") == 0)
        return REG_CL;
    if (strcasecmp(str, "ch") == 0)
        return REG_CH;
    if (strcasecmp(str, "dl") == 0)
        return REG_DL;
    if (strcasecmp(str, "dh") == 0)
        return REG_DH;
    // Control registers
    if (strcasecmp(str, "cr0") == 0)
        return REG_CR0;
    if (strcasecmp(str, "cr1") == 0)
        return REG_CR1;
    if (strcasecmp(str, "cr2") == 0)
        return REG_CR2;
    if (strcasecmp(str, "cr3") == 0)
        return REG_CR3;
    if (strcasecmp(str, "cr4") == 0)
        return REG_CR4;
    if (strcasecmp(str, "cr5") == 0)
        return REG_CR5;
    if (strcasecmp(str, "cr6") == 0)
        return REG_CR6;
    if (strcasecmp(str, "cr7") == 0)
        return REG_CR7;
    return REG_NONE;
}

const char *register_to_string(register_t reg)
{
    switch (reg)
    {
    case REG_AX:
        return "ax";
    case REG_BX:
        return "bx";
    case REG_CX:
        return "cx";
    case REG_DX:
        return "dx";
    case REG_SI:
        return "si";
    case REG_DI:
        return "di";
    case REG_BP:
        return "bp";
    case REG_SP:
        return "sp";
    case REG_CS:
        return "cs";
    case REG_DS:
        return "ds";
    case REG_ES:
        return "es";    case REG_SS:
        return "ss";
    case REG_FS:
        return "fs";
    case REG_GS:
        return "gs";
    // 32-bit registers
    case REG_EAX:
        return "eax";
    case REG_EBX:
        return "ebx";
    case REG_ECX:
        return "ecx";
    case REG_EDX:
        return "edx";
    case REG_ESI:
        return "esi";
    case REG_EDI:
        return "edi";
    case REG_EBP:
        return "ebp";
    case REG_ESP:
        return "esp";
    // 8-bit registers
    case REG_AL:
        return "al";
    case REG_AH:
        return "ah";
    case REG_BL:
        return "bl";
    case REG_BH:
        return "bh";
    case REG_CL:
        return "cl";
    case REG_CH:
        return "ch";
    case REG_DL:
        return "dl";
    case REG_DH:
        return "dh";
    // Control registers
    case REG_CR0:
        return "cr0";
    case REG_CR1:
        return "cr1";
    case REG_CR2:
        return "cr2";
    case REG_CR3:
        return "cr3";
    case REG_CR4:
        return "cr4";
    case REG_CR5:
        return "cr5";
    case REG_CR6:
        return "cr6";
    case REG_CR7:
        return "cr7";
    default:
        return "none";
    }
}

// Lexer functions
lexer_t *lexer_create(const char *input)
{
    lexer_t *lexer = malloc(sizeof(lexer_t));
    if (!lexer)
        return NULL;

    lexer->length = strlen(input);
    lexer->input = malloc(lexer->length + 1);
    if (!lexer->input)
    {
        free(lexer);
        return NULL;
    }

    strcpy(lexer->input, input);
    lexer->position = 0;
    lexer->line = 1;
    lexer->column = 1;

    return lexer;
}

void lexer_destroy(lexer_t *lexer)
{
    if (lexer)
    {
        free(lexer->input);
        free(lexer);
    }
}

static void lexer_skip_whitespace(lexer_t *lexer)
{
    while (lexer->position < lexer->length && is_whitespace(lexer->input[lexer->position]))
    {
        if (lexer->input[lexer->position] == '\t')
        {
            lexer->column += 4; // Assume tab width of 4
        }
        else
        {
            lexer->column++;
        }
        lexer->position++;
    }
}

static void lexer_skip_comment(lexer_t *lexer)
{
    // Skip comments starting with ';' or '//'
    if (lexer->position < lexer->length)
    {
        if (lexer->input[lexer->position] == ';')
        {
            while (lexer->position < lexer->length && lexer->input[lexer->position] != '\n')
            {
                lexer->position++;
            }
            return;
        }
        else if (lexer->input[lexer->position] == '/' &&
                 lexer->position + 1 < lexer->length &&
                 lexer->input[lexer->position + 1] == '/')
        {
            // Skip '//' comment
            lexer->position += 2;
            while (lexer->position < lexer->length && lexer->input[lexer->position] != '\n')
            {
                lexer->position++;
            }
            return;
        }
    }
    if (lexer->position < lexer->length && lexer->input[lexer->position] == ';')
    {
        while (lexer->position < lexer->length && lexer->input[lexer->position] != '\n')
        {
            lexer->position++;
        }
    }
}

static token_t lexer_read_string(lexer_t *lexer)
{
    token_t token = {0};
    token.line = lexer->line;
    token.column = lexer->column;

    size_t start = lexer->position;

    // Handle dot-prefixed identifiers like .text, .data, .bss
    if (lexer->position < lexer->length && lexer->input[lexer->position] == '.')
    {
        lexer->position++;
        lexer->column++;
    }

    while (lexer->position < lexer->length && is_alnum(lexer->input[lexer->position]))
    {
        lexer->position++;
        lexer->column++;
    }

    size_t length = lexer->position - start;
    if (length >= MAX_OPERAND_LENGTH - 1)
    {
        length = MAX_OPERAND_LENGTH - 1;
    }

    strncpy(token.value, &lexer->input[start], length);
    token.value[length] = '\0';
    // Determine token type
    if (parse_register(token.value) != REG_NONE)
    {
        token.type = TOKEN_REGISTER;
    }
    else if (strcasecmp(token.value, "byte") == 0)
    {
        token.type = TOKEN_BYTE;
    }
    else if (strcasecmp(token.value, "word") == 0)
    {
        token.type = TOKEN_WORD;
    }
    else if (strcasecmp(token.value, "dword") == 0)
    {
        token.type = TOKEN_DWORD;
    }
    else
    { // Check if it's a known instruction
        const char *instructions[] = {
            // Data movement
            "mov", "push", "pop", "xchg", "lea",
            // Arithmetic
            "add", "sub", "xor", "cmp", "and", "or", "adc", "sbb", "test",
            "mul", "imul", "div", "idiv", "inc", "dec", "neg", "not",
            // Bit manipulation and shifts
            "shl", "shr", "sal", "sar", "rol", "ror", "rcl", "rcr",
            // Control flow
            "call", "ret", "retf", "retn", "jmp",
            // Conditional jumps
            "je", "jne", "jz", "jnz", "jb", "jnb", "jc", "jnc",
            "ja", "jna", "jae", "jnae", "jbe", "jnbe",
            "jl", "jnl", "jle", "jnle", "jg", "jng", "jge", "jnge",
            "js", "jns", "jo", "jno", "jp", "jnp", "jpe", "jpo",
            // Loop instructions
            "loop", "loope", "loopz", "loopne", "loopnz", "jcxz",
            // String operations
            "movsb", "movsw", "cmpsb", "cmpsw", "scasb", "scasw",
            "lodsb", "lodsw", "stosb", "stosw",
            // String prefixes
            "rep", "repe", "repz", "repne", "repnz",
            // Flag operations
            "clc", "stc", "cmc", "cld", "std", "cli", "sti",
            "lahf", "sahf", "pushf", "popf",
            // Stack operations
            "pusha", "popa", // System instructions
            "int", "int3", "into", "iret", "hlt", "wait", "lock", "nop", "lgdt",
            // BCD operations
            "daa", "das", "aaa", "aas", "aam", "aad",
            // I/O operations
            "in", "out",
            // Convert operations
            "cbw", "cwd"};
        token.type = TOKEN_LABEL; // Default to label
        for (size_t i = 0; i < sizeof(instructions) / sizeof(instructions[0]); i++)
        {
            if (strcasecmp(token.value, instructions[i]) == 0)
            {
                token.type = TOKEN_INSTRUCTION;
                break;
            }
        }
    }

    return token;
}

static token_t lexer_read_number(lexer_t *lexer)
{
    token_t token = {0};
    token.type = TOKEN_IMMEDIATE;
    token.line = lexer->line;
    token.column = lexer->column;

    size_t start = lexer->position;

    // Handle hex numbers (0x prefix)
    if (lexer->position + 1 < lexer->length &&
        lexer->input[lexer->position] == '0' &&
        (lexer->input[lexer->position + 1] == 'x' || lexer->input[lexer->position + 1] == 'X'))
    {
        lexer->position += 2; // Skip 0x
        lexer->column += 2;
        while (lexer->position < lexer->length && is_hex_digit(lexer->input[lexer->position]))
        {
            lexer->position++;
            lexer->column++;
        }
    }
    else
    {
        // Handle decimal numbers
        while (lexer->position < lexer->length && is_digit(lexer->input[lexer->position]))
        {
            lexer->position++;
            lexer->column++;
        }
    }

    size_t length = lexer->position - start;
    if (length >= MAX_OPERAND_LENGTH - 1)
    {
        length = MAX_OPERAND_LENGTH - 1;
    }

    strncpy(token.value, &lexer->input[start], length);
    token.value[length] = '\0';

    return token;
}

static token_t lexer_read_character(lexer_t *lexer)
{
    token_t token = {0};
    token.type = TOKEN_IMMEDIATE;
    token.line = lexer->line;
    token.column = lexer->column;

    lexer->position++; // Skip opening quote
    lexer->column++;

    if (lexer->position < lexer->length)
    {
        char c = lexer->input[lexer->position];
        snprintf(token.value, sizeof(token.value), "%d", (int)c);
        lexer->position++;
        lexer->column++;

        // Skip closing quote if present
        if (lexer->position < lexer->length && lexer->input[lexer->position] == '\'')
        {
            lexer->position++;
            lexer->column++;
        }
    }
    return token;
}

static token_t lexer_read_string_literal(lexer_t *lexer)
{
    token_t token = {0};
    token.type = TOKEN_STRING;
    token.line = lexer->line;
    token.column = lexer->column;

    lexer->position++; // Skip opening quote
    lexer->column++;

    size_t start = lexer->position;
    size_t value_idx = 0;

    while (lexer->position < lexer->length &&
           lexer->input[lexer->position] != '"' &&
           value_idx < MAX_OPERAND_LENGTH - 1)
    {
        char c = lexer->input[lexer->position];

        // Handle escape sequences
        if (c == '\\' && lexer->position + 1 < lexer->length)
        {
            lexer->position++; // Skip backslash
            lexer->column++;

            char next = lexer->input[lexer->position];
            switch (next)
            {
            case 'n':
                c = '\n';
                break;
            case 'r':
                c = '\r';
                break;
            case 't':
                c = '\t';
                break;
            case '\\':
                c = '\\';
                break;
            case '"':
                c = '"';
                break;
            case '0':
                c = '\0';
                break;
            default:
                c = next;
                break; // For any other character, use as-is
            }
        }

        token.value[value_idx++] = c;
        lexer->position++;
        lexer->column++;
    }

    token.value[value_idx] = '\0';

    // Skip closing quote if present
    if (lexer->position < lexer->length && lexer->input[lexer->position] == '"')
    {
        lexer->position++;
        lexer->column++;
    }

    return token;
}

token_t lexer_next_token(lexer_t *lexer)
{
    token_t token = {0};

    lexer_skip_whitespace(lexer);

    if (lexer->position >= lexer->length)
    {
        token.type = TOKEN_EOF;
        return token;
    }

    char current = lexer->input[lexer->position];
    token.line = lexer->line;
    token.column = lexer->column;

    switch (current)
    {
    case '$':
        token.type = TOKEN_LABEL;
        // Check for $$ (section start)
        if (lexer->position + 1 < lexer->length && lexer->input[lexer->position + 1] == '$')
        {
            token.value[0] = '$';
            token.value[1] = '$';
            token.value[2] = '\0';
            lexer->position += 2;
            lexer->column += 2;
        }
        else
        {
            // Single $ (current address)
            token.value[0] = '$';
            token.value[1] = '\0';
            lexer->position++;
            lexer->column++;
        }
        break;
    case '\n':
        token.type = TOKEN_NEWLINE;
        lexer->position++;
        lexer->line++;
        lexer->column = 1;
        break;

    case ';':
        lexer_skip_comment(lexer);
        return lexer_next_token(lexer); // Get next token after comment

    case ',':
        token.type = TOKEN_COMMA;
        token.value[0] = current;
        token.value[1] = '\0';
        lexer->position++;
        lexer->column++;
        break;

    case '+':
        token.type = TOKEN_PLUS;
        token.value[0] = current;
        token.value[1] = '\0';
        lexer->position++;
        lexer->column++;
        break;

    case '-':
        token.type = TOKEN_MINUS;
        token.value[0] = current;
        token.value[1] = '\0';
        lexer->position++;
        lexer->column++;
        break;

    case '*':
        token.type = TOKEN_MULTIPLY;
        token.value[0] = current;
        token.value[1] = '\0';
        lexer->position++;
        lexer->column++;
        break;

    case '/':
        // Handle '//' comments
        if (lexer->position + 1 < lexer->length && lexer->input[lexer->position + 1] == '/')
        {
            lexer_skip_comment(lexer);
            return lexer_next_token(lexer);
        }
        token.type = TOKEN_DIVIDE;
        token.type = TOKEN_DIVIDE;
        token.value[0] = current;
        token.value[1] = '\0';
        lexer->position++;
        lexer->column++;
        break;

    case '(':
        token.type = TOKEN_LPAREN;
        token.value[0] = current;
        token.value[1] = '\0';
        lexer->position++;
        lexer->column++;
        break;

    case ')':
        token.type = TOKEN_RPAREN;
        token.value[0] = current;
        token.value[1] = '\0';
        lexer->position++;
        lexer->column++;
        break;

    case '[':
        token.type = TOKEN_LBRACKET;
        token.value[0] = current;
        token.value[1] = '\0';
        lexer->position++;
        lexer->column++;
        break;
    case ']':
        token.type = TOKEN_RBRACKET;
        token.value[0] = current;
        token.value[1] = '\0';
        lexer->position++;
        lexer->column++;
        break;

    case ':':
        token.type = TOKEN_COLON;
        token.value[0] = current;
        token.value[1] = '\0';
        lexer->position++;
        lexer->column++;
        break;
    case '#':
        // Directive
        token.type = TOKEN_DIRECTIVE;
        size_t start = lexer->position;
        lexer->position++; // Skip '#'

        // Read directive name (letters only)
        while (lexer->position < lexer->length && is_alpha(lexer->input[lexer->position]))
        {
            lexer->position++;
            lexer->column++;
        }

        size_t length = lexer->position - start;
        if (length >= MAX_OPERAND_LENGTH - 1)
        {
            length = MAX_OPERAND_LENGTH - 1;
        }
        strncpy(token.value, &lexer->input[start], length);
        token.value[length] = '\0';
        lexer->column += length;
        break;
    case '\'':
        return lexer_read_character(lexer);
    case '"':
        return lexer_read_string_literal(lexer);

    case '.':
        // Handle dot-prefixed identifiers like .text, .data, .bss
        if (lexer->position + 1 < lexer->length && is_alpha(lexer->input[lexer->position + 1]))
        {
            return lexer_read_string(lexer);
        }
        else
        {
            // Just a standalone dot
            token.type = TOKEN_UNKNOWN;
            token.value[0] = current;
            token.value[1] = '\0';
            lexer->position++;
            lexer->column++;
        }
        break;

    default:
        if (is_alpha(current))
        {
            return lexer_read_string(lexer);
        }
        else if (is_digit(current))
        {
            return lexer_read_number(lexer);
        }
        else
        {
            token.type = TOKEN_UNKNOWN;
            token.value[0] = current;
            token.value[1] = '\0';
            lexer->position++;
            lexer->column++;
        }
        break;
    }
    lexer->current_token = token;
    return token;
}

token_t lexer_peek_token(lexer_t *lexer)
{
    size_t saved_pos = lexer->position;
    int saved_line = lexer->line;
    int saved_col = lexer->column;

    token_t token = lexer_next_token(lexer);

    lexer->position = saved_pos;
    lexer->line = saved_line;
    lexer->column = saved_col;

    return token;
}

bool lexer_is_at_end(lexer_t *lexer)
{
    return lexer->position >= lexer->length;
}
