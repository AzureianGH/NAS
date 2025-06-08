#include "nas.h"
#include <ctype.h>

#ifdef __linux__
bool strcasecmp(const char *s1, const char *s2)
{
    while (*s1 && *s2 && tolower((unsigned char)*s1) == tolower((unsigned char)*s2))
    {
        s1++;
        s2++;
    }
    return tolower((unsigned char)*s1) - tolower((unsigned char)*s2);
}
#endif

bool codegen_ensure_capacity(assembler_t *asm_ctx, size_t additional_size)
{
    // Get current section
    section_t *current_section = section_get_current(asm_ctx);
    if (!current_section)
    {
        // Fallback to global code buffer if no current section
        if (asm_ctx->code_size + additional_size > asm_ctx->code_capacity)
        {
            size_t new_capacity = asm_ctx->code_capacity * 2;
            if (new_capacity < asm_ctx->code_size + additional_size)
            {
                new_capacity = asm_ctx->code_size + additional_size + 1024;
            }

            uint8_t *new_buffer = realloc(asm_ctx->code_buffer, new_capacity);
            if (!new_buffer)
            {
                return false;
            }

            asm_ctx->code_buffer = new_buffer;
            asm_ctx->code_capacity = new_capacity;
        }
        return true;
    }

    // Ensure current section has enough capacity
    if (current_section->size + additional_size > current_section->data_capacity)
    {
        size_t new_capacity = current_section->data_capacity * 2;
        if (new_capacity < current_section->size + additional_size)
        {
            new_capacity = current_section->size + additional_size + 1024;
        }
        if (new_capacity == 0)
        {
            new_capacity = 1024;
        }

        uint8_t *new_buffer = realloc(current_section->data, new_capacity);
        if (!new_buffer)
        {
            return false;
        }

        current_section->data = new_buffer;
        current_section->data_capacity = new_capacity;
    }

    return true;
}

bool codegen_emit_byte(assembler_t *asm_ctx, uint8_t byte)
{    
    // Always advance address
    asm_ctx->current_address++;

    // Only emit on pass 2 and beyond
    if (asm_ctx->pass >= 2)
    {
        section_t *current_section = section_get_current(asm_ctx);
        
        if (current_section)
        {
            // Emit to current section
            if (!codegen_ensure_capacity(asm_ctx, 1))
            {
                return false;
            }
            current_section->data[current_section->size++] = byte;
        }
        else
        {
            // Fallback to global code buffer
            if (!codegen_ensure_capacity(asm_ctx, 1))
            {
                return false;
            }
            asm_ctx->code_buffer[asm_ctx->code_size++] = byte;
        }
    }

    return true;
}

bool codegen_emit_word(assembler_t *asm_ctx, uint16_t word)
{    
    // Always advance address
    asm_ctx->current_address += 2;

    // Only emit on pass 2 and beyond
    if (asm_ctx->pass >= 2)
    {
        section_t *current_section = section_get_current(asm_ctx);
        
        if (current_section)
        {
            // Emit to current section
            if (!codegen_ensure_capacity(asm_ctx, 2))
            {
                return false;
            }
            // Little-endian encoding
            current_section->data[current_section->size++] = (uint8_t)(word & 0xFF);
            current_section->data[current_section->size++] = (uint8_t)((word >> 8) & 0xFF);
        }
        else
        {
            // Fallback to global code buffer
            if (!codegen_ensure_capacity(asm_ctx, 2))
            {
                return false;
            }
            // Little-endian encoding
            asm_ctx->code_buffer[asm_ctx->code_size++] = (uint8_t)(word & 0xFF);
            asm_ctx->code_buffer[asm_ctx->code_size++] = (uint8_t)((word >> 8) & 0xFF);
        }
    }

    return true;
}

bool codegen_emit_dword(assembler_t *asm_ctx, uint32_t dword)
{    
    // Always advance address
    asm_ctx->current_address += 4;

    // Only emit on pass 2 and beyond
    if (asm_ctx->pass >= 2)
    {
        section_t *current_section = section_get_current(asm_ctx);
        
        if (current_section)
        {
            // Emit to current section
            if (!codegen_ensure_capacity(asm_ctx, 4))
            {
                return false;
            }
            // Little-endian encoding
            current_section->data[current_section->size++] = (uint8_t)(dword & 0xFF);
            current_section->data[current_section->size++] = (uint8_t)((dword >> 8) & 0xFF);
            current_section->data[current_section->size++] = (uint8_t)((dword >> 16) & 0xFF);
            current_section->data[current_section->size++] = (uint8_t)((dword >> 24) & 0xFF);
        }
        else
        {
            // Fallback to global code buffer
            if (!codegen_ensure_capacity(asm_ctx, 4))
            {
                return false;
            }
            // Little-endian encoding
            asm_ctx->code_buffer[asm_ctx->code_size++] = (uint8_t)(dword & 0xFF);
            asm_ctx->code_buffer[asm_ctx->code_size++] = (uint8_t)((dword >> 8) & 0xFF);
            asm_ctx->code_buffer[asm_ctx->code_size++] = (uint8_t)((dword >> 16) & 0xFF);
            asm_ctx->code_buffer[asm_ctx->code_size++] = (uint8_t)((dword >> 24) & 0xFF);
        }
    }

    return true;
}

bool codegen_emit_bytes(assembler_t *asm_ctx, const uint8_t *bytes, size_t count)
{    
    // Always advance address
    asm_ctx->current_address += count;

    // Only emit on pass 2 and beyond
    if (asm_ctx->pass >= 2)
    {
        section_t *current_section = section_get_current(asm_ctx);
        
        if (current_section)
        {
            // Emit to current section
            if (!codegen_ensure_capacity(asm_ctx, count))
            {
                return false;
            }
            for (size_t i = 0; i < count; i++)
            {
                current_section->data[current_section->size++] = bytes[i];
            }
        }
        else
        {
            // Fallback to global code buffer
            if (!codegen_ensure_capacity(asm_ctx, count))
            {
                return false;
            }
            for (size_t i = 0; i < count; i++)
            {
                asm_ctx->code_buffer[asm_ctx->code_size++] = bytes[i];
            }
        }
    }

    return true;
}

uint32_t codegen_get_current_address(assembler_t *asm_ctx)
{
    return asm_ctx->current_address;
}

void codegen_set_address(assembler_t *asm_ctx, uint32_t address)
{
    asm_ctx->current_address = address;
}

bool codegen_align(assembler_t *asm_ctx, int alignment)
{
    uint32_t current = codegen_get_current_address(asm_ctx);
    uint32_t aligned = (current + alignment - 1) & ~(alignment - 1);
    uint32_t padding = aligned - current;

    for (uint32_t i = 0; i < padding; i++)
    {
        if (!codegen_emit_byte(asm_ctx, 0))
        {
            return false;
        }
    }

    return true;
}

void codegen_reset(assembler_t *asm_ctx)
{
    asm_ctx->code_size = 0;
    asm_ctx->current_address = asm_ctx->origin;
}

bool codegen_generate_instruction(assembler_t *asm_ctx, const instruction_t *instr)
{
    uint8_t opcode_buffer[16]; // Maximum instruction size
    size_t opcode_size = 0;

    // Special-case: jmp/call to '$' (current address)
    const instruction_def_t *def = find_instruction(instr->mnemonic);
    if ((def->encoding == ENC_JMP_REL || def->encoding == ENC_CALL_REL) &&
        instr->operand_count == 1 && instr->operands[0].type == OPERAND_LABEL &&
        strcmp(instr->operands[0].value.label, "$") == 0)
    {
        // Emit short jump/call to current instruction address (2-byte instruction, so displacement = -2)
        codegen_emit_byte(asm_ctx, def->opcode);
        codegen_emit_byte(asm_ctx, (uint8_t)0xFE); // -2 in two's complement
        return true;
    }
    // Handle special case for push with character literal
    if (strcasecmp(instr->mnemonic, "push") == 0 &&
        instr->operand_count == 1 &&
        instr->operands[0].type == OPERAND_IMMEDIATE)
    {

        instruction_t push_instr = *instr;
        push_instr.operands[0].type = OPERAND_IMMEDIATE;

        if (!generate_opcode(&push_instr, opcode_buffer, &opcode_size, asm_ctx))
        {
            return false;
        }
    }
    else
    { // Generate opcode for the instruction
        if (!generate_opcode(instr, opcode_buffer, &opcode_size, asm_ctx))
        {
            if (asm_ctx->verbose)
            {
                fprintf(stderr, "Error: Failed to generate opcode for instruction '%s' at line %d\n",
                        instr->mnemonic, instr->line);
            }
            return false;
        }
    }

    // Emit the generated bytes
    return codegen_emit_bytes(asm_ctx, opcode_buffer, opcode_size);
}
