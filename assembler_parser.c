#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// ...existing code...

// Add this function to parse far jump instructions
int parse_far_jump(const char* instruction, uint8_t* output, int* output_len) {
    if (strncmp(instruction, "jmp", 3) != 0) {
        return 0; // Not a jump instruction
    }
    
    const char* operand = instruction + 3;
    while (*operand == ' ' || *operand == '\t') operand++; // Skip whitespace
    
    // Look for segment:offset pattern
    char* colon_pos = strchr(operand, ':');
    if (colon_pos == NULL) {
        return 0; // Not a far jump
    }
    
    // Parse segment (before colon)
    uint16_t segment = 0;
    if (strncmp(operand, "0x", 2) == 0) {
        segment = (uint16_t)strtol(operand, NULL, 16);
    } else {
        segment = (uint16_t)strtol(operand, NULL, 10);
    }
    
    // Parse offset (after colon)
    const char* offset_str = colon_pos + 1;
    uint32_t offset = 0;
    
    // Handle label references
    if (isalpha(*offset_str) || *offset_str == '_') {
        // This is a label - you'll need to resolve it in your symbol table
        offset = resolve_label(offset_str);
    } else if (strncmp(offset_str, "0x", 2) == 0) {
        offset = (uint32_t)strtol(offset_str, NULL, 16);
    } else {
        offset = (uint32_t)strtol(offset_str, NULL, 10);
    }
    
    // Generate far jump opcode (0xEA + 4-byte offset + 2-byte segment)
    output[0] = 0xEA;                    // Far jump opcode
    output[1] = offset & 0xFF;           // Offset low byte
    output[2] = (offset >> 8) & 0xFF;    // Offset byte 2
    output[3] = (offset >> 16) & 0xFF;   // Offset byte 3
    output[4] = (offset >> 24) & 0xFF;   // Offset high byte
    output[5] = segment & 0xFF;          // Segment low byte
    output[6] = (segment >> 8) & 0xFF;   // Segment high byte
    
    *output_len = 7;
    return 1; // Successfully parsed
}

// Add this to your main instruction parsing function
int parse_instruction(const char* line, uint8_t* output, int* output_len) {
    // ...existing code...
    
    // Try to parse as far jump first
    if (parse_far_jump(line, output, output_len)) {
        return 1;
    }
    
    // ...existing code for other instructions...
}

// ...existing code...