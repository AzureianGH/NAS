#include "nas.h"
#include <stdarg.h>

assembler_t *assembler_create(void)
{
    assembler_t *asm_ctx = malloc(sizeof(assembler_t));
    if (!asm_ctx)
        return NULL;

    memset(asm_ctx, 0, sizeof(assembler_t));    // Default settings
    asm_ctx->mode = MODE_16BIT;
    asm_ctx->cmdline_mode = MODE_16BIT;
    asm_ctx->cmdline_mode_set = false;
    asm_ctx->directive_mode_set = false;
    asm_ctx->bit_change_allowed = false;
    asm_ctx->format = FORMAT_BIN;
    asm_ctx->origin = 0x0000; // Default origin address
    asm_ctx->current_address = asm_ctx->origin;
    asm_ctx->pass = 1; // Initialize to pass 1

    // Allocate initial code buffer
    asm_ctx->code_capacity = 65536; // 64KB initial capacity
    asm_ctx->code_buffer = malloc(asm_ctx->code_capacity);
    if (!asm_ctx->code_buffer)
    {
        free(asm_ctx);
        return NULL;
    }    // Initialize sections
    asm_ctx->sections = NULL;
    asm_ctx->current_section_ptr = NULL;

    // Create default .text section
    section_t *text_section = section_create(".text", SECTION_TEXT);
    if (!text_section)
    {
        free(asm_ctx->code_buffer);
        free(asm_ctx);
        return NULL;
    }
    section_add(asm_ctx, text_section);
    asm_ctx->current_section_ptr = text_section;

    return asm_ctx;
}

void assembler_destroy(assembler_t *asm_ctx)
{
    if (asm_ctx)
    {
        if (asm_ctx->code_buffer)
        {
            free(asm_ctx->code_buffer);
        }
        if (asm_ctx->symbols)
        {
            symbol_table_destroy(asm_ctx->symbols);
        }
        if (asm_ctx->input && asm_ctx->input != stdin)
        {
            fclose(asm_ctx->input);
        }
        if (asm_ctx->output && asm_ctx->output != stdout)
        {
            fclose(asm_ctx->output);
        }
        if (asm_ctx->sections)
        {
            section_table_destroy(asm_ctx->sections);
        }
        free(asm_ctx);
    }
}

bool assembler_set_mode(assembler_t *asm_ctx, asm_mode_t mode)
{
    asm_ctx->mode = mode;
    return true;
}

bool assembler_set_cmdline_mode(assembler_t *asm_ctx, asm_mode_t mode)
{
    asm_ctx->cmdline_mode = mode;
    asm_ctx->cmdline_mode_set = true;
    asm_ctx->mode = mode; // Also set the current mode
    return true;
}

bool assembler_set_format(assembler_t *asm_ctx, output_format_t format)
{
    asm_ctx->format = format;
    return true;
}

bool assembler_set_origin(assembler_t *asm_ctx, uint32_t origin)
{
    asm_ctx->origin = origin;
    asm_ctx->current_address = origin;
    return true;
}

// Symbol table functions
void symbol_table_dump(assembler_t *asm_ctx)
{
    if (!asm_ctx->verbose)
        return;

    // ANSI color codes
    const char *header_color = "\033[1;36m";    // Bright cyan
    const char *defined_color = "\033[1;32m";   // Bright green
    const char *undefined_color = "\033[1;31m"; // Bright red
    const char *name_color = "\033[1;33m";      // Bright yellow
    const char *address_color = "\033[1;35m";   // Bright magenta
    const char *reset_color = "\033[0m";        // Reset

    printf("%s╔════════════════════════════════════════════════════════════════╗%s\n", header_color, reset_color);
    printf("%s║                        SYMBOL TABLE                           ║%s\n", header_color, reset_color);
    printf("%s╠════╤═══════════════════════╤═══════════╤═══════════════════════╣%s\n", header_color, reset_color);
    printf("%s║ #  │ Symbol Name           │ Address   │ Status                ║%s\n", header_color, reset_color);
    printf("%s╠════╪═══════════════════════╪═══════════╪═══════════════════════╣%s\n", header_color, reset_color);

    symbol_t *current = asm_ctx->symbols;
    int count = 0;
    while (current)
    {
        const char *status_color = current->defined ? defined_color : undefined_color;
        const char *status_text = current->defined ? "DEFINED" : "UNDEFINED";
        
        printf("║%s%3d%s │ %s%-21.21s%s │ %s0x%08X%s │ %s%-21s%s ║\n",
               header_color, ++count, reset_color,
               name_color, current->name, reset_color,
               address_color, current->address, reset_color,
               status_color, status_text, reset_color);
        current = current->next;
    }
    
    if (count == 0)
    {
        printf("║    │ %s(no symbols)%s        │           │                       ║\n", 
               undefined_color, reset_color);
    }
    
    printf("%s╚════╧═══════════════════════╧═══════════╧═══════════════════════╝%s\n", header_color, reset_color);
    printf("%sTotal symbols: %d%s\n\n", header_color, count, reset_color);
}

symbol_t *symbol_lookup(assembler_t *asm_ctx, const char *name)
{
    symbol_t *current = asm_ctx->symbols;
    while (current)
    {
        if (strcmp(current->name, name) == 0)
        {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

bool symbol_define(assembler_t *asm_ctx, const char *name, uint32_t address)
{
    symbol_t *existing = symbol_lookup(asm_ctx, name);
    if (existing)
    {
        if (existing->defined && asm_ctx->pass == 1)
        {
            return false; // Symbol already defined in same pass
        }        // Allow redefinition in subsequent passes for address updates
        existing->address = address;
        existing->defined = true;
        existing->section = asm_ctx->current_section_ptr ? asm_ctx->current_section_ptr->type : SECTION_TEXT;
        return true;
    }

    symbol_t *new_symbol = malloc(sizeof(symbol_t));
    if (!new_symbol)
        return false;

    strncpy(new_symbol->name, name, MAX_LABEL_LENGTH - 1);
    new_symbol->name[MAX_LABEL_LENGTH - 1] = '\0';    new_symbol->address = address;
    new_symbol->defined = true;
    new_symbol->section = asm_ctx->current_section_ptr ? asm_ctx->current_section_ptr->type : SECTION_TEXT;
    new_symbol->next = asm_ctx->symbols;
    asm_ctx->symbols = new_symbol;

    return true;
}

bool symbol_reference(assembler_t *asm_ctx, const char *name)
{
    // Skip creating symbol table entry for special '$' symbol (current address)
    if (strcmp(name, "$") == 0)
    {
        return true;
    }

    symbol_t *existing = symbol_lookup(asm_ctx, name);
    if (existing)
    {
        return true;
    }

    // Create undefined symbol
    symbol_t *new_symbol = malloc(sizeof(symbol_t));
    if (!new_symbol)
        return false;

    strncpy(new_symbol->name, name, MAX_LABEL_LENGTH - 1);
    new_symbol->name[MAX_LABEL_LENGTH - 1] = '\0';    new_symbol->address = 0;
    new_symbol->defined = false;
    new_symbol->section = SECTION_TEXT;  // Default section for undefined symbols
    new_symbol->next = asm_ctx->symbols;
    asm_ctx->symbols = new_symbol;

    return true;
}

void symbol_table_destroy(symbol_t *symbols)
{
    while (symbols)
    {
        symbol_t *next = symbols->next;
        free(symbols);
        symbols = next;
    }
}

bool symbol_check_undefined(assembler_t *asm_ctx)
{
    symbol_t *current = asm_ctx->symbols;
    bool has_undefined = false;

    while (current)
    {
        if (!current->defined)
        {
            assembler_error(asm_ctx, "Undefined symbol: '%s'", current->name);
            has_undefined = true;
        }
        current = current->next;
    }

    if (has_undefined)
    {
        // List all symbols in the symbol table for debugging
        fprintf(stderr, "\nSymbol table contents:\n");
        current = asm_ctx->symbols;
        while (current)
        {
            fprintf(stderr, "  %s -> 0x%04X (defined=%s)\n",
                    current->name, current->address, current->defined ? "yes" : "no");
            current = current->next;
        }
        fprintf(stderr, "\n");
    }

    return !has_undefined; // Return true if no undefined symbols found
}

// Output functions
bool output_write_binary(assembler_t *asm_ctx)
{
    if (!asm_ctx->output)
        return false;

    // For binary output, concatenate all sections in order: .text, .data, .bss
    section_type_t section_order[] = {SECTION_TEXT, SECTION_DATA, SECTION_BSS};
    
    for (int i = 0; i < 3; i++)
    {
        section_type_t type = section_order[i];
        section_t *current = asm_ctx->sections;
        
        while (current)
        {
            if (current->type == type && current->size > 0)
            {
                if (current->data)
                {
                    // Write actual data for .text and .data sections
                    size_t written = fwrite(current->data, 1, current->size, asm_ctx->output);
                    if (written != current->size)
                        return false;
                }
                else if (current->type == SECTION_BSS)
                {
                    // Write zeros for .bss section
                    for (size_t j = 0; j < current->size; j++)
                    {
                        if (fputc(0, asm_ctx->output) == EOF)
                            return false;
                    }
                }
            }
            current = current->next;
        }
    }

    return true;
}

bool output_write_hex(assembler_t *asm_ctx)
{
    if (!asm_ctx->output)
        return false;

    // For hex output, concatenate all sections in order: .text, .data, .bss
    section_type_t section_order[] = {SECTION_TEXT, SECTION_DATA, SECTION_BSS};
    size_t bytes_written = 0;
    
    for (int i = 0; i < 3; i++)
    {
        section_type_t type = section_order[i];
        section_t *current = asm_ctx->sections;
        
        while (current)
        {
            if (current->type == type && current->size > 0)
            {
                if (current->data)
                {
                    // Write actual data for .text and .data sections
                    for (size_t j = 0; j < current->size; j++)
                    {
                        fprintf(asm_ctx->output, "%02X ", current->data[j]);
                        bytes_written++;
                        if (bytes_written % 16 == 0)
                        {
                            fprintf(asm_ctx->output, "\n");
                        }
                    }
                }
                else if (current->type == SECTION_BSS)
                {
                    // Write zeros for .bss section
                    for (size_t j = 0; j < current->size; j++)
                    {
                        fprintf(asm_ctx->output, "00 ");
                        bytes_written++;
                        if (bytes_written % 16 == 0)
                        {
                            fprintf(asm_ctx->output, "\n");
                        }
                    }
                }
            }
            current = current->next;
        }
    }

    if (bytes_written % 16 != 0)
    {
        fprintf(asm_ctx->output, "\n");
    }

    return true;
}

// ELF32 structures for generating Linux-compatible executables
typedef struct {
    uint8_t e_ident[16];     // ELF identification
    uint16_t e_type;         // Object file type
    uint16_t e_machine;      // Architecture
    uint32_t e_version;      // Object file version
    uint32_t e_entry;        // Entry point virtual address
    uint32_t e_phoff;        // Program header table file offset
    uint32_t e_shoff;        // Section header table file offset
    uint32_t e_flags;        // Processor-specific flags
    uint16_t e_ehsize;       // ELF header size in bytes
    uint16_t e_phentsize;    // Program header table entry size
    uint16_t e_phnum;        // Program header table entry count
    uint16_t e_shentsize;    // Section header table entry size
    uint16_t e_shnum;        // Section header table entry count
    uint16_t e_shstrndx;     // Section header string table index
} __attribute__((packed)) Elf32_Ehdr;

typedef struct {
    uint32_t p_type;         // Segment type
    uint32_t p_offset;       // Segment file offset
    uint32_t p_vaddr;        // Segment virtual address
    uint32_t p_paddr;        // Segment physical address
    uint32_t p_filesz;       // Segment size in file
    uint32_t p_memsz;        // Segment size in memory
    uint32_t p_flags;        // Segment flags
    uint32_t p_align;        // Segment alignment
} __attribute__((packed)) Elf32_Phdr;

// ELF constants
#define EI_MAG0     0
#define EI_MAG1     1
#define EI_MAG2     2
#define EI_MAG3     3
#define EI_CLASS    4
#define EI_DATA     5
#define EI_VERSION  6
#define EI_OSABI    7
#define EI_PAD      8

#define ELFMAG0     0x7f
#define ELFMAG1     'E'
#define ELFMAG2     'L'
#define ELFMAG3     'F'
#define ELFCLASS32  1
#define ELFDATA2LSB 1
#define EV_CURRENT  1
#define ELFOSABI_SYSV 0

#define ET_EXEC     2
#define EM_386      3
#define PT_LOAD     1
#define PF_X        1
#define PF_W        2
#define PF_R        4

bool output_write_elf(assembler_t *asm_ctx)
{
    if (!asm_ctx->output)
        return false;

    // ELF files are only supported for 32-bit mode
    if (asm_ctx->mode != MODE_32BIT)
        return false;

    // Calculate addresses and sizes
    const uint32_t BASE_ADDR = 0x08048000;  // Standard Linux base address
    const uint32_t ELF_HEADER_SIZE = sizeof(Elf32_Ehdr);
    const uint32_t PROGRAM_HEADER_SIZE = sizeof(Elf32_Phdr);
    
    // Count how many sections we have
    int section_count = 0;
    section_t *current = asm_ctx->sections;
    while (current)
    {
        section_count++;
        current = current->next;
    }
    
    const uint32_t HEADERS_SIZE = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE * section_count;
    
    // Look for _start symbol to set entry point
    symbol_t *start_symbol = symbol_lookup(asm_ctx, "_start");
    section_t *text_section = section_find(asm_ctx, ".text");
    uint32_t entry_offset = 0;
    
    if (start_symbol && text_section)
    {
        entry_offset = text_section->address + (start_symbol->address - text_section->address);
    }
    else if (text_section)
    {
        entry_offset = text_section->address;
    }
    
    uint32_t entry_point = BASE_ADDR + HEADERS_SIZE + entry_offset;

    // Create ELF header
    Elf32_Ehdr ehdr = {0};
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS32;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
    
    ehdr.e_type = ET_EXEC;
    ehdr.e_machine = EM_386;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_entry = entry_point;
    ehdr.e_phoff = ELF_HEADER_SIZE;
    ehdr.e_shoff = 0;  // No section headers for now
    ehdr.e_flags = 0;
    ehdr.e_ehsize = ELF_HEADER_SIZE;
    ehdr.e_phentsize = PROGRAM_HEADER_SIZE;
    ehdr.e_phnum = section_count;  // One program header per section
    ehdr.e_shentsize = 0;
    ehdr.e_shnum = 0;
    ehdr.e_shstrndx = 0;

    // Write ELF header
    if (fwrite(&ehdr, sizeof(Elf32_Ehdr), 1, asm_ctx->output) != 1)
        return false;

    // Write program headers for each section
    uint32_t file_offset = HEADERS_SIZE;
    current = asm_ctx->sections;
    
    // Process sections in order: .text, .data, .bss
    section_type_t section_order[] = {SECTION_TEXT, SECTION_DATA, SECTION_BSS};
    
    for (int i = 0; i < 3; i++)
    {
        section_type_t type = section_order[i];
        current = asm_ctx->sections;
        
        while (current)
        {
            if (current->type == type && current->size > 0)
            {
                Elf32_Phdr phdr = {0};
                phdr.p_type = PT_LOAD;
                phdr.p_offset = file_offset;
                phdr.p_vaddr = BASE_ADDR + file_offset;
                phdr.p_paddr = phdr.p_vaddr;
                
                if (current->type == SECTION_BSS)
                {
                    // BSS section: no data in file, but occupies memory
                    phdr.p_filesz = 0;
                    phdr.p_memsz = current->size;
                    phdr.p_flags = PF_R | PF_W;  // Read and write permissions
                }
                else
                {
                    // Text/Data sections: have data in file and memory
                    phdr.p_filesz = current->size;
                    phdr.p_memsz = current->size;
                    
                    if (current->type == SECTION_TEXT)
                        phdr.p_flags = PF_R | PF_X;  // Read and execute permissions
                    else
                        phdr.p_flags = PF_R | PF_W;  // Read and write permissions
                        
                    file_offset += current->size;
                }
                
                phdr.p_align = 0x1000;  // Page alignment

                // Write program header
                if (fwrite(&phdr, sizeof(Elf32_Phdr), 1, asm_ctx->output) != 1)
                    return false;
            }
            current = current->next;
        }
    }

    // Write section data (skip BSS as it has no file data)
    for (int i = 0; i < 2; i++)  // Only TEXT and DATA, not BSS
    {
        section_type_t type = section_order[i];
        current = asm_ctx->sections;
        
        while (current)
        {
            if (current->type == type && current->size > 0 && current->data)
            {
                if (fwrite(current->data, 1, current->size, asm_ctx->output) != current->size)
                    return false;
            }
            current = current->next;
        }
    }

    return true;
}

// Error handling
void assembler_error(assembler_t *asm_ctx, const char *format, ...)
{
    asm_ctx->error_occurred = true;
    va_list args;
    va_start(args, format);
    fprintf(stderr, "Error: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void assembler_warning(assembler_t *asm_ctx, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    fprintf(stderr, "Warning: ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

static char *read_file_content(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
        return NULL;

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = malloc(length + 1);
    if (!content)
    {
        fclose(file);
        return NULL;
    }

    fread(content, 1, length, file);
    content[length] = '\0';
    fclose(file);

    return content;
}

static bool assembler_pass(assembler_t *asm_ctx, const char *input_content, int pass)
{
    // Create lexer and parser for this pass
    lexer_t *lexer = lexer_create(input_content);
    if (!lexer)
    {
        assembler_error(asm_ctx, "Failed to create lexer for pass %d", pass);
        return false;
    }

    parser_t *parser = parser_create(lexer, asm_ctx);
    if (!parser)
    {
        assembler_error(asm_ctx, "Failed to create parser for pass %d", pass);
        lexer_destroy(lexer);
        return false;
    }    asm_ctx->pass = pass;
    bool success = true;
    instruction_t instruction;    // Reset address tracking for each pass
    asm_ctx->current_address = asm_ctx->origin;
    
    // Reset section sizes for each pass
    section_t *current_section = asm_ctx->sections;
    while (current_section)
    {
        current_section->size = 0;
        current_section = current_section->next;
    }
    
    if (pass >= 2)
    {
        codegen_reset(asm_ctx); // Reset code buffer for all code generation passes
    }
    if (asm_ctx->verbose)
    {
        printf("Starting pass %d...\n", pass);
        if (pass >= 2)
        {
            symbol_table_dump(asm_ctx);
        }
    }

    // Process all lines
    while (true)
    {
        bool parsed = parser_parse_line(parser, &instruction);
        if (!parsed)
        {
            break; // no more lines or reached EOF, or parsing error occurred
        }

        // Check if an error occurred during parsing
        if (asm_ctx->error_occurred)
        {
            success = false;
            break;
        }        // Process instructions - calculate sizes in all passes, generate code in pass 2+
        if (instruction.mnemonic[0] != '\0')
        {
            uint8_t dummy_buffer[16];
            size_t current_size = 0;
            uint32_t instruction_address = asm_ctx->current_address;
            
            // Calculate instruction size
            if (!generate_opcode(&instruction, dummy_buffer, &current_size, asm_ctx))
            {
                assembler_error(asm_ctx, "Failed to generate opcode for instruction '%s' at line %d",
                                instruction.mnemonic, instruction.line);
                success = false;
                break;
            }

            if (pass == 1)
            {
                // Pass 1: Just advance address based on calculated size
                asm_ctx->current_address += current_size;
            }
            else
            {
                // Pass 2+: Generate actual code and check for size consistency
                uint32_t expected_address_after = asm_ctx->current_address + current_size;
                
                // Generate actual code (this also advances the address)
                if (!codegen_generate_instruction(asm_ctx, &instruction))
                {
                    assembler_error(asm_ctx, "Failed to generate code for instruction '%s' at line %d",
                                    instruction.mnemonic, instruction.line);
                    success = false;
                    break;
                }
                
                // Check if the actual final address matches our expectation
                if (asm_ctx->current_address != expected_address_after)
                {
                    if (asm_ctx->verbose)
                    {
                        printf("DEBUG: Address mismatch for instruction '%s' at 0x%04X: expected=0x%04X, actual=0x%04X\n",
                               instruction.mnemonic, instruction_address, expected_address_after, asm_ctx->current_address);
                    }
                    asm_ctx->sizes_changed = true;
                }
            }
        }
    }    // Cleanup
    parser_destroy(parser);
    lexer_destroy(lexer);

    // Calculate section addresses after processing
    section_calculate_addresses(asm_ctx);

    if (asm_ctx->verbose)
    {
        printf("Pass %d completed. Current address: 0x%x\n", pass, asm_ctx->current_address);
        
        // Print section information
        section_t *current = asm_ctx->sections;
        while (current)
        {
            printf("  Section %s: address=0x%x, size=%u\n", 
                   current->name, current->address, current->size);
            current = current->next;
        }
    }

    return success;
}
bool assembler_assemble_file(assembler_t *asm_ctx, const char *input_file, const char *output_file)
{
    // Read input file
    char *input_content = read_file_content(input_file);
    if (!input_content)
    {
        assembler_error(asm_ctx, "Failed to read input file: %s", input_file);
        return false;
    }

    // Open output file
    asm_ctx->output = fopen(output_file, "wb");
    if (!asm_ctx->output)
    {
        assembler_error(asm_ctx, "Failed to open output file: %s", output_file);
        free(input_content);
        return false;
    }    bool success = true;
    const int max_passes = 10; // Limit to prevent infinite loops
    int pass = 1;
    bool had_size_changes = false;

    // Iterative multi-pass assembly: continue until instruction sizes stabilize
    do {
        asm_ctx->sizes_changed = false;
        
        if (asm_ctx->verbose)
        {
            printf("Starting pass %d...\n", pass);
        }

        if (!assembler_pass(asm_ctx, input_content, pass))
        {
            success = false;
            goto cleanup;
        }

        if (asm_ctx->verbose)
        {
            printf("Pass %d completed. Sizes changed: %s\n", 
                   pass, asm_ctx->sizes_changed ? "yes" : "no");
        }

        had_size_changes = asm_ctx->sizes_changed;
        pass++;
        
        // Check for max passes limit
        if (pass > max_passes)
        {
            if (had_size_changes)
            {
                assembler_error(asm_ctx, "Assembly failed to converge after %d passes", max_passes);
                success = false;
                goto cleanup;
            }
            break;
        }
        
        // Continue if: this is the first pass through pass 2, OR the previous pass had size changes
    } while (pass == 2 || had_size_changes);

    // Check for undefined symbols and report errors
    if (!symbol_check_undefined(asm_ctx))
    {
        success = false;
        goto cleanup;
    }// Write output
    if (success)
    {
        switch (asm_ctx->format)
        {
        case FORMAT_BIN:
            success = output_write_binary(asm_ctx);
            break;
        case FORMAT_HEX:
            success = output_write_hex(asm_ctx);
            break;
        case FORMAT_ELF:
            success = output_write_elf(asm_ctx);
            break;
        default:
            success = false;
            break;
        }
    }

cleanup:
    free(input_content);
    fclose(asm_ctx->output);
    asm_ctx->output = NULL;    if (success && asm_ctx->verbose)
    {
        size_t total_size = section_get_total_size(asm_ctx);
        printf("Assembly completed successfully. Total output size: %zu bytes\n", total_size);
    }

    return success;
}

// Section management functions
section_t *section_create(const char *name, section_type_t type)
{
    section_t *section = malloc(sizeof(section_t));
    if (!section)
        return NULL;

    strncpy(section->name, name, MAX_LABEL_LENGTH - 1);
    section->name[MAX_LABEL_LENGTH - 1] = '\0';
    section->type = type;
    section->address = 0;
    section->size = 0;
    section->data = NULL;
    section->data_capacity = 0;
    section->next = NULL;

    return section;
}

bool section_add(assembler_t *asm_ctx, section_t *section)
{
    if (!asm_ctx || !section)
        return false;

    // Check if section already exists
    if (section_find(asm_ctx, section->name))
        return false;    // Add to linked list
    section->next = asm_ctx->sections;
    asm_ctx->sections = section;

    return true;
}

section_t *section_find(assembler_t *asm_ctx, const char *name)
{
    if (!asm_ctx || !name)
        return NULL;

    section_t *current = asm_ctx->sections;
    while (current)
    {
        if (strcmp(current->name, name) == 0)
            return current;
        current = current->next;
    }
    return NULL;
}

bool section_switch(assembler_t *asm_ctx, const char *name)
{
    if (!asm_ctx || !name)
        return false;

    section_t *section = section_find(asm_ctx, name);    if (!section)
        return false;

    asm_ctx->current_section_ptr = section;
    
    // Update current address to the section's current position
    asm_ctx->current_address = section->address + section->size;
    
    return true;
}

section_t *section_get_current(assembler_t *asm_ctx)
{
    return asm_ctx ? asm_ctx->current_section_ptr : NULL;
}

void section_table_destroy(section_t *sections)
{
    while (sections)
    {
        section_t *next = sections->next;
        if (sections->data)
            free(sections->data);
        free(sections);
        sections = next;
    }
}

// Section address calculation functions
void section_calculate_addresses(assembler_t *asm_ctx)
{
    if (!asm_ctx)
        return;

    uint32_t current_addr = asm_ctx->origin;
    
    // Calculate addresses for each section type in order: .text, .data, .bss
    section_type_t section_order[] = {SECTION_TEXT, SECTION_DATA, SECTION_BSS};
    
    for (int i = 0; i < 3; i++)
    {
        section_type_t type = section_order[i];
        section_t *current = asm_ctx->sections;
        
        while (current)
        {
            if (current->type == type)
            {
                current->address = current_addr;
                current_addr += current->size;
                
                // Align to 4-byte boundary for next section
                if (current_addr % 4 != 0)
                    current_addr = (current_addr + 3) & ~3;
            }
            current = current->next;
        }
    }
}

size_t section_get_total_size(assembler_t *asm_ctx)
{
    if (!asm_ctx)
        return 0;
        
    size_t total = 0;
    section_t *current = asm_ctx->sections;
    
    while (current)
    {
        total += current->size;
        current = current->next;
    }
    
    return total;
}
