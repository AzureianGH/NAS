#include "nas.h"
#include <stdarg.h>
#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#define usleep(x) Sleep((x)/1000)
#else
#include <unistd.h>
#define usleep(x)
#endif

assembler_t *assembler_create(void)
{
    assembler_t *asm_ctx = malloc(sizeof(assembler_t));
    if (!asm_ctx)
        return NULL;

    memset(asm_ctx, 0, sizeof(assembler_t)); // Default settings
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
    } // Initialize sections
    asm_ctx->sections = NULL;
    asm_ctx->current_section_ptr = NULL;

    // Initialize relocations
    asm_ctx->relocations = NULL;

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
        if (asm_ctx->relocations)
        {
            relocation_table_destroy(asm_ctx->relocations);
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

// Progress display functions
static void clear_line() {
    printf("\r\033[K");  // Clear line
}

static void show_pass_progress(const char* phase, int current_pass, int total_passes, const char* action) {
    clear_line();
    int progress = (total_passes > 0) ? (int)((current_pass * 40) / total_passes) : 0;
    printf("\r\033[36m[");
    for (int i = 0; i < 40; i++) {
        if (i < progress) printf("=");
        else printf("-");
    }
    printf("]\033[0m Pass \033[33m%d\033[0m: %s", current_pass, action);
    if (phase && strlen(phase) > 0) {
        printf(" \033[36m(%s)\033[0m", phase);
    }
    fflush(stdout);
}

static void show_symbol_resolution(const char* symbol_name, uint32_t address, bool defined) {
    clear_line();
    const char* status_color = defined ? "\033[32m" : "\033[33m";
    const char* status = defined ? "RESOLVED" : "DEFERRED";
    printf("\r\033[34m>\033[0m Symbol: \033[35m%-20s\033[0m -> %s0x%04X %s\033[0m", 
           symbol_name, status_color, address, status);
    fflush(stdout);
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

    printf("%s+================================================================+%s\n", header_color, reset_color);
    printf("%s|                        SYMBOL TABLE                            |%s\n", header_color, reset_color);
    printf("%s+====+=======================+============+======================+%s\n", header_color, reset_color);
    printf("%s| #  | Symbol Name           | Address    | Status               |%s\n", header_color, reset_color);
    printf("%s+====+=======================+============+======================+%s\n", header_color, reset_color);

    symbol_t *current = asm_ctx->symbols;
    int count = 0;
    while (current)
    {
        const char *status_color = current->defined ? defined_color : undefined_color;
        const char *status_text = current->defined ? "DEFINED" : "UNDEFINED";

        printf("|%s%3d%s | %s%-21.21s%s | %s0x%08X%s | %s%-21s%s|\n",
               header_color, ++count, reset_color,
               name_color, current->name, reset_color,
               address_color, current->address, reset_color,
               status_color, status_text, reset_color);
        current = current->next;
    }

    if (count == 0)
    {
        printf("|    | %s(no symbols)%s        |           |                       |\n",
               undefined_color, reset_color);
    }

    printf("%s+====+=======================+============+======================+%s\n", header_color, reset_color);
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
        } // Allow redefinition in subsequent passes for address updates
        existing->address = address;
        existing->defined = true;
        existing->section = asm_ctx->current_section_ptr ? asm_ctx->current_section_ptr->type : SECTION_TEXT;
        
        // Show symbol resolution progress
        if (asm_ctx->verbose && asm_ctx->pass >= 2) {
            show_symbol_resolution(name, address, true);
            usleep(25000); // 25ms delay
        }
        
        return true;
    }

    symbol_t *new_symbol = malloc(sizeof(symbol_t));
    if (!new_symbol)
        return false;

    strncpy(new_symbol->name, name, MAX_LABEL_LENGTH - 1);
    new_symbol->name[MAX_LABEL_LENGTH - 1] = '\0';
    new_symbol->address = address;
    new_symbol->defined = true;
    new_symbol->global = false;  // Initialize global flag
    new_symbol->external = false; // Initialize external flag
    new_symbol->section = asm_ctx->current_section_ptr ? asm_ctx->current_section_ptr->type : SECTION_TEXT;
    new_symbol->next = asm_ctx->symbols;
    asm_ctx->symbols = new_symbol;
    
    // Show symbol resolution progress
    if (asm_ctx->verbose && asm_ctx->pass >= 2) {
        show_symbol_resolution(name, address, true);
        usleep(25000); // 25ms delay
    }

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
    new_symbol->name[MAX_LABEL_LENGTH - 1] = '\0';
    new_symbol->address = 0;
    new_symbol->defined = false;
    new_symbol->global = false;  // Initialize global flag
    new_symbol->external = false; // Initialize external flag
    new_symbol->section = SECTION_UNDEF; // Undefined symbols have no section
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
        // Only report undefined symbols if they are not external
        // External symbols are meant to be undefined and resolved by the linker
        if (!current->defined && !current->external)
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
            fprintf(stderr, "  %s -> 0x%04X (defined=%s, external=%s)\n",
                    current->name, current->address,
                    current->defined ? "yes" : "no",
                    current->external ? "yes" : "no");
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
typedef struct
{
    uint8_t e_ident[16];  // ELF identification
    uint16_t e_type;      // Object file type
    uint16_t e_machine;   // Architecture
    uint32_t e_version;   // Object file version
    uint32_t e_entry;     // Entry point virtual address
    uint32_t e_phoff;     // Program header table file offset
    uint32_t e_shoff;     // Section header table file offset
    uint32_t e_flags;     // Processor-specific flags
    uint16_t e_ehsize;    // ELF header size in bytes
    uint16_t e_phentsize; // Program header table entry size
    uint16_t e_phnum;     // Program header table entry count
    uint16_t e_shentsize; // Section header table entry size
    uint16_t e_shnum;     // Section header table entry count
    uint16_t e_shstrndx;  // Section header string table index
} __attribute__((packed)) Elf32_Ehdr;

// ELF64 structures for generating 64-bit ELF files
typedef struct
{
    uint8_t e_ident[16];  // ELF identification
    uint16_t e_type;      // Object file type
    uint16_t e_machine;   // Architecture
    uint32_t e_version;   // Object file version
    uint64_t e_entry;     // Entry point virtual address
    uint64_t e_phoff;     // Program header table file offset
    uint64_t e_shoff;     // Section header table file offset
    uint32_t e_flags;     // Processor-specific flags
    uint16_t e_ehsize;    // ELF header size in bytes
    uint16_t e_phentsize; // Program header table entry size
    uint16_t e_phnum;     // Program header table entry count
    uint16_t e_shentsize; // Section header table entry size
    uint16_t e_shnum;     // Section header table entry count
    uint16_t e_shstrndx;  // Section header string table index
} __attribute__((packed)) Elf64_Ehdr;

typedef struct
{
    uint32_t p_type;   // Segment type
    uint32_t p_flags;  // Segment flags
    uint64_t p_offset; // Segment file offset
    uint64_t p_vaddr;  // Segment virtual address
    uint64_t p_paddr;  // Segment physical address
    uint64_t p_filesz; // Segment size in file
    uint64_t p_memsz;  // Segment size in memory
    uint64_t p_align;  // Segment alignment
} __attribute__((packed)) Elf64_Phdr;

// ELF constants
#define EI_MAG0 0
#define EI_MAG1 1
#define EI_MAG2 2
#define EI_MAG3 3
#define EI_CLASS 4
#define EI_DATA 5
#define EI_VERSION 6
#define EI_OSABI 7
#define EI_PAD 8

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASS32 1
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EV_CURRENT 1
#define ELFOSABI_SYSV 0

#define ET_REL 1  // Relocatable object file
#define ET_EXEC 2 // Executable file
#define EM_386 3  // Intel 80386
#define EM_X86_64 62  // AMD x86-64
#define PT_LOAD 1 // Loadable segment
#define PF_X 1    // Execute
#define PF_W 2    // Write
#define PF_R 4    // Read

// Section header types
#define SHT_NULL 0     // Section header table entry unused
#define SHT_PROGBITS 1 // Program data
#define SHT_SYMTAB 2   // Symbol table
#define SHT_STRTAB 3   // String table
#define SHT_RELA 4     // Relocation entries with addends
#define SHT_NOBITS 8   // Program space with no data (bss)
#define SHT_REL 9      // Relocation entries, no addends

// Section header flags
#define SHF_WRITE 0x1     // Writable
#define SHF_ALLOC 0x2     // Occupies memory during execution
#define SHF_EXECINSTR 0x4 // Executable

// Special section indices
#define SHN_UNDEF 0    // Undefined section
#define SHN_ABS 0xfff1 // Absolute values

// Symbol binding
#define STB_LOCAL 0  // Local symbol
#define STB_GLOBAL 1 // Global symbol
#define STB_WEAK 2   // Weak symbol

// Symbol types
#define STT_NOTYPE 0  // Symbol type not specified
#define STT_OBJECT 1  // Symbol is a data object
#define STT_FUNC 2    // Symbol is a code object
#define STT_SECTION 3 // Symbol associated with a section
#define STT_FILE 4    // Symbol's name is file name

// Macro to combine symbol binding and type
#define ELF32_ST_INFO(bind, type) (((bind) << 4) + ((type) & 0xf))

// i386 relocation types
#define R_386_NONE 0 // No reloc
#define R_386_32 1   // Direct 32 bit
#define R_386_PC32 2 // PC relative 32 bit

// x86-64 relocation types
#define R_X86_64_NONE 0     // No reloc
#define R_X86_64_64 1       // Direct 64 bit
#define R_X86_64_PC32 2     // PC relative 32 bit signed
#define R_X86_64_GOT32 3    // 32 bit GOT entry
#define R_X86_64_PLT32 4    // 32 bit PLT address
#define R_X86_64_32 10      // Direct 32 bit zero extended
#define R_X86_64_32S 11     // Direct 32 bit sign extended

// ELF32 relocation entry
typedef struct
{
    uint32_t r_offset; // Location (file offset, or vaddr) to apply the action
    uint32_t r_info;   // Relocation type and symbol index
} __attribute__((packed)) Elf32_Rel;

// ELF64 relocation entry with addend
typedef struct
{
    uint64_t r_offset; // Location (file offset, or vaddr) to apply the action
    uint64_t r_info;   // Relocation type and symbol index
    int64_t r_addend;  // Addend
} __attribute__((packed)) Elf64_Rela;

// Macro to extract symbol index from r_info
#define ELF32_R_SYM(i) ((i) >> 8)
#define ELF64_R_SYM(i) ((i) >> 32)
// Macro to extract relocation type from r_info
#define ELF32_R_TYPE(i) ((unsigned char)(i))
#define ELF64_R_TYPE(i) ((i) & 0xffffffff)
// Macro to combine symbol index and relocation type
#define ELF32_R_INFO(s, t) (((s) << 8) + (unsigned char)(t))
#define ELF64_R_INFO(s, t) (((uint64_t)(s) << 32) + ((t) & 0xffffffff))

// ELF32 symbol table entry
typedef struct
{
    uint32_t st_name;  // Symbol name (string table index)
    uint32_t st_value; // Symbol value
    uint32_t st_size;  // Symbol size
    uint8_t st_info;   // Symbol type and binding
    uint8_t st_other;  // Symbol visibility
    uint16_t st_shndx; // Section index
} __attribute__((packed)) Elf32_Sym;

// ELF64 symbol table entry
typedef struct
{
    uint32_t st_name;  // Symbol name (string table index)
    uint8_t st_info;   // Symbol type and binding
    uint8_t st_other;  // Symbol visibility
    uint16_t st_shndx; // Section index
    uint64_t st_value; // Symbol value
    uint64_t st_size;  // Symbol size
} __attribute__((packed)) Elf64_Sym;

// ELF32 section header structure
typedef struct
{
    uint32_t sh_name;      // Section name (string table index)
    uint32_t sh_type;      // Section type
    uint32_t sh_flags;     // Section flags
    uint32_t sh_addr;      // Section virtual addr at execution
    uint32_t sh_offset;    // Section file offset
    uint32_t sh_size;      // Section size in bytes
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint32_t sh_addralign; // Section alignment
    uint32_t sh_entsize;   // Entry size if section holds table
} __attribute__((packed)) Elf32_Shdr;

// ELF64 section header structure
typedef struct
{
    uint32_t sh_name;      // Section name (string table index)
    uint32_t sh_type;      // Section type
    uint64_t sh_flags;     // Section flags
    uint64_t sh_addr;      // Section virtual addr at execution
    uint64_t sh_offset;    // Section file offset
    uint64_t sh_size;      // Section size in bytes
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint64_t sh_addralign; // Section alignment
    uint64_t sh_entsize;   // Entry size if section holds table
} __attribute__((packed)) Elf64_Shdr;

// Forward declarations for ELF output functions
static bool output_write_elf32(assembler_t *asm_ctx);
static bool output_write_elf64(assembler_t *asm_ctx);

bool output_write_elf(assembler_t *asm_ctx)
{
    if (!asm_ctx->output)
        return false;

    // ELF files are only supported for 32-bit and 64-bit modes
    if (asm_ctx->mode != MODE_32BIT && asm_ctx->mode != MODE_64BIT)
        return false;

    // Choose appropriate ELF format based on mode
    if (asm_ctx->mode == MODE_32BIT)
    {
        return output_write_elf32(asm_ctx);
    }
    else // MODE_64BIT
    {
        return output_write_elf64(asm_ctx);
    }
}

static bool output_write_elf32(assembler_t *asm_ctx)
{
    if (!asm_ctx->output)
        return false;

    // ELF files are only supported for 32-bit and 64-bit modes
    if (asm_ctx->mode != MODE_32BIT && asm_ctx->mode != MODE_64BIT)
        return false;

    // Count sections that have data
    int section_count = 0;
    section_t *current = asm_ctx->sections;
    while (current)
    {
        if (current->size > 0)
            section_count++;
        current = current->next;
    } // Calculate symbol counts
    int symbol_count = 2; // Start with 2 for the null symbol and FILE symbol
    symbol_t *sym = asm_ctx->symbols;
    while (sym)
    {
        symbol_count++;
        sym = sym->next;
    }

    // Build symbol string table
    char *strtab = malloc(4096); // Generous buffer
    if (!strtab)
        return false;
    uint32_t strtab_offset = 1; // Start after null byte
    strtab[0] = '\0';           // Null string at offset 0
                                // Add filename to string table for FILE symbol
    uint32_t filename_offset = strtab_offset;
    const char *full_filename = asm_ctx->input_filename ? asm_ctx->input_filename : "unknown.asm";

    // Extract just the basename (filename without path) for FILE symbol
    const char *filename = full_filename;
    const char *last_slash = strrchr(full_filename, '/');
    const char *last_backslash = strrchr(full_filename, '\\');
    if (last_slash || last_backslash)
    {
        // Use the last occurrence of either slash or backslash
        const char *last_separator = (last_slash > last_backslash) ? last_slash : last_backslash;
        if (last_separator)
            filename = last_separator + 1;
    }

    size_t filename_len = strlen(filename);
    if (strtab_offset + filename_len + 1 >= 4096)
    {
        free(strtab);
        return false; // String table too large
    }
    strcpy(&strtab[strtab_offset], filename);
    strtab_offset += filename_len + 1;

    // Build symbol name offset table
    uint32_t *symbol_name_offsets = malloc(symbol_count * sizeof(uint32_t));
    if (!symbol_name_offsets)
    {
        free(strtab);
        return false;
    }

    // Add all symbol names to string table and record their offsets
    sym = asm_ctx->symbols;
    int symbol_index = 1; // Start at 1 (skip null symbol)
    while (sym)
    {
        size_t name_len = strlen(sym->name);
        if (strtab_offset + name_len + 1 >= 4096)
        {
            free(strtab);
            free(symbol_name_offsets);
            return false; // String table too large
        }
        strcpy(&strtab[strtab_offset], sym->name);
        symbol_name_offsets[symbol_index] = strtab_offset; // Store offset in separate array
        strtab_offset += name_len + 1;
        symbol_index++;
        sym = sym->next;
    }
    uint32_t strtab_size = strtab_offset;

    // Count relocations by section to determine if we need .rel.text, .rel.data, etc.
    int text_relocations = 0, data_relocations = 0;
    relocation_t *reloc = asm_ctx->relocations;
    while (reloc)
    {
        if (reloc->section == SECTION_TEXT)
            text_relocations++;
        else if (reloc->section == SECTION_DATA)
            data_relocations++;
        reloc = reloc->next;
    }

    // Count relocation sections needed
    int relocation_sections = 0;
    if (text_relocations > 0)
        relocation_sections++;
    if (data_relocations > 0)
        relocation_sections++;

    // Calculate section count: null + sections + .symtab + .strtab + .shstrtab + relocation sections
    int total_sections = section_count + 4 + relocation_sections;

    // Calculate file layout
    uint32_t elf_header_size = sizeof(Elf32_Ehdr);

    // Section data starts after ELF header
    uint32_t section_data_offset = elf_header_size;
    uint32_t current_offset = section_data_offset;

    // Calculate section data offsets
    current = asm_ctx->sections;
    while (current)
    {
        if (current->size > 0 && current->type != SECTION_BSS)
        {
            current_offset += current->size;
        }
        current = current->next;
    }

    // Symbol table comes after section data
    uint32_t symtab_offset = current_offset;
    uint32_t symtab_size = symbol_count * sizeof(Elf32_Sym);
    current_offset += symtab_size;
    // String table comes after symbol table
    uint32_t strtab_file_offset = current_offset;
    current_offset += strtab_size;

    // Relocation sections come after string table
    uint32_t rel_text_offset = 0, rel_data_offset = 0;
    uint32_t rel_text_size = 0, rel_data_size = 0;

    if (text_relocations > 0)
    {
        rel_text_offset = current_offset;
        rel_text_size = text_relocations * sizeof(Elf32_Rel);
        current_offset += rel_text_size;
    }

    if (data_relocations > 0)
    {
        rel_data_offset = current_offset;
        rel_data_size = data_relocations * sizeof(Elf32_Rel);
        current_offset += rel_data_size;
    }

    // Section header string table comes after relocation sections
    uint32_t shstrtab_offset = current_offset;
    const char section_names[] = "\0.text\0.data\0.bss\0.symtab\0.strtab\0.shstrtab\0.rel.text\0.rel.data\0";
    uint32_t shstrtab_size = sizeof(section_names) - 1;
    current_offset += shstrtab_size;

    // Section headers come last
    uint32_t section_headers_offset = current_offset;

    // Create ELF header for relocatable object file
    Elf32_Ehdr ehdr = {0};
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS32;  // Use ELF32 format for both modes for now
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;

    ehdr.e_type = ET_REL; // Relocatable object file
    ehdr.e_machine = (asm_ctx->mode == MODE_64BIT) ? EM_X86_64 : EM_386;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_entry = 0; // No entry point for relocatable
    ehdr.e_phoff = 0; // No program headers for relocatable
    ehdr.e_shoff = section_headers_offset;
    ehdr.e_flags = 0;
    ehdr.e_ehsize = elf_header_size;
    ehdr.e_phentsize = 0; // No program headers
    ehdr.e_phnum = 0;     // No program headers
    ehdr.e_shentsize = sizeof(Elf32_Shdr);
    ehdr.e_shnum = total_sections;
    // e_shstrndx will be set after section index calculation

    // Write ELF header (temporarily with placeholder for e_shstrndx)
    long ehdr_position = ftell(asm_ctx->output);
    if (fwrite(&ehdr, sizeof(Elf32_Ehdr), 1, asm_ctx->output) != 1)
    {
        free(strtab);
        return false;
    }

    // Write section data in order: .text, .data (skip .bss as it has no file data)
    section_type_t section_order[] = {SECTION_TEXT, SECTION_DATA};

    for (int i = 0; i < 2; i++)
    {
        section_type_t type = section_order[i];
        current = asm_ctx->sections;

        while (current)
        {
            if (current->type == type && current->size > 0 && current->data)
            {
                if (fwrite(current->data, 1, current->size, asm_ctx->output) != current->size)
                {
                    free(strtab);
                    return false;
                }
            }
            current = current->next;
        }
    } // Write symbol table
    // First symbol is always null
    Elf32_Sym null_sym = {0};
    if (fwrite(&null_sym, sizeof(Elf32_Sym), 1, asm_ctx->output) != 1)
    {
        free(strtab);
        return false;
    }

    // Second symbol is FILE symbol with source filename
    Elf32_Sym file_sym = {0};
    file_sym.st_name = filename_offset;
    file_sym.st_value = 0;
    file_sym.st_size = 0;
    file_sym.st_info = ELF32_ST_INFO(STB_LOCAL, STT_FILE);
    file_sym.st_other = 0;
    file_sym.st_shndx = SHN_ABS; // FILE symbols use SHN_ABS
    if (fwrite(&file_sym, sizeof(Elf32_Sym), 1, asm_ctx->output) != 1)
    {
        free(strtab);
        return false;
    }

    // Write all symbols - local symbols first, then global symbols (ELF convention)
    sym = asm_ctx->symbols;
    symbol_index = 1; // Reset index for symbol table writing

    // First pass: write local symbols
    while (sym)
    {
        if (!sym->global) // Write local symbols first
        {
            Elf32_Sym elf_sym = {0};
            elf_sym.st_name = symbol_name_offsets[symbol_index]; // Use stored offset
            elf_sym.st_value = sym->defined ? sym->address : 0;  // Use actual symbol address
            elf_sym.st_size = 0;                                 // Size unknown for most symbols
                                                                 // Determine symbol type and binding
            uint8_t bind = STB_LOCAL;
            uint8_t type = STT_NOTYPE; // Default type

            // Try to determine if it's a function by looking at the section
            if (sym->section == SECTION_TEXT)
            {
                type = STT_FUNC;
            }
            else if (sym->section == SECTION_DATA || sym->section == SECTION_BSS)
            {
                type = STT_OBJECT;
            }

            elf_sym.st_info = ELF32_ST_INFO(bind, type);
            elf_sym.st_other = 0;

            // Set section index based on symbol section
            // External symbols should always be undefined (SHN_UNDEF)
            if (sym->external)
            {
                elf_sym.st_shndx = SHN_UNDEF; // External symbols are undefined
            }
            else if (sym->section == SECTION_TEXT)
            {
                elf_sym.st_shndx = 1; // .text is section 1
            }
            else if (sym->section == SECTION_DATA)
            {
                elf_sym.st_shndx = 2; // .data is section 2
            }
            else if (sym->section == SECTION_BSS)
            {
                elf_sym.st_shndx = 3; // .bss is section 3
            }
            else // SECTION_UNDEF or other undefined sections
            {
                elf_sym.st_shndx = SHN_UNDEF; // Undefined section
            }

            if (fwrite(&elf_sym, sizeof(Elf32_Sym), 1, asm_ctx->output) != 1)
            {
                free(strtab);
                return false;
            }
        }
        symbol_index++;
        sym = sym->next;
    }

    // Second pass: write global symbols
    sym = asm_ctx->symbols;
    symbol_index = 1; // Reset index
    while (sym)
    {
        if (sym->global) // Write global symbols second
        {
            Elf32_Sym elf_sym = {0};
            elf_sym.st_name = symbol_name_offsets[symbol_index]; // Use stored offset
            elf_sym.st_value = sym->defined ? sym->address : 0;  // Use actual symbol address
            elf_sym.st_size = 0;                                 // Size unknown for most symbols
                                                                 // Determine symbol type and binding
            uint8_t bind = STB_GLOBAL;
            uint8_t type = STT_NOTYPE; // Default type

            // Try to determine if it's a function by looking at the section
            if (sym->section == SECTION_TEXT)
            {
                type = STT_FUNC;
            }
            else if (sym->section == SECTION_DATA || sym->section == SECTION_BSS)
            {
                type = STT_OBJECT;
            }

            elf_sym.st_info = ELF32_ST_INFO(bind, type);
            elf_sym.st_other = 0;

            // Set section index based on symbol section
            // External symbols should always be undefined (SHN_UNDEF)
            if (sym->external)
            {
                elf_sym.st_shndx = SHN_UNDEF; // External symbols are undefined
            }
            else if (sym->section == SECTION_TEXT)
            {
                elf_sym.st_shndx = 1; // .text is section 1
            }
            else if (sym->section == SECTION_DATA)
            {
                elf_sym.st_shndx = 2; // .data is section 2
            }
            else if (sym->section == SECTION_BSS)
            {
                elf_sym.st_shndx = 3; // .bss is section 3
            }
            else // SECTION_UNDEF or other undefined sections
            {
                elf_sym.st_shndx = SHN_UNDEF; // Undefined section
            }

            if (fwrite(&elf_sym, sizeof(Elf32_Sym), 1, asm_ctx->output) != 1)
            {
                free(strtab);
                return false;
            }
        }
        symbol_index++;
        sym = sym->next;
    }

    // Clean up offset table
    free(symbol_name_offsets); // Write string table
    if (fwrite(strtab, 1, strtab_size, asm_ctx->output) != strtab_size)
    {
        free(strtab);
        return false;
    }

    free(strtab);

    // Write relocation sections
    if (text_relocations > 0)
    {
        // Write .rel.text relocation entries
        relocation_t *reloc = asm_ctx->relocations;
        while (reloc)
        {
            if (reloc->section == SECTION_TEXT)
            {
                // Find symbol index for the symbol being relocated
                symbol_t *sym = asm_ctx->symbols;
                uint32_t symbol_index = 1; // Start after null symbol

                // Skip FILE symbol
                symbol_index++;

                // Find the symbol
                while (sym)
                {
                    if (strcmp(sym->name, reloc->symbol_name) == 0)
                        break;
                    symbol_index++;
                    sym = sym->next;
                }

                if (sym)
                {
                    Elf32_Rel rel_entry = {0};
                    rel_entry.r_offset = reloc->offset;
                    rel_entry.r_info = ELF32_R_INFO(symbol_index, reloc->relocation_type);

                    if (fwrite(&rel_entry, sizeof(Elf32_Rel), 1, asm_ctx->output) != 1)
                        return false;

                    if (asm_ctx->verbose)
                    {
                        printf("DEBUG: Wrote .rel.text entry: offset=0x%X, symbol_index=%d, type=%d\n",
                               rel_entry.r_offset, symbol_index, reloc->relocation_type);
                    }
                }
            }
            reloc = reloc->next;
        }
    }

    if (data_relocations > 0)
    {
        // Write .rel.data relocation entries (similar logic as .rel.text)
        relocation_t *reloc = asm_ctx->relocations;
        while (reloc)
        {
            if (reloc->section == SECTION_DATA)
            {
                // Find symbol index for the symbol being relocated
                symbol_t *sym = asm_ctx->symbols;
                uint32_t symbol_index = 1; // Start after null symbol

                // Skip FILE symbol
                symbol_index++;

                // Find the symbol
                while (sym)
                {
                    if (strcmp(sym->name, reloc->symbol_name) == 0)
                        break;
                    symbol_index++;
                    sym = sym->next;
                }

                if (sym)
                {
                    Elf32_Rel rel_entry = {0};
                    rel_entry.r_offset = reloc->offset;
                    rel_entry.r_info = ELF32_R_INFO(symbol_index, reloc->relocation_type);

                    if (fwrite(&rel_entry, sizeof(Elf32_Rel), 1, asm_ctx->output) != 1)
                        return false;

                    if (asm_ctx->verbose)
                    {
                        printf("DEBUG: Wrote .rel.data entry: offset=0x%X, symbol_index=%d, type=%d\n",
                               rel_entry.r_offset, symbol_index, reloc->relocation_type);
                    }
                }
            }
            reloc = reloc->next;
        }
    }

    // Write .shstrtab (section header string table)
    if (fwrite(section_names, 1, shstrtab_size, asm_ctx->output) != shstrtab_size)
        return false;

    // Write section headers

    // 1. NULL section header (index 0)
    Elf32_Shdr null_shdr = {0};
    if (fwrite(&null_shdr, sizeof(Elf32_Shdr), 1, asm_ctx->output) != 1)
        return false;

    // 2. Section headers for actual sections
    uint32_t file_offset = section_data_offset; // String table offsets: \0.text\0.data\0.bss\0.symtab\0.strtab\0.shstrtab\0.rel.text\0.rel.data\0
    //                       0 1     7 13   18 26     34 44        54
    uint32_t text_name_offset = 1;      // ".text"
    uint32_t data_name_offset = 7;      // ".data"
    uint32_t bss_name_offset = 13;      // ".bss"
    uint32_t symtab_name_offset = 18;   // ".symtab"
    uint32_t strtab_name_offset = 26;   // ".strtab"
    uint32_t shstrtab_name_offset = 34; // ".shstrtab"
    uint32_t rel_text_name_offset = 44; // ".rel.text"
    uint32_t rel_data_name_offset = 54; // ".rel.data"// Count local symbols for sh_info (index of first non-local symbol)
    int local_symbol_count = 2;         // Start with 2 for null symbol and FILE symbol
    sym = asm_ctx->symbols;
    while (sym)
    {
        if (!sym->global)
            local_symbol_count++;
        sym = sym->next;
    }

    // Write .text section header if it exists
    current = asm_ctx->sections;
    while (current)
    {
        if (current->type == SECTION_TEXT && current->size > 0)
        {
            Elf32_Shdr shdr = {0};
            shdr.sh_name = text_name_offset;
            shdr.sh_type = SHT_PROGBITS;
            shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
            shdr.sh_addr = 0;
            shdr.sh_offset = file_offset;
            shdr.sh_size = current->size;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = 1;
            shdr.sh_entsize = 0;

            if (fwrite(&shdr, sizeof(Elf32_Shdr), 1, asm_ctx->output) != 1)
                return false;

            file_offset += current->size;
            break;
        }
        current = current->next;
    }

    // Write .data section header if it exists
    current = asm_ctx->sections;
    while (current)
    {
        if (current->type == SECTION_DATA && current->size > 0)
        {
            Elf32_Shdr shdr = {0};
            shdr.sh_name = data_name_offset;
            shdr.sh_type = SHT_PROGBITS;
            shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
            shdr.sh_addr = 0;
            shdr.sh_offset = file_offset;
            shdr.sh_size = current->size;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = 1;
            shdr.sh_entsize = 0;

            if (fwrite(&shdr, sizeof(Elf32_Shdr), 1, asm_ctx->output) != 1)
                return false;

            file_offset += current->size;
            break;
        }
        current = current->next;
    }

    // Write .bss section header if it exists (no file data)
    current = asm_ctx->sections;
    while (current)
    {
        if (current->type == SECTION_BSS && current->size > 0)
        {
            Elf32_Shdr shdr = {0};
            shdr.sh_name = bss_name_offset;
            shdr.sh_type = SHT_NOBITS;
            shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
            shdr.sh_addr = 0;
            shdr.sh_offset = 0; // No file data
            shdr.sh_size = current->size;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = 1;
            shdr.sh_entsize = 0;

            if (fwrite(&shdr, sizeof(Elf32_Shdr), 1, asm_ctx->output) != 1)
                return false;
            break;
        }
        current = current->next;
    }

    // Calculate actual section indices
    // Layout: null(0), .text(1), .data(2), .bss(3), .symtab(4), .strtab(5), .rel.text(?), .rel.data(?), .shstrtab(last)
    int next_section_index = 1; // Start after null section
    int text_section_index = -1, data_section_index = -1, bss_section_index = -1;
    int symtab_section_index = -1, strtab_section_index = -1;

    // Assign indices for regular sections
    current = asm_ctx->sections;
    while (current)
    {
        if (current->size > 0)
        {
            if (current->type == SECTION_TEXT)
                text_section_index = next_section_index++;
            else if (current->type == SECTION_DATA)
                data_section_index = next_section_index++;
            else if (current->type == SECTION_BSS)
                bss_section_index = next_section_index++;
        }
        current = current->next;
    }

    // Assign indices for special sections
    symtab_section_index = next_section_index++;
    strtab_section_index = next_section_index++;

    // Relocation sections come next
    int rel_text_section_index = -1, rel_data_section_index = -1;
    if (text_relocations > 0)
        rel_text_section_index = next_section_index++;
    if (data_relocations > 0)
        rel_data_section_index = next_section_index++;
    // .shstrtab is last
    int shstrtab_section_index = next_section_index;

    // Update the ELF header with the correct shstrndx
    long current_position = ftell(asm_ctx->output);
    fseek(asm_ctx->output, ehdr_position + offsetof(Elf32_Ehdr, e_shstrndx), SEEK_SET);
    uint16_t shstrndx = (uint16_t)shstrtab_section_index;
    fwrite(&shstrndx, sizeof(uint16_t), 1, asm_ctx->output);
    fseek(asm_ctx->output, current_position, SEEK_SET); // Write .symtab section header
    Elf32_Shdr symtab_shdr = {0};
    symtab_shdr.sh_name = symtab_name_offset;
    symtab_shdr.sh_type = SHT_SYMTAB;
    symtab_shdr.sh_flags = 0;
    symtab_shdr.sh_addr = 0;
    symtab_shdr.sh_offset = symtab_offset;
    symtab_shdr.sh_size = symtab_size;
    symtab_shdr.sh_link = strtab_section_index; // Index of .strtab section
    symtab_shdr.sh_info = local_symbol_count;   // Index of first non-local symbol
    symtab_shdr.sh_addralign = 4;
    symtab_shdr.sh_entsize = sizeof(Elf32_Sym);

    if (fwrite(&symtab_shdr, sizeof(Elf32_Shdr), 1, asm_ctx->output) != 1)
        return false;

    // Write .strtab section header
    Elf32_Shdr strtab_shdr = {0};
    strtab_shdr.sh_name = strtab_name_offset;
    strtab_shdr.sh_type = SHT_STRTAB;
    strtab_shdr.sh_flags = 0;
    strtab_shdr.sh_addr = 0;
    strtab_shdr.sh_offset = strtab_file_offset;
    strtab_shdr.sh_size = strtab_size;
    strtab_shdr.sh_link = 0;
    strtab_shdr.sh_info = 0;
    strtab_shdr.sh_addralign = 1;
    strtab_shdr.sh_entsize = 0;

    if (fwrite(&strtab_shdr, sizeof(Elf32_Shdr), 1, asm_ctx->output) != 1)
        return false;

    // Write relocation section headers
    if (text_relocations > 0 && text_section_index >= 0)
    {
        Elf32_Shdr rel_text_shdr = {0};
        rel_text_shdr.sh_name = rel_text_name_offset;
        rel_text_shdr.sh_type = SHT_REL;
        rel_text_shdr.sh_flags = 0;
        rel_text_shdr.sh_addr = 0;
        rel_text_shdr.sh_offset = rel_text_offset;
        rel_text_shdr.sh_size = rel_text_size;
        rel_text_shdr.sh_link = symtab_section_index; // Index of .symtab section
        rel_text_shdr.sh_info = text_section_index;   // Index of .text section being relocated
        rel_text_shdr.sh_addralign = 4;
        rel_text_shdr.sh_entsize = sizeof(Elf32_Rel);

        if (fwrite(&rel_text_shdr, sizeof(Elf32_Shdr), 1, asm_ctx->output) != 1)
            return false;
    }

    if (data_relocations > 0 && data_section_index >= 0)
    {
        Elf32_Shdr rel_data_shdr = {0};
        rel_data_shdr.sh_name = rel_data_name_offset;
        rel_data_shdr.sh_type = SHT_REL;
        rel_data_shdr.sh_flags = 0;
        rel_data_shdr.sh_addr = 0;
        rel_data_shdr.sh_offset = rel_data_offset;
        rel_data_shdr.sh_size = rel_data_size;
        rel_data_shdr.sh_link = symtab_section_index; // Index of .symtab section
        rel_data_shdr.sh_info = data_section_index;   // Index of .data section being relocated
        rel_data_shdr.sh_addralign = 4;
        rel_data_shdr.sh_entsize = sizeof(Elf32_Rel);

        if (fwrite(&rel_data_shdr, sizeof(Elf32_Shdr), 1, asm_ctx->output) != 1)
            return false;
    }

    // Write .shstrtab section header (last section)
    Elf32_Shdr shstrtab_shdr = {0};
    shstrtab_shdr.sh_name = shstrtab_name_offset;
    shstrtab_shdr.sh_type = SHT_STRTAB;
    shstrtab_shdr.sh_flags = 0;
    shstrtab_shdr.sh_addr = 0;
    shstrtab_shdr.sh_offset = shstrtab_offset;
    shstrtab_shdr.sh_size = shstrtab_size;
    shstrtab_shdr.sh_link = 0;
    shstrtab_shdr.sh_info = 0;
    shstrtab_shdr.sh_addralign = 1;
    shstrtab_shdr.sh_entsize = 0;

    if (fwrite(&shstrtab_shdr, sizeof(Elf32_Shdr), 1, asm_ctx->output) != 1)
        return false;

    return true;
}

static bool output_write_elf64(assembler_t *asm_ctx)
{
    // Count sections that have data
    int section_count = 0;
    section_t *current = asm_ctx->sections;
    while (current)
    {
        if (current->size > 0)
            section_count++;
        current = current->next;
    }

    // Calculate symbol counts
    int symbol_count = 2; // Start with 2 for the null symbol and FILE symbol
    symbol_t *sym = asm_ctx->symbols;
    while (sym)
    {
        symbol_count++;
        sym = sym->next;
    }

    // Build symbol string table
    char *strtab = malloc(4096); // Generous buffer
    if (!strtab)
        return false;
    uint32_t strtab_offset = 1; // Start after null byte
    strtab[0] = '\0';           // Null string at offset 0
    
    // Add filename to string table for FILE symbol
    uint32_t filename_offset = strtab_offset;
    const char *full_filename = asm_ctx->input_filename ? asm_ctx->input_filename : "unknown.asm";

    // Extract just the basename (filename without path) for FILE symbol
    const char *filename = full_filename;
    const char *last_slash = strrchr(full_filename, '/');
    const char *last_backslash = strrchr(full_filename, '\\');
    if (last_slash || last_backslash)
    {
        // Use the last occurrence of either slash or backslash
        const char *last_separator = (last_slash > last_backslash) ? last_slash : last_backslash;
        if (last_separator)
            filename = last_separator + 1;
    }

    size_t filename_len = strlen(filename);
    if (strtab_offset + filename_len + 1 >= 4096)
    {
        free(strtab);
        return false; // String table too large
    }
    strcpy(&strtab[strtab_offset], filename);
    strtab_offset += filename_len + 1;

    // Build symbol name offset table
    uint32_t *symbol_name_offsets = malloc(symbol_count * sizeof(uint32_t));
    if (!symbol_name_offsets)
    {
        free(strtab);
        return false;
    }

    // Add all symbol names to string table and record their offsets
    sym = asm_ctx->symbols;
    int symbol_index = 1; // Start at 1 (skip null symbol)
    while (sym)
    {
        size_t name_len = strlen(sym->name);
        if (strtab_offset + name_len + 1 >= 4096)
        {
            free(strtab);
            free(symbol_name_offsets);
            return false; // String table too large
        }
        strcpy(&strtab[strtab_offset], sym->name);
        symbol_name_offsets[symbol_index] = strtab_offset; // Store offset in separate array
        strtab_offset += name_len + 1;
        symbol_index++;
        sym = sym->next;
    }
    uint32_t strtab_size = strtab_offset;

    // Count relocations by section to determine if we need .rel.text, .rel.data, etc.
    int text_relocations = 0, data_relocations = 0;
    relocation_t *reloc = asm_ctx->relocations;
    while (reloc)
    {
        if (reloc->section == SECTION_TEXT)
            text_relocations++;
        else if (reloc->section == SECTION_DATA)
            data_relocations++;
        reloc = reloc->next;
    }

    // Count relocation sections needed
    int relocation_sections = 0;
    if (text_relocations > 0)
        relocation_sections++;
    if (data_relocations > 0)
        relocation_sections++;

    // Calculate section count: null + sections + .symtab + .strtab + .shstrtab + relocation sections
    int total_sections = section_count + 4 + relocation_sections;

    // Calculate file layout
    uint64_t elf_header_size = sizeof(Elf64_Ehdr);

    // Section data starts after ELF header
    uint64_t section_data_offset = elf_header_size;
    uint64_t current_offset = section_data_offset;

    // Calculate section data offsets
    current = asm_ctx->sections;
    while (current)
    {
        if (current->size > 0 && current->type != SECTION_BSS)
        {
            current_offset += current->size;
        }
        current = current->next;
    }

    // Symbol table comes after section data
    uint64_t symtab_offset = current_offset;
    uint64_t symtab_size = symbol_count * sizeof(Elf64_Sym);
    current_offset += symtab_size;
    
    // String table comes after symbol table
    uint64_t strtab_file_offset = current_offset;
    current_offset += strtab_size;

    // Relocation sections come after string table
    uint64_t rel_text_offset = 0, rel_data_offset = 0;
    uint64_t rel_text_size = 0, rel_data_size = 0;

    if (text_relocations > 0)
    {
        rel_text_offset = current_offset;
        rel_text_size = text_relocations * sizeof(Elf64_Rela);
        current_offset += rel_text_size;
    }

    if (data_relocations > 0)
    {
        rel_data_offset = current_offset;
        rel_data_size = data_relocations * sizeof(Elf64_Rela);
        current_offset += rel_data_size;
    }

    // Section header string table comes after relocation sections
    uint64_t shstrtab_offset = current_offset;
    const char section_names[] = "\0.text\0.data\0.bss\0.symtab\0.strtab\0.shstrtab\0.rela.text\0.rela.data\0";
    uint64_t shstrtab_size = sizeof(section_names) - 1;
    current_offset += shstrtab_size;

    // Section headers come last
    uint64_t section_headers_offset = current_offset;

    // Create ELF64 header for relocatable object file
    Elf64_Ehdr ehdr = {0};
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;  // Use ELF64 format
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;

    ehdr.e_type = ET_REL; // Relocatable object file
    ehdr.e_machine = EM_X86_64; // x86-64 architecture
    ehdr.e_version = EV_CURRENT;
    ehdr.e_entry = 0; // No entry point for relocatable
    ehdr.e_phoff = 0; // No program headers for relocatable
    ehdr.e_shoff = section_headers_offset;
    ehdr.e_flags = 0;
    ehdr.e_ehsize = elf_header_size;
    ehdr.e_phentsize = 0; // No program headers
    ehdr.e_phnum = 0;     // No program headers
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    ehdr.e_shnum = total_sections;
    // e_shstrndx will be set after section index calculation

    // Write ELF header (temporarily with placeholder for e_shstrndx)
    long ehdr_position = ftell(asm_ctx->output);
    if (fwrite(&ehdr, sizeof(Elf64_Ehdr), 1, asm_ctx->output) != 1)
    {
        free(strtab);
        free(symbol_name_offsets);
        return false;
    }

    // Write section data in order: .text, .data (skip .bss as it has no file data)
    section_type_t section_order[] = {SECTION_TEXT, SECTION_DATA};

    for (int i = 0; i < 2; i++)
    {
        section_type_t type = section_order[i];
        current = asm_ctx->sections;

        while (current)
        {
            if (current->type == type && current->size > 0 && current->data)
            {
                if (fwrite(current->data, 1, current->size, asm_ctx->output) != current->size)
                {
                    free(strtab);
                    free(symbol_name_offsets);
                    return false;
                }
            }
            current = current->next;
        }
    }

    // Write symbol table
    // First symbol is always null
    Elf64_Sym null_sym = {0};
    if (fwrite(&null_sym, sizeof(Elf64_Sym), 1, asm_ctx->output) != 1)
    {
        free(strtab);
        free(symbol_name_offsets);
        return false;
    }

    // Second symbol is FILE symbol with source filename
    Elf64_Sym file_sym = {0};
    file_sym.st_name = filename_offset;
    file_sym.st_value = 0;
    file_sym.st_size = 0;
    file_sym.st_info = ELF32_ST_INFO(STB_LOCAL, STT_FILE); // ST_INFO is same for ELF32/64
    file_sym.st_other = 0;
    file_sym.st_shndx = SHN_ABS; // FILE symbols use SHN_ABS
    if (fwrite(&file_sym, sizeof(Elf64_Sym), 1, asm_ctx->output) != 1)
    {
        free(strtab);
        free(symbol_name_offsets);
        return false;
    }

    // Write all symbols - local symbols first, then global symbols (ELF convention)
    sym = asm_ctx->symbols;
    symbol_index = 1; // Reset index for symbol table writing

    // First pass: write local symbols
    while (sym)
    {
        if (!sym->global) // Write local symbols first
        {
            Elf64_Sym elf_sym = {0};
            elf_sym.st_name = symbol_name_offsets[symbol_index]; // Use stored offset
            elf_sym.st_value = sym->defined ? sym->address : 0;  // Use actual symbol address
            elf_sym.st_size = 0;                                 // Size unknown for most symbols
                                                                 // Determine symbol type and binding
            uint8_t bind = STB_LOCAL;
            uint8_t type = STT_NOTYPE; // Default type

            // Try to determine if it's a function by looking at the section
            if (sym->section == SECTION_TEXT)
            {
                type = STT_FUNC;
            }
            else if (sym->section == SECTION_DATA || sym->section == SECTION_BSS)
            {
                type = STT_OBJECT;
            }

            elf_sym.st_info = ELF32_ST_INFO(bind, type); // ST_INFO is same for ELF32/64
            elf_sym.st_other = 0;

            // Set section index based on symbol section
            // External symbols should always be undefined (SHN_UNDEF)
            if (sym->external)
            {
                elf_sym.st_shndx = SHN_UNDEF; // External symbols are undefined
            }
            else if (sym->section == SECTION_TEXT)
            {
                elf_sym.st_shndx = 1; // .text is section 1
            }
            else if (sym->section == SECTION_DATA)
            {
                elf_sym.st_shndx = 2; // .data is section 2
            }
            else if (sym->section == SECTION_BSS)
            {
                elf_sym.st_shndx = 3; // .bss is section 3
            }
            else // SECTION_UNDEF or other undefined sections
            {
                elf_sym.st_shndx = SHN_UNDEF; // Undefined section
            }

            if (fwrite(&elf_sym, sizeof(Elf64_Sym), 1, asm_ctx->output) != 1)
            {
                free(strtab);
                free(symbol_name_offsets);
                return false;
            }
        }
        symbol_index++;
        sym = sym->next;
    }

    // Second pass: write global symbols
    sym = asm_ctx->symbols;
    symbol_index = 1; // Reset index
    while (sym)
    {
        if (sym->global) // Write global symbols second
        {
            Elf64_Sym elf_sym = {0};
            elf_sym.st_name = symbol_name_offsets[symbol_index]; // Use stored offset
            elf_sym.st_value = sym->defined ? sym->address : 0;  // Use actual symbol address
            elf_sym.st_size = 0;                                 // Size unknown for most symbols
                                                                 // Determine symbol type and binding
            uint8_t bind = STB_GLOBAL;
            uint8_t type = STT_NOTYPE; // Default type

            // Try to determine if it's a function by looking at the section
            if (sym->section == SECTION_TEXT)
            {
                type = STT_FUNC;
            }
            else if (sym->section == SECTION_DATA || sym->section == SECTION_BSS)
            {
                type = STT_OBJECT;
            }

            elf_sym.st_info = ELF32_ST_INFO(bind, type); // ST_INFO is same for ELF32/64
            elf_sym.st_other = 0;

            // Set section index based on symbol section
            // External symbols should always be undefined (SHN_UNDEF)
            if (sym->external)
            {
                elf_sym.st_shndx = SHN_UNDEF; // External symbols are undefined
            }
            else if (sym->section == SECTION_TEXT)
            {
                elf_sym.st_shndx = 1; // .text is section 1
            }
            else if (sym->section == SECTION_DATA)
            {
                elf_sym.st_shndx = 2; // .data is section 2
            }
            else if (sym->section == SECTION_BSS)
            {
                elf_sym.st_shndx = 3; // .bss is section 3
            }
            else // SECTION_UNDEF or other undefined sections
            {
                elf_sym.st_shndx = SHN_UNDEF; // Undefined section
            }

            if (fwrite(&elf_sym, sizeof(Elf64_Sym), 1, asm_ctx->output) != 1)
            {
                free(strtab);
                free(symbol_name_offsets);
                return false;
            }
        }
        symbol_index++;
        sym = sym->next;
    }

    // Write string table
    if (fwrite(strtab, 1, strtab_size, asm_ctx->output) != strtab_size)
    {
        free(strtab);
        free(symbol_name_offsets);
        return false;
    }

    free(strtab);

    // Write relocation sections
    if (text_relocations > 0)
    {
        // Write .rela.text relocation entries
        relocation_t *reloc = asm_ctx->relocations;
        while (reloc)
        {
            if (reloc->section == SECTION_TEXT)
            {
                // Find symbol index for the symbol being relocated
                symbol_t *sym = asm_ctx->symbols;
                uint32_t symbol_index = 1; // Start after null symbol

                // Skip FILE symbol
                symbol_index++;

                // Find the symbol
                while (sym)
                {
                    if (strcmp(sym->name, reloc->symbol_name) == 0)
                        break;
                    symbol_index++;
                    sym = sym->next;
                }

                if (sym)
                {
                    Elf64_Rela rel_entry = {0};
                    rel_entry.r_offset = reloc->offset;
                    rel_entry.r_info = ELF64_R_INFO(symbol_index, reloc->relocation_type);
                    rel_entry.r_addend = reloc->addend;

                    if (fwrite(&rel_entry, sizeof(Elf64_Rela), 1, asm_ctx->output) != 1)
                    {
                        free(symbol_name_offsets);
                        return false;
                    }

                    if (asm_ctx->verbose)
                    {
                        printf("DEBUG: Wrote .rela.text entry: offset=0x%llX, symbol_index=%d, type=%d, addend=%lld\n",
                               (unsigned long long)rel_entry.r_offset, symbol_index, reloc->relocation_type, 
                               (long long)rel_entry.r_addend);
                    }
                }
            }
            reloc = reloc->next;
        }
    }

    if (data_relocations > 0)
    {
        // Write .rela.data relocation entries (similar logic as .rela.text)
        relocation_t *reloc = asm_ctx->relocations;
        while (reloc)
        {
            if (reloc->section == SECTION_DATA)
            {
                // Find symbol index for the symbol being relocated
                symbol_t *sym = asm_ctx->symbols;
                uint32_t symbol_index = 1; // Start after null symbol

                // Skip FILE symbol
                symbol_index++;

                // Find the symbol
                while (sym)
                {
                    if (strcmp(sym->name, reloc->symbol_name) == 0)
                        break;
                    symbol_index++;
                    sym = sym->next;
                }

                if (sym)
                {
                    Elf64_Rela rel_entry = {0};
                    rel_entry.r_offset = reloc->offset;
                    rel_entry.r_info = ELF64_R_INFO(symbol_index, reloc->relocation_type);
                    rel_entry.r_addend = reloc->addend;

                    if (fwrite(&rel_entry, sizeof(Elf64_Rela), 1, asm_ctx->output) != 1)
                    {
                        free(symbol_name_offsets);
                        return false;
                    }

                    if (asm_ctx->verbose)
                    {
                        printf("DEBUG: Wrote .rela.data entry: offset=0x%llX, symbol_index=%d, type=%d, addend=%lld\n",
                               (unsigned long long)rel_entry.r_offset, symbol_index, reloc->relocation_type,
                               (long long)rel_entry.r_addend);
                    }
                }
            }
            reloc = reloc->next;
        }
    }

    // Write .shstrtab (section header string table)
    if (fwrite(section_names, 1, shstrtab_size, asm_ctx->output) != shstrtab_size)
    {
        free(symbol_name_offsets);
        return false;
    }

    // Write section headers

    // 1. NULL section header (index 0)
    Elf64_Shdr null_shdr = {0};
    if (fwrite(&null_shdr, sizeof(Elf64_Shdr), 1, asm_ctx->output) != 1)
    {
        free(symbol_name_offsets);
        return false;
    }

    // 2. Section headers for actual sections
    uint64_t file_offset = section_data_offset;
    
    // String table offsets: \0.text\0.data\0.bss\0.symtab\0.strtab\0.shstrtab\0.rela.text\0.rela.data\0
    //                       0 1     7 13   18 26     34 44        55
    uint32_t text_name_offset = 1;      // ".text"
    uint32_t data_name_offset = 7;      // ".data"
    uint32_t bss_name_offset = 13;      // ".bss"
    uint32_t symtab_name_offset = 18;   // ".symtab"
    uint32_t strtab_name_offset = 26;   // ".strtab"
    uint32_t shstrtab_name_offset = 34; // ".shstrtab"
    uint32_t rel_text_name_offset = 44; // ".rela.text"
    uint32_t rel_data_name_offset = 55; // ".rela.data"

    // Count local symbols for sh_info (index of first non-local symbol)
    int local_symbol_count = 2;         // Start with 2 for null symbol and FILE symbol
    sym = asm_ctx->symbols;
    while (sym)
    {
        if (!sym->global)
            local_symbol_count++;
        sym = sym->next;
    }

    // Write .text section header if it exists
    current = asm_ctx->sections;
    while (current)
    {
        if (current->type == SECTION_TEXT && current->size > 0)
        {
            Elf64_Shdr shdr = {0};
            shdr.sh_name = text_name_offset;
            shdr.sh_type = SHT_PROGBITS;
            shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
            shdr.sh_addr = 0;
            shdr.sh_offset = file_offset;
            shdr.sh_size = current->size;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = 1;
            shdr.sh_entsize = 0;

            if (fwrite(&shdr, sizeof(Elf64_Shdr), 1, asm_ctx->output) != 1)
                return false;

            file_offset += current->size;
            break;
        }
        current = current->next;
    }

    // Write .data section header if it exists
    current = asm_ctx->sections;
    while (current)
    {
        if (current->type == SECTION_DATA && current->size > 0)
        {
            Elf64_Shdr shdr = {0};
            shdr.sh_name = data_name_offset;
            shdr.sh_type = SHT_PROGBITS;
            shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
            shdr.sh_addr = 0;
            shdr.sh_offset = file_offset;
            shdr.sh_size = current->size;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = 1;
            shdr.sh_entsize = 0;

            if (fwrite(&shdr, sizeof(Elf64_Shdr), 1, asm_ctx->output) != 1)
                return false;

            file_offset += current->size;
            break;
        }
        current = current->next;
    }

    // Write .bss section header if it exists (no file data)
    current = asm_ctx->sections;
    while (current)
    {
        if (current->type == SECTION_BSS && current->size > 0)
        {
            Elf64_Shdr shdr = {0};
            shdr.sh_name = bss_name_offset;
            shdr.sh_type = SHT_NOBITS;
            shdr.sh_flags = SHF_ALLOC | SHF_WRITE;
            shdr.sh_addr = 0;
            shdr.sh_offset = 0; // No file data
            shdr.sh_size = current->size;
            shdr.sh_link = 0;
            shdr.sh_info = 0;
            shdr.sh_addralign = 1;
            shdr.sh_entsize = 0;

            if (fwrite(&shdr, sizeof(Elf64_Shdr), 1, asm_ctx->output) != 1)
                return false;
            break;
        }
        current = current->next;
    }

    // Calculate actual section indices
    // Layout: null(0), .text(1), .data(2), .bss(3), .symtab(4), .strtab(5), .rel.text(?), .rel.data(?), .shstrtab(last)
    int next_section_index = 1; // Start after null section
    int text_section_index = -1, data_section_index = -1, bss_section_index = -1;
    int symtab_section_index = -1, strtab_section_index = -1;

    // Assign indices for regular sections
    current = asm_ctx->sections;
    while (current)
    {
        if (current->size > 0)
        {
            if (current->type == SECTION_TEXT)
                text_section_index = next_section_index++;
            else if (current->type == SECTION_DATA)
                data_section_index = next_section_index++;
            else if (current->type == SECTION_BSS)
                bss_section_index = next_section_index++;
        }
        current = current->next;
    }

    // Assign indices for special sections
    symtab_section_index = next_section_index++;
    strtab_section_index = next_section_index++;

    // Relocation sections come next
    int rel_text_section_index = -1, rel_data_section_index = -1;
    if (text_relocations > 0)
        rel_text_section_index = next_section_index++;
    if (data_relocations > 0)
        rel_data_section_index = next_section_index++;
    
    // .shstrtab is last
    int shstrtab_section_index = next_section_index;

    // Update the ELF header with the correct shstrndx
    long current_position = ftell(asm_ctx->output);
    fseek(asm_ctx->output, ehdr_position + offsetof(Elf64_Ehdr, e_shstrndx), SEEK_SET);
    uint16_t shstrndx = (uint16_t)shstrtab_section_index;
    fwrite(&shstrndx, sizeof(uint16_t), 1, asm_ctx->output);
    fseek(asm_ctx->output, current_position, SEEK_SET);

    // Write .symtab section header
    Elf64_Shdr symtab_shdr = {0};
    symtab_shdr.sh_name = symtab_name_offset;
    symtab_shdr.sh_type = SHT_SYMTAB;
    symtab_shdr.sh_flags = 0;
    symtab_shdr.sh_addr = 0;
    symtab_shdr.sh_offset = symtab_offset;
    symtab_shdr.sh_size = symtab_size;
    symtab_shdr.sh_link = strtab_section_index; // Index of .strtab section
    symtab_shdr.sh_info = local_symbol_count;   // Index of first non-local symbol
    symtab_shdr.sh_addralign = 8; // 8-byte alignment for 64-bit
    symtab_shdr.sh_entsize = sizeof(Elf64_Sym);

    if (fwrite(&symtab_shdr, sizeof(Elf64_Shdr), 1, asm_ctx->output) != 1)
    {
        free(symbol_name_offsets);
        return false;
    }

    // Write .strtab section header
    Elf64_Shdr strtab_shdr = {0};
    strtab_shdr.sh_name = strtab_name_offset;
    strtab_shdr.sh_type = SHT_STRTAB;
    strtab_shdr.sh_flags = 0;
    strtab_shdr.sh_addr = 0;
    strtab_shdr.sh_offset = strtab_file_offset;
    strtab_shdr.sh_size = strtab_size;
    strtab_shdr.sh_link = 0;
    strtab_shdr.sh_info = 0;
    strtab_shdr.sh_addralign = 1;
    strtab_shdr.sh_entsize = 0;

    if (fwrite(&strtab_shdr, sizeof(Elf64_Shdr), 1, asm_ctx->output) != 1)
    {
        free(symbol_name_offsets);
        return false;
    }

    // Write relocation section headers
    if (text_relocations > 0 && text_section_index >= 0)
    {
        Elf64_Shdr rel_text_shdr = {0};
        rel_text_shdr.sh_name = rel_text_name_offset;
        rel_text_shdr.sh_type = SHT_RELA;
        rel_text_shdr.sh_flags = 0;
        rel_text_shdr.sh_addr = 0;
        rel_text_shdr.sh_offset = rel_text_offset;
        rel_text_shdr.sh_size = rel_text_size;
        rel_text_shdr.sh_link = symtab_section_index; // Index of .symtab section
        rel_text_shdr.sh_info = text_section_index;   // Index of .text section being relocated
        rel_text_shdr.sh_addralign = 8; // 8-byte alignment for 64-bit
        rel_text_shdr.sh_entsize = sizeof(Elf64_Rela);

        if (fwrite(&rel_text_shdr, sizeof(Elf64_Shdr), 1, asm_ctx->output) != 1)
        {
            free(symbol_name_offsets);
            return false;
        }
    }

    if (data_relocations > 0 && data_section_index >= 0)
    {
        Elf64_Shdr rel_data_shdr = {0};
        rel_data_shdr.sh_name = rel_data_name_offset;
        rel_data_shdr.sh_type = SHT_RELA;
        rel_data_shdr.sh_flags = 0;
        rel_data_shdr.sh_addr = 0;
        rel_data_shdr.sh_offset = rel_data_offset;
        rel_data_shdr.sh_size = rel_data_size;
        rel_data_shdr.sh_link = symtab_section_index; // Index of .symtab section
        rel_data_shdr.sh_info = data_section_index;   // Index of .data section being relocated
        rel_data_shdr.sh_addralign = 8; // 8-byte alignment for 64-bit
        rel_data_shdr.sh_entsize = sizeof(Elf64_Rela);

        if (fwrite(&rel_data_shdr, sizeof(Elf64_Shdr), 1, asm_ctx->output) != 1)
        {
            free(symbol_name_offsets);
            return false;
        }
    }

    // Write .shstrtab section header (last section)
    Elf64_Shdr shstrtab_shdr = {0};
    shstrtab_shdr.sh_name = shstrtab_name_offset;
    shstrtab_shdr.sh_type = SHT_STRTAB;
    shstrtab_shdr.sh_flags = 0;
    shstrtab_shdr.sh_addr = 0;
    shstrtab_shdr.sh_offset = shstrtab_offset;
    shstrtab_shdr.sh_size = shstrtab_size;
    shstrtab_shdr.sh_link = 0;
    shstrtab_shdr.sh_info = 0;
    shstrtab_shdr.sh_addralign = 1;
    shstrtab_shdr.sh_entsize = 0;

    if (fwrite(&shstrtab_shdr, sizeof(Elf64_Shdr), 1, asm_ctx->output) != 1)
    {
        free(symbol_name_offsets);
        return false;
    }

    // Clean up
    free(symbol_name_offsets);
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
    FILE *file = fopen(filename, "rb"); // Use binary mode to avoid Windows text mode issues
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

    size_t bytes_read = fread(content, 1, length, file);
    content[bytes_read] = '\0'; // Use actual bytes read instead of length
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
    }
    asm_ctx->pass = pass;
    bool success = true;
    instruction_t instruction; // Reset address tracking for each pass
    asm_ctx->current_address = asm_ctx->origin;

    // Reset section sizes for each pass
    section_t *current_section = asm_ctx->sections;
    while (current_section)
    {
        current_section->size = 0;
        current_section = current_section->next;
    }    if (pass >= 2)
    {
        codegen_reset(asm_ctx); // Reset code buffer for all code generation passes
    }
    
    int line_count = 0;
    int processed_lines = 0;
    
    // Count total lines for progress display (if verbose)
    if (asm_ctx->verbose) {
        const char *temp = input_content;
        while (*temp) {
            if (*temp == '\n') line_count++;
            temp++;
        }
        if (line_count == 0) line_count = 1; // At least one line
        
        show_pass_progress("initializing", 0, line_count, "parsing source");
        usleep(100000); // 100ms delay
        
        if (pass >= 2)
        {
            symbol_table_dump(asm_ctx);
        }
    }    // Process all lines
    while (true)
    {
        bool parsed = parser_parse_line(parser, &instruction);
        if (!parsed)
        {
            break; // no more lines or reached EOF, or parsing error occurred
        }
        
        processed_lines++;
        
        // Show progress every few lines for smooth animation
        if (asm_ctx->verbose && processed_lines % 5 == 0) {
            show_pass_progress("processing", processed_lines, line_count, 
                             pass == 1 ? "calculating sizes" : "generating code");
            usleep(15000); // 15ms delay
        }

        // Check if an error occurred during parsing
        if (asm_ctx->error_occurred)
        {
            success = false;
            break;
        }// Process instructions - calculate sizes in all passes, generate code in pass 2+
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
    } // Cleanup
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
    // Store input filename in assembler context
    asm_ctx->input_filename = (char *)input_file;

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

    // Show assembler startup
    if (asm_ctx->verbose) {
        printf("\n\033[1;35m+- NAS Assembly Engine -----------------------------------------------+\033[0m\n");
        printf("\033[1;35m|\033[0m \033[36mInitializing multi-pass assembler...\033[0m                           \033[1;35m|\033[0m\n");
        printf("\033[1;35m+-----------------------------------------------------------------+\033[0m\n\n");
        printf("\033[1;32m*\033[0m Input file: \033[33m%s\033[0m\n", input_file);
        printf("\033[1;32m*\033[0m Output file: \033[33m%s\033[0m\n", output_file);
        if (asm_ctx->mode == MODE_16BIT)
        {
            printf("\033[1;32m*\033[0m Mode: \033[33m16-bit\033[0m\n");
        }
        else if (asm_ctx->mode == MODE_32BIT)
        {
            printf("\033[1;32m*\033[0m Mode: \033[33m32-bit\033[0m\n");
        }
        else if (asm_ctx->mode == MODE_64BIT)
        {
            printf("\033[1;32m*\033[0m Mode: \033[33m64-bit\033[0m\n");
        }
        else
        {
            printf("\033[1;32m*\033[0m Mode: \033[33mUnknown\033[0m\n");
        }
        printf("\033[1;32m*\033[0m Format: \033[33m%s\033[0m\n\n", 
               asm_ctx->format == FORMAT_BIN ? "binary" : 
               (asm_ctx->format == FORMAT_HEX ? "hex" : "elf"));
    }

    // Iterative multi-pass assembly: continue until instruction sizes stabilize
    do
    {
        asm_ctx->sizes_changed = false;

        if (asm_ctx->verbose)
        {
            printf("\033[1;34mO Phase %d:\033[0m %s\n", pass, 
                   pass == 1 ? "Symbol discovery and size calculation" :
                   pass == 2 ? "Code generation and symbol resolution" :
                   "Address convergence and refinement");
        }        if (!assembler_pass(asm_ctx, input_content, pass))
        {
            success = false;
            goto cleanup;
        }

        if (asm_ctx->verbose)
        {
            clear_line();
            const char* status_color = asm_ctx->sizes_changed ? "\033[33m" : "\033[32m";
            const char* status_text = asm_ctx->sizes_changed ? "SIZES CHANGED" : "CONVERGED";
            printf("\r\033[1;32m*\033[0m Pass %d complete - %s%s\033[0m\n", 
                   pass, status_color, status_text);
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
        }        // Continue if: this is the first pass through pass 2, OR the previous pass had size changes
    } while (pass == 2 || had_size_changes);

    if (asm_ctx->verbose) {
        printf("\n\033[1;34mO Final Phase:\033[0m Symbol validation and output generation\n");
        
        // Count symbols for display
        int symbol_count = 0, defined_count = 0, undefined_count = 0;
        symbol_t *sym = asm_ctx->symbols;
        while (sym) {
            symbol_count++;
            if (sym->defined) defined_count++;
            else undefined_count++;
            sym = sym->next;
        }
        
        printf("Validating %d symbols (%d defined, %d undefined)...\n", 
               symbol_count, defined_count, undefined_count);
    }

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
    asm_ctx->output = NULL;
    if (success && asm_ctx->verbose)
    {
        size_t total_size = section_get_total_size(asm_ctx);
        
        // Count symbols
        int symbol_count = 0, defined_count = 0;
        symbol_t *sym = asm_ctx->symbols;
        while (sym) {
            symbol_count++;
            if (sym->defined) defined_count++;
            sym = sym->next;
        }
        
        // Count sections
        int section_count = 0;
        section_t *sect = asm_ctx->sections;
        while (sect) {
            if (sect->size > 0) section_count++;
            sect = sect->next;
        }
        
        printf("\n\033[1;32m@ Assembly Summary:\033[0m\n");
        printf("   * \033[33m%d\033[0m passes completed\n", pass - 1);
        printf("   * \033[33m%d\033[0m symbols resolved\n", defined_count);
        printf("   * \033[33m%d\033[0m sections generated\n", section_count);
        printf("   * \033[33m%zu\033[0m bytes written\n", total_size);
        printf("   * Output format: \033[33m%s\033[0m\n", 
               asm_ctx->format == FORMAT_BIN ? "binary" : 
               (asm_ctx->format == FORMAT_HEX ? "hex" : "elf"));
        printf("\n\033[1;32m*\033[0m Assembly completed successfully!\n\n");
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
        return false; // Add to linked list
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

    section_t *section = section_find(asm_ctx, name);
    if (!section)
        return false;

    asm_ctx->current_section_ptr = section;

    // During assembly, use section-relative addresses
    // The current_address should be the section's base address plus current size
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

bool symbol_mark_global(assembler_t *asm_ctx, const char *name)
{
    if (!asm_ctx || !name)
        return false;

    symbol_t *symbol = symbol_lookup(asm_ctx, name);
    if (!symbol)
    {
        // Create undefined symbol and mark as global
        if (!symbol_reference(asm_ctx, name))
            return false;
        symbol = symbol_lookup(asm_ctx, name);
    }

    if (symbol)
    {
        symbol->global = true;
        return true;
    }

    return false;
}

bool symbol_mark_external(assembler_t *asm_ctx, const char *name)
{
    if (!asm_ctx || !name)
        return false;

    symbol_t *symbol = symbol_lookup(asm_ctx, name);
    if (!symbol)
    {
        // Create undefined external symbol
        if (!symbol_reference(asm_ctx, name))
            return false;
        symbol = symbol_lookup(asm_ctx, name);
    }

    if (symbol)
    {
        symbol->external = true;
        symbol->global = true; // External symbols are also global
        return true;
    }

    return false;
}

// Relocation management functions
void relocation_add(assembler_t *asm_ctx, uint32_t offset, const char *symbol_name, int relocation_type, section_type_t section, int64_t addend)
{
    if (!asm_ctx || !symbol_name)
        return;

    // Check for duplicate relocations
    relocation_t *existing = asm_ctx->relocations;
    while (existing)
    {
        if (existing->offset == offset &&
            existing->section == section &&
            existing->relocation_type == relocation_type &&
            strcmp(existing->symbol_name, symbol_name) == 0)
        {
            if (asm_ctx->verbose)
            {
                printf("DEBUG: Duplicate relocation detected, skipping: offset=0x%X, symbol='%s', type=%d, section=%d\n",
                       offset, symbol_name, relocation_type, section);
            }
            return; // Don't add duplicate
        }
        existing = existing->next;
    }

    relocation_t *reloc = malloc(sizeof(relocation_t));
    if (!reloc)
        return;

    reloc->offset = offset;
    strncpy(reloc->symbol_name, symbol_name, MAX_LABEL_LENGTH - 1);
    reloc->symbol_name[MAX_LABEL_LENGTH - 1] = '\0';
    reloc->relocation_type = relocation_type;
    reloc->addend = addend;
    reloc->section = section;
    reloc->next = asm_ctx->relocations;
    asm_ctx->relocations = reloc;

    if (asm_ctx->verbose)
    {
        printf("DEBUG: Added relocation: offset=0x%X, symbol='%s', type=%d, section=%d, addend=%lld\n",
               offset, symbol_name, relocation_type, section, (long long)addend);
    }
}

void relocation_table_destroy(relocation_t *relocations)
{
    while (relocations)
    {
        relocation_t *next = relocations->next;
        free(relocations);
        relocations = next;
    }
}
