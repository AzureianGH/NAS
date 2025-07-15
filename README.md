# NAS (Nathan's Assembler)

A feature-rich x86 assembler written in C that supports 16-bit, 32-bit, and 64-bit assembly programming. NAS is designed to generate efficient machine code for bootloaders, operating systems, and low-level programming projects.

## Features

### Core Assembly Support
- **Multi-mode support**: 16-bit, 32-bit, and 64-bit x86 assembly
- **Two-pass assembler**: Resolves forward references and optimizes code generation
- **Multiple output formats**: Binary and Intel HEX
- **Cross-platform**: Windows and Linux compatible

### Instruction Set
NAS supports a comprehensive x86 instruction set including:

#### Data Movement
- `mov`, `push`, `pop`, `xchg`, `lea`
- Register-to-register, register-to-memory, immediate-to-register operations
- Segment override prefixes (`cs:`, `ds:`, `es:`, `ss:`)

#### Arithmetic & Logic
- Basic arithmetic: `add`, `sub`, `mul`, `imul`, `div`, `idiv`
- Logical operations: `and`, `or`, `xor`, `not`, `neg`
- Comparison: `cmp`, `test`
- Increment/decrement: `inc`, `dec`
- With carry: `adc`, `sbb`

#### Bit Manipulation & Shifts
- Shift operations: `shl`, `shr`, `sal`, `sar`
- Rotate operations: `rol`, `ror`, `rcl`, `rcr`
- Supports shift by 1, CL register, or immediate values

#### Control Flow
- Unconditional jumps: `jmp`, `call`, `ret`
- Conditional jumps: All x86 conditional jumps (`je`, `jne`, `jz`, `jnz`, `jc`, `jnc`, `ja`, `jb`, etc.)
- Loop instructions: `loop`, `loope`, `loopne`, `jcxz`

#### String Operations
- Basic string ops: `movsb`, `movsw`, `cmpsb`, `cmpsw`, `scasb`, `scasw`, `lodsb`, `lodsw`, `stosb`, `stosw`
- REP prefixes: `rep`, `repe`, `repne`, `repz`, `repnz`
- Combined REP+string operations: `rep_movsb`, `rep_stosw`, etc.

#### System & I/O
- Interrupt handling: `int`, `int3`, `into`, `iret`
- I/O operations: `in`, `out` (with immediate ports or DX register)
- System control: `cli`, `sti`, `hlt`, `nop`, `wait`
- Flag operations: `clc`, `stc`, `cmc`, `cld`, `std`, `lahf`, `sahf`, `pushf`, `popf`

#### Stack Operations
- Individual register push/pop
- Push all/pop all: `pusha`, `popa`
- Push immediate values

#### BCD & ASCII Arithmetic
- BCD adjust: `daa`, `das`
- ASCII adjust: `aaa`, `aas`, `aam`, `aad`

### Memory Addressing Modes
NAS supports all x86 16-bit addressing modes:
- Direct addressing: `[0x1000]`, `[label]`
- Register indirect: `[bx]`, `[si]`, `[di]`, `[bp]`
- Base + displacement: `[bx+4]`, `[bp-2]`
- Base + index: `[bx+si]`, `[bp+di]`
- Base + index + displacement: `[bx+si+8]`, `[bp+di-4]`
- Segment overrides: `[cs:0x100]`, `[ds:bx]`, `[es:si+4]`

### Size Specifiers
- Explicit size specification: `byte [address]`, `word [address]`
- Automatic size detection based on operands
- Mixed 8-bit and 16-bit operations

### Assembler Directives
- `#width 16|32` - Set assembly mode (16-bit or 32-bit)
- `#origin address` - Set origin address (e.g., `#origin 0x7C00`)
- `#db value[,value...]` - Define bytes
- `#dw value[,value...]` - Define words
- `#times count #db/#dw value` - Repeat data definitions
- `#define symbol value` - Define symbolic constants

### Labels & Symbols
- Forward and backward label references
- Symbol table with address resolution
- Automatic label-to-address conversion
- Support for label-based memory addressing

## Installation

### Prerequisites
- GCC or compatible C compiler
- Make (for building)
- QEMU (optional, for testing bootable images)

### Building
```bash
git clone https://github.com/AzureianGH/nas.git
cd nas
make
```

The assembler will be built as `bin/nas`.

### Testing
```bash
# Assemble the test file
make test_asm

# Test with QEMU (if available)
make test_os
```

## Usage

### Basic Syntax
```bash
nas [options] input_file -o output_file
```

### Options
- `-m, --mode <16|32>` - Assembly mode (default: 16)
- `-f, --format <bin|hex>` - Output format (default: bin)
- `-o, --output <file>` - Output file (required)
- `-v, --verbose` - Verbose output for debugging
- `-h, --help` - Show help message
- `--version` - Show version information

### Examples

#### Basic 16-bit Assembly
```bash
nas -m16 -f bin bootloader.asm -o bootloader.bin
```

#### Intel HEX Output
```bash
nas --mode 16 --format hex program.asm -o program.hex
```

#### Verbose Assembly
```bash
nas -v -m16 test.asm -o test.bin
```

## Assembly Language Syntax

### Basic Program Structure
```asm
#width 16
#origin 0x7C00

start:
    mov ax, 0x1000
    mov ds, ax
    
    mov si, hello_msg
    call print_string
    
    hlt

hello_msg:
    #db "Hello, World!", 0

print_string:
    ; Print string function
    mov ah, 0x0E
.loop:
    lodsb
    test al, al
    jz .done
    int 0x10
    jmp .loop
.done:
    ret
```

### Memory Operations
```asm
; Direct memory access
mov ax, [0x1000]
mov word [0x2000], 0x1234

; Segment overrides
mov al, [cs:0x100]
mov [ds:bx], al
mov word [es:di+2], 0x5678

; Complex addressing
mov ax, [bx+si]
mov [bp+di+8], cx
add word [bx+4], 100
```

### Data Definitions
```asm
; Single values
byte_val: #db 0x42
word_val: #dw 0x1234

; Multiple values
array: #db 1, 2, 3, 4, 5
message: #db "Hello", 13, 10, 0

; Repeated data
buffer: #times 512 #db 0
stack: #times 256 #dw 0
```

## Output Formats

### Binary Format
Generates raw binary output suitable for:
- Bootloaders
- Embedded systems
- Direct memory loading

### Intel HEX Format
Generates Intel HEX format suitable for:
- EPROM programmers
- Debugging tools
- Development environments

## Error Handling

NAS provides comprehensive error reporting including:
- Syntax errors with line numbers
- Undefined symbol references
- Invalid instruction operands
- Addressing mode conflicts
- Value range violations

### Verbose Mode
Use `-v` flag for detailed assembly information:
- Pass-by-pass assembly progress
- Symbol table contents
- Address calculations
- Opcode generation details

## Compatibility

### x86 Compatibility
- Intel 8086/8088 instruction set
- Intel 80186/80188 extensions
- Selected 80386 features (immediate shifts)

### Platform Support
- **Windows**: Native compilation with MinGW
- **Linux**: GCC compilation
- **Cross-platform**: Consistent behavior across platforms

## Development

### Project Structure
```
nas/
├── include/           # Header files
│   ├── nas.h         # Main definitions
│   ├── lexer.h       # Lexical analyzer
│   ├── parser.h      # Parser definitions
│   ├── instruction_set.h  # Instruction definitions
│   ├── codegen.h     # Code generation
│   └── assembler.h   # Assembler context
├── src/              # Source files
│   ├── main.c        # Entry point
│   ├── lexer.c       # Lexical analysis
│   ├── parser.c      # Parsing logic
│   ├── instruction_set.c  # Instruction encoding
│   ├── codegen.c     # Code generation
│   └── assembler.c   # Assembly coordination
├── test/             # Test files
│   └── test.asm      # Example assembly
├── Makefile          # Build configuration
└── README.md         # This file
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

NAS is free software distributed under the terms specified in the source code. See individual source files for detailed copyright information.

## Version Information

Current version: 3.00
- Windows build: `nas-win-x64` || `nas-win-x86`
- Linux build: `nas-linux-x64` || `nas-linux-x86`

For version information, run:
```bash
nas --version
```

## Examples

See the `test/` directory for example assembly programs demonstrating various features of the assembler.
