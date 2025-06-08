#width 16
#origin 0x7C00  ; Bootloader address (example)

_start:
    ; Set up GDT
    cli                     ; Disable interrupts
    lgdt [gdt_descriptor]   ; Load GDT

    ; Enable protected mode
    mov eax, cr0
    or eax, 1               ; Set PE bit
    mov cr0, eax

    ; Far jump to protected mode
    jmp 0x08:protected_mode_start  ; 0x08 is the code segment selector

; GDT definition
gdt_start:
    #dw 0x0000, 0x0000       ; Null descriptor
    #dw 0xFFFF, 0x0000       ; Code segment descriptor
    #db 0x00, 0x9A, 0xCF, 0x00
    #dw 0xFFFF, 0x0000       ; Data segment descriptor
    #db 0x00, 0x92, 0xCF, 0x00
gdt_end:

gdt_descriptor:
    #dw gdt_end - gdt_start - 1  ; Limit
    #dd gdt_start                ; Base address

#width 32
protected_mode_start:
    ; Set up segment registers
    mov ax, 0x10           ; Data segment selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    hlt                    ; Halt the CPU