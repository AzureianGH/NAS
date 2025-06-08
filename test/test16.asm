_softReset:
    ; Naked function - no prologue generated
    ; Inline assembly statement
    cli
    ; Inline assembly statement
    mov al, 0xFE
    ; Inline assembly statement
    out 0x64, al
    ; Inline assembly statement
    hlt
    ; Inline assembly statement
    jmp $