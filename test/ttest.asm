#width 16
#origin 0x7C00

jmp main

main:
    xor ah, ah
    mov al, 0x13
    int 0x10

    mov ah, 0x0e
    xor bh, bh
    mov bl, 7
    mov si, string

writeTxt:
    lodsb
    cmp al, 0
    je end
    int 0x10
    jmp writeTxt

end:
    jmp end

string: #db "Hello", 0
#times (510 - $) #db 0
#dw 0xAA55