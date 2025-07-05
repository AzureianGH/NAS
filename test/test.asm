#width 64

_start:
    push rbp
    mov rbp, rsp
    mov rax, 1
    add rax, 2

    and rax, 0xFFFF
    cmp rax, 3
    jne _error
    mov rax, 0x1234

    mov rbp, rsp
    pop rbp
    ret

_error:
    mov rax, 0x5678
    ret