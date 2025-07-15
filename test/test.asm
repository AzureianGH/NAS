#width 64
#extend printf
#global main

#section .text
main:                      
    push    rbp    
    mov     rbp, rsp       
    
    sub     rsp, 8
    
    lea     rdi, [fmt]
    lea     rsi, [msg]
    mov     rax, 0
    call    printf

    add     rsp, 8
    pop     rbp

    mov     rax, 0
    ret


msg:
    #db "Hello, world!", 0
fmt:
    #db "%s", 0x0A, 0 