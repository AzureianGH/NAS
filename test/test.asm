#width 64
#extend printf
#global nas_print

#section .text
nas_print: ; C CODE: void nas_print(char* msg)        
    push rbp    
    mov rbp, rsp       

    mov rsi, rdi ; msg
    lea rdi, [fmt]

    mov rax, 0
    call printf
    pop rbp
    ret

fmt:
    #db "%s", 0x0A, 0 