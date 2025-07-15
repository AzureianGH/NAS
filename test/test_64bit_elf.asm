#width 64
#global main
#section .text
#extend exit
main:
    xor rdi, rdi
    mov edi, 123
    call exit