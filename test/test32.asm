#section .text
#global main
#extend exit
main:
    push dword 123
    call exit
    add esp, 4