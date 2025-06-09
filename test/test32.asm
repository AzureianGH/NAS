#section .text
#global main
#extend exit
main:
    push 0xAF
    call exit
    add esp, 4