#section .data
format_string:
    #db "%d\n", 0  ;Format string for printf, null-terminated

#section .text
#global main
#extend getpid
#extend exit
#extend printf

main:
    push ebp
    mov ebp, esp

    ;Call getpid to get the process ID
    call getpid
    mov ebx, eax  ;Store the process ID in ebx

    ;Prepare the format string for printf
    push ebx
    push format_string
    call printf
    add esp, 8  ;Clean up the stack

    ;Exit the program
    push 0
    call exit
    