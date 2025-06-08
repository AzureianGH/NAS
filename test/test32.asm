#width 32

_start:
    ; linux syscall for read input
    mov eax, 3          ; syscall number for sys_read
    mov ebx, 0          ; file descriptor 0 (stdin)
    mov ecx, buffer     ; pointer to the buffer
    mov edx, 128        ; maximum number of bytes to read
    int 0x80            ; call kernel

    ; linux syscall for print string
    mov eax, 4          ; syscall number for sys_write
    mov ebx, 1          ; file descriptor 1 (stdout)
    mov ecx, hello      ; pointer to the hello message
    int 0x80            ; call kernel


    ; linux syscall for print string
    mov eax, 4          ; syscall number for sys_write
    mov ebx, 1          ; file descriptor 1 (stdout)
    mov ecx, buffer     ; pointer to the buffer
    int 0x80            ; call kernel

    ; exit syscall
    mov eax, 1          ; syscall number for sys_exit
    xor ebx, ebx        ; exit code 0
    int 0x80            ; call kernel