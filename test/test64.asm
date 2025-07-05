#width 64

mov rax, rbx        ; 64-bit register move
mov r8, r15         ; Extended registers
add rsp, 8          ; 64-bit stack pointer
push r9             ; Push 64-bit extended register
pop r10             ; Pop to extended register

; 64-bit string operations
movsq               ; 64-bit string move
stosq               ; 64-bit string store

; Mixed register sizes
mov eax, r8d        ; 32-bit parts of 64-bit registers
mov al, r9b         ; 8-bit parts of extended registers
mov ax, r10w        ; 16-bit parts of extended registers

; Instructions that should work in 64-bit mode
inc rax
dec rbp
xor r11, r12
cmp r13, r14
