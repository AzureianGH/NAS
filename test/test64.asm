#width 64

mov rax, rbx
mov r8, r15
add rsp, 8
push r9
pop r10

movsq
stosq

mov eax, r8d
mov al, r9b
mov ax, r10w

inc rax
dec rbp
xor r11, r12
cmp r13, r14
