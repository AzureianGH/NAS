#width 64

; Test basic 64-bit register moves
xor al, al
mov rax, 0x1234567890ABCDEF
mov rbx, rax
mov rcx, r8
mov r9, r10

; Test REX prefix combinations
mov r8b, al     ; REX.R + 8-bit
mov r9w, bx     ; REX.R + 16-bit  
mov r10d, ecx   ; REX.R + 32-bit
mov r11, rdx    ; REX.W + REX.R + 64-bit

; Test 64-bit string operations  
movsb
movsw
movsd
movsq