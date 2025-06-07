#width 16
#origin 0x7C00

_kernel_tick: 
    #dw 0x0000

start:
    ; Test basic 16-bit instructions that should work
    mov ax, bx
    add ax, 1000
    
    ; Test problematic instructions mentioned by user
    cmp word [cs:_kernel_tick], 1000
    
    ; More advanced 16-bit features
    mov word [ds:0x1000], 0x5678
    add word [es:si+4], 100
    sub byte [ss:bp-2], 50
    
    ; Test various segment overrides
    mov al, [cs:0x100]
    mov [ds:bx], al
    mov word [es:di+2], 0x1234
    
    ; Test memory addressing modes
    mov ax, [bx+si]
    mov [bp+di+8], cx
    add word [bx], 500
    
    ; Test more complex operations
    cmp word [ds:0x2000], 0x8000
    test byte [cs:start], 0xFF
    inc word [ds:bx+si+10]
    
    hlt
