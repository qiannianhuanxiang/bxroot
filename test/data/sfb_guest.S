// ET_EXEC 静态 guest：号经寄存器搬运的 openat（改写器默认不改的一类）
    .text
    .global _start
_start:
    mov  x0, #-100
    adrp x1, path
    add  x1, x1, :lo12:path
    mov  x2, #0
    mov  x3, #0
    mov  x6, #56
    mov  x8, x6
    svc  #0
    cmp  x0, #0
    b.lt fail
    adrp x1, buf
    add  x1, x1, :lo12:buf
    mov  x2, #64
    mov  x8, #63
    svc  #0
    mov  x2, x0
    mov  x0, #1
    adrp x1, buf
    add  x1, x1, :lo12:buf
    mov  x8, #64
    svc  #0
    mov  x0, #0
    mov  x8, #94
    svc  #0
fail:
    neg  x0, x0
    mov  x8, #94
    svc  #0
    .section .rodata
path: .asciz "/bxtest/hello"
    .data
buf: .space 64
