	.file	"main.c"
	.text
.Ltext0:
	.file 1 "/home/boricj/Documents/ghidra-delinker-extension/src/test/resources/ascii-table/src/main.c"
#APP
	.section .text.nolibc_memmove_memcpy
.weak memmove
.weak memcpy
memmove:
memcpy:
movq %rdx, %rcx
	movq %rdi, %rax
	movq %rdi, %rdx
	subq %rsi, %rdx
	cmpq %rcx, %rdx
	jb   1f
	rep movsb
	retq
1:leaq -1(%rdi, %rcx, 1), %rdi
	leaq -1(%rsi, %rcx, 1), %rsi
	std
	rep movsb
	cld
	retq
.section .text.nolibc_memset
.weak memset
memset:
xchgl %eax, %esi
	movq  %rdx, %rcx
	pushq %rdi
	rep stosb
	popq  %rax
	retq

#NO_APP
	.type	sys_exit, @function
sys_exit:
.LVL0:
.LFB24:
	.file 2 "/home/boricj/Documents/linux/tools/include/nolibc/sys.h"
	.loc 2 297 1 view -0
	.cfi_startproc
	.loc 2 298 2 view .LVU1
.LBB2:
	.loc 2 298 2 view .LVU2
	.loc 2 298 2 view .LVU3
	movl	$60, %eax
	.loc 2 298 2 view .LVU4
	movzbl	%dil, %edi
.LVL1:
	.loc 2 298 2 view .LVU5
#APP
# 298 "/home/boricj/Documents/linux/tools/include/nolibc/sys.h" 1
	syscall

# 0 "" 2
.LVL2:
	.loc 2 298 2 view .LVU6
#NO_APP
	.p2align 1
.L2:
.LBE2:
	.loc 2 299 2 view .LVU7
	.loc 2 299 7 view .LVU8
	jmp	.L2
	.cfi_endproc
.LFE24:
	.size	sys_exit, .-sys_exit
	.type	_exit, @function
_exit:
.LVL3:
.LFB25:
	.loc 2 304 1 view -0
	.cfi_startproc
	.loc 2 305 2 view .LVU10
	call	sys_exit
.LVL4:
	.loc 2 305 2 is_stmt 0 view .LVU11
	.cfi_endproc
.LFE25:
	.size	_exit, .-_exit
	.type	exit, @function
exit:
.LVL5:
.LFB26:
	.loc 2 310 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 2 311 2 view .LVU13
	call	_exit
.LVL6:
	.loc 2 311 2 is_stmt 0 view .LVU14
	.cfi_endproc
.LFE26:
	.size	exit, .-exit
	.type	sys_getpid, @function
sys_getpid:
.LFB39:
	.loc 2 439 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 2 440 2 view .LVU16
.LBB3:
	.loc 2 440 9 view .LVU17
	.loc 2 440 9 view .LVU18
	movl	$39, %eax
	.loc 2 440 9 view .LVU19
#APP
# 440 "/home/boricj/Documents/linux/tools/include/nolibc/sys.h" 1
	syscall

# 0 "" 2
.LVL7:
	.loc 2 440 9 view .LVU20
#NO_APP
.LBE3:
	.loc 2 441 1 is_stmt 0 view .LVU21
	ret
	.cfi_endproc
.LFE39:
	.size	sys_getpid, .-sys_getpid
	.type	sys_kill, @function
sys_kill:
.LVL8:
.LFB48:
	.loc 2 523 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 2 524 2 view .LVU23
.LBB4:
	.loc 2 524 9 view .LVU24
	.loc 2 524 9 view .LVU25
	movl	$62, %eax
	.loc 2 524 9 view .LVU26
	movslq	%edi, %rdi
	.loc 2 524 9 view .LVU27
	movslq	%esi, %rsi
	.loc 2 524 9 view .LVU28
#APP
# 524 "/home/boricj/Documents/linux/tools/include/nolibc/sys.h" 1
	syscall

# 0 "" 2
.LVL9:
	.loc 2 524 9 view .LVU29
#NO_APP
.LBE4:
	.loc 2 525 1 is_stmt 0 view .LVU30
	ret
	.cfi_endproc
.LFE48:
	.size	sys_kill, .-sys_kill
	.type	sys_write, @function
sys_write:
.LVL10:
.LFB85:
	.loc 2 925 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 2 926 2 view .LVU32
.LBB5:
	.loc 2 926 9 view .LVU33
	.loc 2 926 9 view .LVU34
	movl	$1, %eax
	.loc 2 926 9 view .LVU35
	movslq	%edi, %rdi
	.loc 2 926 9 view .LVU36
	.loc 2 926 9 view .LVU37
	.loc 2 926 9 view .LVU38
#APP
# 926 "/home/boricj/Documents/linux/tools/include/nolibc/sys.h" 1
	syscall

# 0 "" 2
.LVL11:
	.loc 2 926 9 view .LVU39
#NO_APP
.LBE5:
	.loc 2 927 1 is_stmt 0 view .LVU40
	ret
	.cfi_endproc
.LFE85:
	.size	sys_write, .-sys_write
	.type	write, @function
write:
.LVL12:
.LFB86:
	.loc 2 931 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 2 932 2 view .LVU42
.LBB6:
	.loc 2 932 9 view .LVU43
	call	sys_write
.LVL13:
	.loc 2 932 9 discriminator 1 view .LVU44
	testq	%rax, %rax
	js	.L10
.L8:
.LBE6:
	.loc 2 933 1 is_stmt 0 view .LVU45
	ret
.L10:
.LBB7:
	.loc 2 932 9 is_stmt 1 discriminator 1 view .LVU46
	negl	%eax
.LVL14:
	.loc 2 932 9 is_stmt 0 discriminator 1 view .LVU47
	movl	%eax, errno(%rip)
	.loc 2 932 9 is_stmt 1 view .LVU48
	.loc 2 932 9 is_stmt 0 discriminator 1 view .LVU49
	movq	$-1, %rax
.LBE7:
	.loc 2 932 9 view .LVU50
	ret
	.cfi_endproc
.LFE86:
	.size	write, .-write
	.type	fileno, @function
fileno:
.LVL15:
.LFB215:
	.file 3 "/home/boricj/Documents/linux/tools/include/nolibc/stdio.h"
	.loc 3 88 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 3 89 2 view .LVU52
	.loc 3 91 2 view .LVU53
	.loc 3 91 5 is_stmt 0 view .LVU54
	testq	%rdi, %rdi
	jns	.L14
	.loc 3 95 2 is_stmt 1 view .LVU55
	.loc 3 95 9 is_stmt 0 view .LVU56
	movl	%edi, %eax
	notl	%eax
	.loc 3 96 1 view .LVU57
	ret
.L14:
	.loc 3 92 3 is_stmt 1 view .LVU58
	.loc 3 92 3 view .LVU59
	movl	$9, errno(%rip)
	.loc 3 92 3 view .LVU60
	.loc 3 93 3 view .LVU61
	.loc 3 93 10 is_stmt 0 view .LVU62
	movl	$-1, %eax
	ret
	.cfi_endproc
.LFE215:
	.size	fileno, .-fileno
	.type	fputc, @function
fputc:
.LVL16:
.LFB220:
	.loc 3 158 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 3 158 1 is_stmt 0 view .LVU64
	subq	$16, %rsp
	.cfi_def_cfa_offset 24
	movl	%edi, %eax
	movq	%rsi, %rdi
.LVL17:
	.loc 3 159 2 is_stmt 1 view .LVU65
	.loc 3 159 16 is_stmt 0 view .LVU66
	movb	%al, 15(%rsp)
	.loc 3 161 2 is_stmt 1 view .LVU67
	.loc 3 161 6 is_stmt 0 view .LVU68
	call	fileno
.LVL18:
	.loc 3 161 6 view .LVU69
	movl	%eax, %edi
	.loc 3 161 6 discriminator 1 view .LVU70
	leaq	15(%rsp), %rsi
	movl	$1, %edx
	call	write
.LVL19:
	.loc 3 161 5 discriminator 2 view .LVU71
	testq	%rax, %rax
	jle	.L17
	.loc 3 163 2 is_stmt 1 view .LVU72
	.loc 3 163 9 is_stmt 0 view .LVU73
	movzbl	15(%rsp), %eax
.L15:
	.loc 3 164 1 view .LVU74
	addq	$16, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	ret
.L17:
	.cfi_restore_state
	.loc 3 162 10 view .LVU75
	movl	$-1, %eax
	jmp	.L15
	.cfi_endproc
.LFE220:
	.size	fputc, .-fputc
	.type	putchar, @function
putchar:
.LVL20:
.LFB221:
	.loc 3 168 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 3 169 2 view .LVU77
	.loc 3 169 9 is_stmt 0 view .LVU78
	movq	$-2, %rsi
	call	fputc
.LVL21:
	.loc 3 170 1 view .LVU79
	ret
	.cfi_endproc
.LFE221:
	.size	putchar, .-putchar
	.weak	_start_c
	.type	_start_c, @function
_start_c:
.LVL22:
.LFB0:
	.file 4 "/home/boricj/Documents/linux/tools/include/nolibc/crt.h"
	.loc 4 34 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 4 34 1 is_stmt 0 view .LVU81
	pushq	%r13
	.cfi_def_cfa_offset 16
	.cfi_offset 13, -16
	pushq	%r12
	.cfi_def_cfa_offset 24
	.cfi_offset 12, -24
	pushq	%rbp
	.cfi_def_cfa_offset 32
	.cfi_offset 6, -32
	pushq	%rbx
	.cfi_def_cfa_offset 40
	.cfi_offset 3, -40
	subq	$8, %rsp
	.cfi_def_cfa_offset 48
	.loc 4 35 2 is_stmt 1 view .LVU82
	.loc 4 36 2 view .LVU83
	.loc 4 37 2 view .LVU84
	.loc 4 38 2 view .LVU85
	.loc 4 39 2 view .LVU86
	.loc 4 40 2 view .LVU87
	.loc 4 41 2 view .LVU88
	.loc 4 43 2 view .LVU89
	.loc 4 46 2 view .LVU90
	.loc 4 66 2 view .LVU91
	.loc 4 66 7 is_stmt 0 view .LVU92
	movq	(%rdi), %rbp
.LVL23:
	.loc 4 67 2 is_stmt 1 view .LVU93
	.loc 4 67 7 is_stmt 0 view .LVU94
	leaq	8(%rdi), %r13
.LVL24:
	.loc 4 70 2 is_stmt 1 view .LVU95
	.loc 4 70 17 is_stmt 0 view .LVU96
	leaq	16(%rdi,%rbp,8), %r12
.LVL25:
	.loc 4 70 10 view .LVU97
	movq	%r12, environ(%rip)
	.loc 4 73 2 is_stmt 1 view .LVU98
.LVL26:
	.loc 4 73 12 is_stmt 0 view .LVU99
	movq	%r12, %rax
.LVL27:
	.loc 4 73 12 view .LVU100
	.p2align 4
.L21:
	.loc 4 73 28 is_stmt 1 discriminator 2 view .LVU101
	movq	%rax, %rdx
	.loc 4 73 33 is_stmt 0 discriminator 2 view .LVU102
	addq	$8, %rax
.LVL28:
	.loc 4 73 28 discriminator 2 view .LVU103
	cmpq	$0, (%rdx)
	jne	.L21
	.loc 4 75 2 is_stmt 1 view .LVU104
	.loc 4 75 8 is_stmt 0 view .LVU105
	movq	%rax, _auxv(%rip)
	.loc 4 77 2 is_stmt 1 view .LVU106
.LVL29:
	.loc 4 77 17 is_stmt 0 view .LVU107
	movl	$__preinit_array_start, %ebx
	.loc 4 77 2 view .LVU108
	jmp	.L22
.LVL30:
.L23:
	.loc 4 78 3 is_stmt 1 view .LVU109
	.loc 4 78 4 is_stmt 0 view .LVU110
	movq	%r12, %rdx
	movq	%r13, %rsi
	movl	%ebp, %edi
	call	*(%rbx)
.LVL31:
	.loc 4 77 84 is_stmt 1 discriminator 3 view .LVU111
	addq	$8, %rbx
.LVL32:
.L22:
	.loc 4 77 52 discriminator 1 view .LVU112
	cmpq	$__preinit_array_end, %rbx
	jb	.L23
	.loc 4 79 17 is_stmt 0 view .LVU113
	movl	$__init_array_start, %ebx
.LVL33:
	.loc 4 79 17 view .LVU114
	jmp	.L24
.LVL34:
.L25:
	.loc 4 80 3 is_stmt 1 view .LVU115
	.loc 4 80 4 is_stmt 0 view .LVU116
	movq	%r12, %rdx
	movq	%r13, %rsi
	movl	%ebp, %edi
	call	*(%rbx)
.LVL35:
	.loc 4 79 78 is_stmt 1 discriminator 3 view .LVU117
	addq	$8, %rbx
.LVL36:
.L24:
	.loc 4 79 49 discriminator 1 view .LVU118
	cmpq	$__init_array_end, %rbx
	jb	.L25
	.loc 4 83 2 view .LVU119
	.loc 4 83 13 is_stmt 0 view .LVU120
	movq	%r12, %rdx
	movq	%r13, %rsi
	movl	%ebp, %edi
	call	*main@GOTPCREL(%rip)
.LVL37:
	movl	%eax, %ebp
.LVL38:
	.loc 4 85 2 is_stmt 1 view .LVU121
	.loc 4 85 17 is_stmt 0 view .LVU122
	movl	$__fini_array_end, %ebx
.LVL39:
	.loc 4 85 2 view .LVU123
	jmp	.L26
.LVL40:
.L27:
	.loc 4 86 3 is_stmt 1 view .LVU124
	.loc 4 86 4 is_stmt 0 view .LVU125
	subq	$8, %rbx
.LVL41:
	.loc 4 86 4 view .LVU126
	call	*(%rbx)
.LVL42:
.L26:
	.loc 4 85 47 is_stmt 1 discriminator 1 view .LVU127
	cmpq	$__fini_array_start, %rbx
	ja	.L27
	.loc 4 88 2 view .LVU128
	movl	%ebp, %edi
	call	exit
.LVL43:
	.cfi_endproc
.LFE0:
	.size	_start_c, .-_start_c
	.weak	_start
	.type	_start, @function
_start:
.LFB1:
	.file 5 "/home/boricj/Documents/linux/tools/include/nolibc/arch-x86_64.h"
	.loc 5 165 1 view -0
	.cfi_startproc
	.loc 5 166 2 view .LVU130
#APP
# 166 "/home/boricj/Documents/linux/tools/include/nolibc/arch-x86_64.h" 1
	xor  %ebp, %ebp
mov  %rsp, %rdi
call _start_c
hlt

# 0 "" 2
	.loc 5 172 32 view .LVU131
	.loc 5 173 1 is_stmt 0 view .LVU132
#NO_APP
	ud2
	.cfi_endproc
.LFE1:
	.size	_start, .-_start
	.section	.text.nolibc_raise,"ax",@progbits
	.weak	raise
	.type	raise, @function
raise:
.LVL44:
.LFB152:
	.file 6 "/home/boricj/Documents/linux/tools/include/nolibc/signal.h"
	.loc 6 22 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 6 22 1 is_stmt 0 view .LVU134
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset 3, -16
	movl	%edi, %ebx
	.loc 6 23 2 is_stmt 1 view .LVU135
	.loc 6 23 9 is_stmt 0 view .LVU136
	call	sys_getpid
.LVL45:
	.loc 6 23 9 view .LVU137
	movl	%eax, %edi
	.loc 6 23 9 discriminator 1 view .LVU138
	movl	%ebx, %esi
	call	sys_kill
.LVL46:
	.loc 6 24 1 view .LVU139
	popq	%rbx
	.cfi_def_cfa_offset 8
.LVL47:
	.loc 6 24 1 view .LVU140
	ret
	.cfi_endproc
.LFE152:
	.size	raise, .-raise
	.section	.text.nolibc_strlen,"ax",@progbits
	.weak	strlen
	.type	strlen, @function
strlen:
.LVL48:
.LFB168:
	.file 7 "/home/boricj/Documents/linux/tools/include/nolibc/string.h"
	.loc 7 136 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 7 137 2 view .LVU142
	.loc 7 139 2 view .LVU143
	.loc 7 139 11 is_stmt 0 view .LVU144
	movl	$0, %eax
	.loc 7 139 2 view .LVU145
	jmp	.L33
.LVL49:
	.loc 7 139 2 view .LVU146
	.p2align 4
.L34:
	.loc 7 140 3 is_stmt 1 view .LVU147
	.loc 7 139 29 discriminator 3 view .LVU148
	addq	$1, %rax
.LVL50:
.L33:
	.loc 7 139 16 discriminator 1 view .LVU149
	cmpb	$0, (%rdi,%rax)
	jne	.L34
	.loc 7 141 2 view .LVU150
	.loc 7 142 1 is_stmt 0 view .LVU151
	ret
	.cfi_endproc
.LFE168:
	.size	strlen, .-strlen
	.section	.text.nolibc_abort,"ax",@progbits
	.weak	abort
	.type	abort, @function
abort:
.LFB184:
	.file 8 "/home/boricj/Documents/linux/tools/include/nolibc/stdlib.h"
	.loc 8 57 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 8 58 2 view .LVU153
	call	sys_getpid
.LVL51:
	movl	%eax, %edi
	.loc 8 58 2 is_stmt 0 discriminator 1 view .LVU154
	movl	$6, %esi
	call	sys_kill
.LVL52:
	.p2align 1
.L36:
	.loc 8 59 2 is_stmt 1 view .LVU155
	.loc 8 59 2 view .LVU156
	jmp	.L36
	.cfi_endproc
.LFE184:
	.size	abort, .-abort
	.text
	.globl	print_number
	.type	print_number, @function
print_number:
.LVL53:
.LFB256:
	.loc 1 25 28 view -0
	.cfi_startproc
	.loc 1 25 28 is_stmt 0 view .LVU158
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	.cfi_offset 3, -24
	movl	%edi, %ebp
	.loc 1 26 5 is_stmt 1 view .LVU159
	.loc 1 28 5 view .LVU160
.LVL54:
	.loc 1 28 12 is_stmt 0 view .LVU161
	movl	$3, %ebx
	.loc 1 28 5 view .LVU162
	jmp	.L38
.LVL55:
.L39:
.LBB8:
	.loc 1 34 13 is_stmt 1 view .LVU163
	addl	$87, %edi
.LVL56:
	.loc 1 34 13 is_stmt 0 view .LVU164
	call	putchar
.LVL57:
.L40:
	.loc 1 34 13 view .LVU165
.LBE8:
	.loc 1 28 26 is_stmt 1 discriminator 2 view .LVU166
	subl	$1, %ebx
.LVL58:
.L38:
	.loc 1 28 19 discriminator 1 view .LVU167
	testl	%ebx, %ebx
	js	.L43
.LBB9:
	.loc 1 29 9 view .LVU168
	.loc 1 29 32 is_stmt 0 view .LVU169
	leal	0(,%rbx,4), %ecx
	.loc 1 29 26 view .LVU170
	movl	%ebp, %edi
	sarl	%cl, %edi
	.loc 1 29 13 view .LVU171
	movl	%edi, %eax
	sarl	$31, %eax
	shrl	$28, %eax
	addl	%eax, %edi
	andl	$15, %edi
	subl	%eax, %edi
.LVL59:
	.loc 1 31 9 is_stmt 1 view .LVU172
	.loc 1 31 12 is_stmt 0 view .LVU173
	cmpl	$9, %edi
	jg	.L39
	.loc 1 32 13 is_stmt 1 view .LVU174
	addl	$48, %edi
.LVL60:
	.loc 1 32 13 is_stmt 0 view .LVU175
	call	putchar
.LVL61:
	.loc 1 32 13 view .LVU176
	jmp	.L40
.LVL62:
.L43:
	.loc 1 32 13 view .LVU177
.LBE9:
	.loc 1 36 1 view .LVU178
	popq	%rbx
	.cfi_def_cfa_offset 16
.LVL63:
	.loc 1 36 1 view .LVU179
	popq	%rbp
	.cfi_def_cfa_offset 8
.LVL64:
	.loc 1 36 1 view .LVU180
	ret
	.cfi_endproc
.LFE256:
	.size	print_number, .-print_number
	.globl	print_ascii_entry
	.type	print_ascii_entry, @function
print_ascii_entry:
.LVL65:
.LFB257:
	.loc 1 38 101 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 38 101 is_stmt 0 view .LVU182
	pushq	%r14
	.cfi_def_cfa_offset 16
	.cfi_offset 14, -16
	pushq	%r13
	.cfi_def_cfa_offset 24
	.cfi_offset 13, -24
	pushq	%r12
	.cfi_def_cfa_offset 32
	.cfi_offset 12, -32
	pushq	%rbp
	.cfi_def_cfa_offset 40
	.cfi_offset 6, -40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	.cfi_offset 3, -48
	movq	%rsi, %r14
	movl	%edx, %r13d
	.loc 1 39 5 is_stmt 1 view .LVU183
	.loc 1 41 5 view .LVU184
	movsbl	%dil, %r12d
	movl	%r12d, %edi
	.loc 1 41 5 is_stmt 0 view .LVU185
	call	print_number
.LVL66:
	.loc 1 42 5 is_stmt 1 view .LVU186
	movl	$32, %edi
	call	putchar
.LVL67:
	.loc 1 44 5 view .LVU187
	.loc 1 44 9 is_stmt 0 view .LVU188
	movl	%r12d, %edi
	call	*isgraph@GOTPCREL(%rip)
.LVL68:
	.loc 1 44 8 discriminator 1 view .LVU189
	testl	%eax, %eax
	je	.L45
	.loc 1 45 9 is_stmt 1 view .LVU190
	movl	%r12d, %edi
	call	putchar
.LVL69:
.L46:
	.loc 1 48 5 view .LVU191
	movl	$32, %edi
	call	putchar
.LVL70:
	.loc 1 50 5 view .LVU192
	.loc 1 50 12 is_stmt 0 view .LVU193
	movl	$0, %ebp
	.loc 1 50 5 view .LVU194
	jmp	.L47
.LVL71:
.L45:
	.loc 1 47 9 is_stmt 1 view .LVU195
	movl	$32, %edi
	call	putchar
.LVL72:
	jmp	.L46
.LVL73:
.L48:
.LBB10:
	.loc 1 56 13 view .LVU196
	movl	$32, %edi
	call	putchar
.LVL74:
.L49:
.LBE10:
	.loc 1 50 44 discriminator 2 view .LVU197
	addl	$1, %ebp
.LVL75:
.L47:
	.loc 1 50 19 discriminator 1 view .LVU198
	cmpl	%r13d, %ebp
	jge	.L52
.LBB11:
	.loc 1 51 9 view .LVU199
	.loc 1 51 53 is_stmt 0 view .LVU200
	movslq	%ebp, %rbx
	salq	$4, %rbx
	.loc 1 51 31 view .LVU201
	addq	%r14, %rbx
.LVL76:
	.loc 1 53 9 is_stmt 1 view .LVU202
	.loc 1 53 13 is_stmt 0 view .LVU203
	movl	%r12d, %edi
	call	*(%rbx)
.LVL77:
	.loc 1 53 12 discriminator 1 view .LVU204
	testl	%eax, %eax
	je	.L48
	.loc 1 54 13 is_stmt 1 view .LVU205
	movsbl	8(%rbx), %edi
	call	putchar
.LVL78:
	jmp	.L49
.LVL79:
.L52:
	.loc 1 54 13 is_stmt 0 view .LVU206
.LBE11:
	.loc 1 58 1 view .LVU207
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%rbp
	.cfi_def_cfa_offset 32
.LVL80:
	.loc 1 58 1 view .LVU208
	popq	%r12
	.cfi_def_cfa_offset 24
.LVL81:
	.loc 1 58 1 view .LVU209
	popq	%r13
	.cfi_def_cfa_offset 16
.LVL82:
	.loc 1 58 1 view .LVU210
	popq	%r14
	.cfi_def_cfa_offset 8
.LVL83:
	.loc 1 58 1 view .LVU211
	ret
	.cfi_endproc
.LFE257:
	.size	print_ascii_entry, .-print_ascii_entry
	.globl	main
	.type	main, @function
main:
.LFB258:
	.loc 1 60 12 is_stmt 1 view -0
	.cfi_startproc
	pushq	%rbx
	.cfi_def_cfa_offset 16
	.cfi_offset 3, -16
	.loc 1 61 5 view .LVU213
	.loc 1 63 5 view .LVU214
.LVL84:
	.loc 1 63 12 is_stmt 0 view .LVU215
	movl	$0, %ebx
	.loc 1 63 5 view .LVU216
	jmp	.L54
.LVL85:
.L60:
.LBB12:
	.loc 1 70 9 discriminator 1 view .LVU217
	movl	$10, %edi
.L55:
	.loc 1 70 9 discriminator 4 view .LVU218
	call	putchar
.LVL86:
.LBE12:
	.loc 1 63 27 is_stmt 1 discriminator 2 view .LVU219
	addl	$1, %ebx
.LVL87:
.L54:
	.loc 1 63 19 discriminator 1 view .LVU220
	cmpl	$127, %ebx
	jg	.L59
.LBB13:
	.loc 1 64 9 view .LVU221
	.loc 1 64 19 is_stmt 0 view .LVU222
	movl	COLUMNS(%rip), %ecx
	.loc 1 64 13 view .LVU223
	movl	%ebx, %eax
	cltd
	idivl	%ecx
	movl	%eax, %esi
.LVL88:
	.loc 1 65 9 is_stmt 1 view .LVU224
	.loc 1 66 9 view .LVU225
	.loc 1 66 27 is_stmt 0 view .LVU226
	movl	%edx, %eax
.LVL89:
	.loc 1 66 27 view .LVU227
	sall	$7, %eax
	.loc 1 66 33 view .LVU228
	cltd
.LVL90:
	.loc 1 66 33 view .LVU229
	idivl	%ecx
	.loc 1 66 13 view .LVU230
	addl	%esi, %eax
.LVL91:
	.loc 1 68 9 is_stmt 1 view .LVU231
	movsbl	%al, %edi
	movl	$10, %edx
	movl	$s_ascii_properties, %esi
.LVL92:
	.loc 1 68 9 is_stmt 0 view .LVU232
	call	print_ascii_entry
.LVL93:
	.loc 1 70 9 is_stmt 1 view .LVU233
	.loc 1 70 19 is_stmt 0 view .LVU234
	movl	COLUMNS(%rip), %ecx
	movl	%ebx, %eax
	cltd
	idivl	%ecx
	.loc 1 70 40 view .LVU235
	subl	$1, %ecx
	.loc 1 70 9 view .LVU236
	cmpl	%ecx, %edx
	je	.L60
	.loc 1 70 9 discriminator 2 view .LVU237
	movl	$9, %edi
	jmp	.L55
.LVL94:
.L59:
	.loc 1 70 9 discriminator 2 view .LVU238
.LBE13:
	.loc 1 73 5 is_stmt 1 view .LVU239
	.loc 1 74 1 is_stmt 0 view .LVU240
	movl	$0, %eax
	popq	%rbx
	.cfi_def_cfa_offset 8
.LVL95:
	.loc 1 74 1 view .LVU241
	ret
	.cfi_endproc
.LFE258:
	.size	main, .-main
	.globl	COLUMNS
	.data
	.align 4
	.type	COLUMNS, @object
	.size	COLUMNS, 4
COLUMNS:
	.long	4
	.globl	s_ascii_properties
	.section	.rodata
	.align 32
	.type	s_ascii_properties, @object
	.size	s_ascii_properties, 160
s_ascii_properties:
	.quad	isgraph
	.byte	103
	.zero	7
	.quad	isprint
	.byte	112
	.zero	7
	.quad	iscntrl
	.byte	99
	.zero	7
	.quad	isspace
	.byte	115
	.zero	7
	.quad	ispunct
	.byte	33
	.zero	7
	.quad	isalnum
	.byte	65
	.zero	7
	.quad	isalpha
	.byte	97
	.zero	7
	.quad	isdigit
	.byte	100
	.zero	7
	.quad	isupper
	.byte	85
	.zero	7
	.quad	islower
	.byte	108
	.zero	7
	.globl	NUM_ASCII_PROPERTIES
	.align 4
	.type	NUM_ASCII_PROPERTIES, @object
	.size	NUM_ASCII_PROPERTIES, 4
NUM_ASCII_PROPERTIES:
	.long	10
	.weak	optopt
	.section	.data.nolibc_getopt,"aw"
	.align 4
	.type	optopt, @object
	.size	optopt, 4
optopt:
	.zero	4
	.weak	opterr
	.align 4
	.type	opterr, @object
	.size	opterr, 4
opterr:
	.long	1
	.weak	optind
	.align 4
	.type	optind, @object
	.size	optind, 4
optind:
	.long	1
	.weak	optarg
	.align 8
	.type	optarg, @object
	.size	optarg, 8
optarg:
	.zero	8
	.weak	errno
	.bss
	.align 4
	.type	errno, @object
	.size	errno, 4
errno:
	.zero	4
	.weak	_auxv
	.align 8
	.type	_auxv, @object
	.size	_auxv, 8
_auxv:
	.zero	8
	.weak	environ
	.align 8
	.type	environ, @object
	.size	environ, 8
environ:
	.zero	8
	.weak	__fini_array_start
	.weak	__fini_array_end
	.weak	__init_array_end
	.weak	__init_array_start
	.weak	__preinit_array_end
	.weak	__preinit_array_start
	.text
.Letext0:
	.file 9 "/home/boricj/Documents/linux/tools/include/nolibc/stdint.h"
	.file 10 "/home/boricj/Documents/linux/tools/include/nolibc/std.h"
	.file 11 "/home/boricj/Documents/linux/tools/include/nolibc/errno.h"
	.file 12 "/home/boricj/Documents/linux/tools/include/nolibc/getopt.h"
	.file 13 "../../include/ctype.h"
	.file 14 "/home/boricj/Documents/linux/tools/include/nolibc/stackprotector.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0xdec
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.long	.LASF91
	.byte	0xc
	.long	.LASF92
	.long	.LASF93
	.long	.Ldebug_ranges0+0xc0
	.quad	0
	.long	.Ldebug_line0
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF0
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF1
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF2
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.long	.LASF3
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF4
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x4
	.long	0x4c
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF5
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF6
	.uleb128 0x5
	.long	.LASF8
	.byte	0x9
	.byte	0x12
	.byte	0x1e
	.long	0x72
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF7
	.uleb128 0x4
	.long	0x72
	.uleb128 0x5
	.long	.LASF9
	.byte	0x9
	.byte	0x13
	.byte	0x1d
	.long	0x8a
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF10
	.uleb128 0x5
	.long	.LASF11
	.byte	0x9
	.byte	0x15
	.byte	0x1c
	.long	0x8a
	.uleb128 0x5
	.long	.LASF12
	.byte	0xa
	.byte	0x17
	.byte	0x1f
	.long	0x4c
	.uleb128 0x6
	.long	.LASF14
	.byte	0x4
	.byte	0xc
	.byte	0x8
	.long	0xbf
	.uleb128 0x9
	.byte	0x3
	.quad	environ
	.uleb128 0x7
	.byte	0x8
	.long	0xc5
	.uleb128 0x7
	.byte	0x8
	.long	0xcb
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF13
	.uleb128 0x4
	.long	0xcb
	.uleb128 0x6
	.long	.LASF15
	.byte	0x4
	.byte	0xd
	.byte	0x16
	.long	0xed
	.uleb128 0x9
	.byte	0x3
	.quad	_auxv
	.uleb128 0x7
	.byte	0x8
	.long	0x79
	.uleb128 0x8
	.long	0x109
	.long	0xfe
	.uleb128 0x9
	.byte	0
	.uleb128 0x4
	.long	0xf3
	.uleb128 0x7
	.byte	0x8
	.long	0x10e
	.uleb128 0x4
	.long	0x103
	.uleb128 0xa
	.long	0x123
	.uleb128 0xb
	.long	0x4c
	.uleb128 0xb
	.long	0xbf
	.uleb128 0xb
	.long	0xbf
	.byte	0
	.uleb128 0xc
	.long	.LASF16
	.byte	0x4
	.byte	0x13
	.byte	0x15
	.long	0xfe
	.uleb128 0xc
	.long	.LASF17
	.byte	0x4
	.byte	0x14
	.byte	0x15
	.long	0xfe
	.uleb128 0xc
	.long	.LASF18
	.byte	0x4
	.byte	0x16
	.byte	0x15
	.long	0xfe
	.uleb128 0xc
	.long	.LASF19
	.byte	0x4
	.byte	0x17
	.byte	0x15
	.long	0xfe
	.uleb128 0x8
	.long	0x169
	.long	0x15e
	.uleb128 0x9
	.byte	0
	.uleb128 0x4
	.long	0x153
	.uleb128 0x7
	.byte	0x8
	.long	0x16e
	.uleb128 0x4
	.long	0x163
	.uleb128 0xd
	.uleb128 0xc
	.long	.LASF20
	.byte	0x4
	.byte	0x19
	.byte	0x15
	.long	0x15e
	.uleb128 0xc
	.long	.LASF21
	.byte	0x4
	.byte	0x1a
	.byte	0x15
	.long	0x15e
	.uleb128 0x2
	.byte	0x10
	.byte	0x5
	.long	.LASF22
	.uleb128 0x2
	.byte	0x10
	.byte	0x7
	.long	.LASF23
	.uleb128 0x6
	.long	.LASF24
	.byte	0xb
	.byte	0x11
	.byte	0x5
	.long	0x4c
	.uleb128 0x9
	.byte	0x3
	.quad	errno
	.uleb128 0x8
	.long	0xcb
	.long	0x1bb
	.uleb128 0xe
	.long	0x72
	.byte	0x14
	.byte	0
	.uleb128 0xf
	.long	.LASF81
	.byte	0x8
	.byte	0x1d
	.byte	0x25
	.long	0x1ab
	.uleb128 0x10
	.long	.LASF25
	.byte	0x1
	.byte	0x3
	.byte	0x28
	.byte	0x10
	.long	0x1e2
	.uleb128 0x11
	.long	.LASF33
	.byte	0x3
	.byte	0x29
	.byte	0x7
	.long	0x1e2
	.byte	0
	.byte	0
	.uleb128 0x8
	.long	0xcb
	.long	0x1f2
	.uleb128 0xe
	.long	0x72
	.byte	0
	.byte	0
	.uleb128 0x5
	.long	.LASF25
	.byte	0x3
	.byte	0x2a
	.byte	0x3
	.long	0x1c7
	.uleb128 0x12
	.long	.LASF26
	.byte	0x3
	.byte	0x2c
	.byte	0x2c
	.long	0x218
	.quad	0xffffffffffffffff
	.uleb128 0x7
	.byte	0x8
	.long	0x1f2
	.uleb128 0x4
	.long	0x212
	.uleb128 0x12
	.long	.LASF27
	.byte	0x3
	.byte	0x2d
	.byte	0x2c
	.long	0x218
	.quad	0xfffffffffffffffe
	.uleb128 0x12
	.long	.LASF28
	.byte	0x3
	.byte	0x2e
	.byte	0x2c
	.long	0x218
	.quad	0xfffffffffffffffd
	.uleb128 0x7
	.byte	0x8
	.long	0xd2
	.uleb128 0x6
	.long	.LASF29
	.byte	0xc
	.byte	0x13
	.byte	0x7
	.long	0xc5
	.uleb128 0x9
	.byte	0x3
	.quad	optarg
	.uleb128 0x6
	.long	.LASF30
	.byte	0xc
	.byte	0x16
	.byte	0x5
	.long	0x4c
	.uleb128 0x9
	.byte	0x3
	.quad	optind
	.uleb128 0x6
	.long	.LASF31
	.byte	0xc
	.byte	0x16
	.byte	0x11
	.long	0x4c
	.uleb128 0x9
	.byte	0x3
	.quad	opterr
	.uleb128 0x6
	.long	.LASF32
	.byte	0xc
	.byte	0x16
	.byte	0x1d
	.long	0x4c
	.uleb128 0x9
	.byte	0x3
	.quad	optopt
	.uleb128 0x13
	.byte	0x10
	.byte	0x1
	.byte	0x4
	.byte	0x9
	.long	0x2c7
	.uleb128 0x11
	.long	.LASF34
	.byte	0x1
	.byte	0x5
	.byte	0xb
	.long	0x2d6
	.byte	0
	.uleb128 0x11
	.long	.LASF35
	.byte	0x1
	.byte	0x6
	.byte	0xa
	.long	0xcb
	.byte	0x8
	.byte	0
	.uleb128 0x14
	.long	0x4c
	.long	0x2d6
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.long	0x2c7
	.uleb128 0x5
	.long	.LASF36
	.byte	0x1
	.byte	0x7
	.byte	0x3
	.long	0x2a3
	.uleb128 0x4
	.long	0x2dc
	.uleb128 0x6
	.long	.LASF37
	.byte	0x1
	.byte	0x9
	.byte	0xb
	.long	0x53
	.uleb128 0x9
	.byte	0x3
	.quad	NUM_ASCII_PROPERTIES
	.uleb128 0x8
	.long	0x2e8
	.long	0x313
	.uleb128 0xe
	.long	0x72
	.byte	0x9
	.byte	0
	.uleb128 0x4
	.long	0x303
	.uleb128 0x6
	.long	.LASF38
	.byte	0x1
	.byte	0xa
	.byte	0x16
	.long	0x313
	.uleb128 0x9
	.byte	0x3
	.quad	s_ascii_properties
	.uleb128 0x6
	.long	.LASF39
	.byte	0x1
	.byte	0x17
	.byte	0x5
	.long	0x4c
	.uleb128 0x9
	.byte	0x3
	.quad	COLUMNS
	.uleb128 0x15
	.long	.LASF40
	.byte	0xd
	.byte	0x8
	.byte	0xc
	.long	0x4c
	.long	0x35a
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x15
	.long	.LASF41
	.byte	0xd
	.byte	0xc
	.byte	0xc
	.long	0x4c
	.long	0x370
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x15
	.long	.LASF42
	.byte	0xd
	.byte	0x6
	.byte	0xc
	.long	0x4c
	.long	0x386
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x15
	.long	.LASF43
	.byte	0xd
	.byte	0x4
	.byte	0xc
	.long	0x4c
	.long	0x39c
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x15
	.long	.LASF44
	.byte	0xd
	.byte	0x3
	.byte	0xc
	.long	0x4c
	.long	0x3b2
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x15
	.long	.LASF45
	.byte	0xd
	.byte	0xa
	.byte	0xc
	.long	0x4c
	.long	0x3c8
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x15
	.long	.LASF46
	.byte	0xd
	.byte	0xb
	.byte	0xc
	.long	0x4c
	.long	0x3de
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x15
	.long	.LASF47
	.byte	0xd
	.byte	0x5
	.byte	0xc
	.long	0x4c
	.long	0x3f4
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x15
	.long	.LASF48
	.byte	0xd
	.byte	0x9
	.byte	0xc
	.long	0x4c
	.long	0x40a
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x15
	.long	.LASF49
	.byte	0xd
	.byte	0x7
	.byte	0xc
	.long	0x4c
	.long	0x420
	.uleb128 0xb
	.long	0x4c
	.byte	0
	.uleb128 0x16
	.long	.LASF90
	.byte	0x4
	.byte	0x2b
	.byte	0x6
	.long	.LASF51
	.long	0x4c
	.long	0x444
	.uleb128 0xb
	.long	0x4c
	.uleb128 0xb
	.long	0xbf
	.uleb128 0xb
	.long	0xbf
	.byte	0
	.uleb128 0x17
	.long	.LASF51
	.byte	0x1
	.byte	0x3c
	.byte	0x5
	.long	0x4c
	.quad	.LFB258
	.quad	.LFE258-.LFB258
	.uleb128 0x1
	.byte	0x9c
	.long	0x4e4
	.uleb128 0x18
	.string	"i"
	.byte	0x1
	.byte	0x3d
	.byte	0x9
	.long	0x4c
	.long	.LLST32
	.long	.LVUS32
	.uleb128 0x19
	.long	.Ldebug_ranges0+0x90
	.uleb128 0x18
	.string	"x"
	.byte	0x1
	.byte	0x40
	.byte	0xd
	.long	0x4c
	.long	.LLST33
	.long	.LVUS33
	.uleb128 0x18
	.string	"y"
	.byte	0x1
	.byte	0x41
	.byte	0xd
	.long	0x4c
	.long	.LLST34
	.long	.LVUS34
	.uleb128 0x1a
	.long	.LASF50
	.byte	0x1
	.byte	0x42
	.byte	0xd
	.long	0x4c
	.long	.LLST35
	.long	.LVUS35
	.uleb128 0x1b
	.quad	.LVL86
	.long	0x721
	.uleb128 0x1c
	.quad	.LVL93
	.long	0x4e4
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x9
	.byte	0x3
	.quad	s_ascii_properties
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x1
	.byte	0x3a
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x1e
	.long	.LASF52
	.byte	0x1
	.byte	0x26
	.byte	0x6
	.quad	.LFB257
	.quad	.LFE257-.LFB257
	.uleb128 0x1
	.byte	0x9c
	.long	0x634
	.uleb128 0x1f
	.long	.LASF50
	.byte	0x1
	.byte	0x26
	.byte	0x1d
	.long	0xcb
	.long	.LLST27
	.long	.LVUS27
	.uleb128 0x1f
	.long	.LASF53
	.byte	0x1
	.byte	0x26
	.byte	0x3d
	.long	0x634
	.long	.LLST28
	.long	.LVUS28
	.uleb128 0x1f
	.long	.LASF54
	.byte	0x1
	.byte	0x26
	.byte	0x4f
	.long	0x4c
	.long	.LLST29
	.long	.LVUS29
	.uleb128 0x18
	.string	"k"
	.byte	0x1
	.byte	0x27
	.byte	0x9
	.long	0x4c
	.long	.LLST30
	.long	.LVUS30
	.uleb128 0x20
	.long	.Ldebug_ranges0+0x60
	.long	0x5a7
	.uleb128 0x1a
	.long	.LASF55
	.byte	0x1
	.byte	0x33
	.byte	0x1f
	.long	0x634
	.long	.LLST31
	.long	.LVUS31
	.uleb128 0x21
	.quad	.LVL74
	.long	0x721
	.long	0x585
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x8
	.byte	0x20
	.byte	0
	.uleb128 0x22
	.quad	.LVL77
	.long	0x599
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x7c
	.sleb128 0
	.byte	0
	.uleb128 0x1b
	.quad	.LVL78
	.long	0x721
	.byte	0
	.uleb128 0x21
	.quad	.LVL66
	.long	0x63a
	.long	0x5bf
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x7c
	.sleb128 0
	.byte	0
	.uleb128 0x21
	.quad	.LVL67
	.long	0x721
	.long	0x5d7
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x8
	.byte	0x20
	.byte	0
	.uleb128 0x21
	.quad	.LVL68
	.long	0x40a
	.long	0x5ef
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x7c
	.sleb128 0
	.byte	0
	.uleb128 0x21
	.quad	.LVL69
	.long	0x721
	.long	0x607
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x7c
	.sleb128 0
	.byte	0
	.uleb128 0x21
	.quad	.LVL70
	.long	0x721
	.long	0x61f
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x8
	.byte	0x20
	.byte	0
	.uleb128 0x1c
	.quad	.LVL72
	.long	0x721
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x8
	.byte	0x20
	.byte	0
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.long	0x2e8
	.uleb128 0x1e
	.long	.LASF56
	.byte	0x1
	.byte	0x19
	.byte	0x6
	.quad	.LFB256
	.quad	.LFE256-.LFB256
	.uleb128 0x1
	.byte	0x9c
	.long	0x719
	.uleb128 0x23
	.string	"num"
	.byte	0x1
	.byte	0x19
	.byte	0x17
	.long	0x4c
	.long	.LLST24
	.long	.LVUS24
	.uleb128 0x18
	.string	"n"
	.byte	0x1
	.byte	0x1a
	.byte	0x9
	.long	0x4c
	.long	.LLST25
	.long	.LVUS25
	.uleb128 0x19
	.long	.Ldebug_ranges0+0x30
	.uleb128 0x1a
	.long	.LASF57
	.byte	0x1
	.byte	0x1d
	.byte	0xd
	.long	0x4c
	.long	.LLST26
	.long	.LVUS26
	.uleb128 0x21
	.quad	.LVL57
	.long	0x721
	.long	0x6d9
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2c
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x22
	.byte	0x3f
	.byte	0x1a
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x1c
	.byte	0x23
	.uleb128 0x57
	.byte	0
	.uleb128 0x1c
	.quad	.LVL61
	.long	0x721
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2c
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x22
	.byte	0x3f
	.byte	0x1a
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x1c
	.byte	0x23
	.uleb128 0x30
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x24
	.long	.LASF94
	.byte	0xe
	.byte	0x32
	.byte	0xd
	.uleb128 0x25
	.long	.LASF58
	.byte	0x3
	.byte	0xa7
	.byte	0x5
	.long	0x4c
	.quad	.LFB221
	.quad	.LFE221-.LFB221
	.uleb128 0x1
	.byte	0x9c
	.long	0x771
	.uleb128 0x23
	.string	"c"
	.byte	0x3
	.byte	0xa7
	.byte	0x11
	.long	0x4c
	.long	.LLST13
	.long	.LVUS13
	.uleb128 0x1c
	.quad	.LVL21
	.long	0x771
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x9
	.byte	0xfe
	.byte	0
	.byte	0
	.uleb128 0x25
	.long	.LASF59
	.byte	0x3
	.byte	0x9d
	.byte	0x5
	.long	0x4c
	.quad	.LFB220
	.quad	.LFE220-.LFB220
	.uleb128 0x1
	.byte	0x9c
	.long	0x7fa
	.uleb128 0x23
	.string	"c"
	.byte	0x3
	.byte	0x9d
	.byte	0xf
	.long	0x4c
	.long	.LLST11
	.long	.LVUS11
	.uleb128 0x1f
	.long	.LASF60
	.byte	0x3
	.byte	0x9d
	.byte	0x18
	.long	0x212
	.long	.LLST12
	.long	.LVUS12
	.uleb128 0x26
	.string	"ch"
	.byte	0x3
	.byte	0x9f
	.byte	0x10
	.long	0x29
	.uleb128 0x2
	.byte	0x91
	.sleb128 -9
	.uleb128 0x21
	.quad	.LVL18
	.long	0x7fa
	.long	0x7e0
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0
	.uleb128 0x1c
	.quad	.LVL19
	.long	0x919
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x91
	.sleb128 -9
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x1
	.byte	0x31
	.byte	0
	.byte	0
	.uleb128 0x25
	.long	.LASF61
	.byte	0x3
	.byte	0x57
	.byte	0x5
	.long	0x4c
	.quad	.LFB215
	.quad	.LFE215-.LFB215
	.uleb128 0x1
	.byte	0x9c
	.long	0x83d
	.uleb128 0x27
	.long	.LASF60
	.byte	0x3
	.byte	0x57
	.byte	0x12
	.long	0x212
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x18
	.string	"i"
	.byte	0x3
	.byte	0x59
	.byte	0xb
	.long	0x91
	.long	.LLST10
	.long	.LVUS10
	.byte	0
	.uleb128 0x28
	.long	.LASF62
	.byte	0x8
	.byte	0x38
	.byte	0x6
	.quad	.LFB184
	.quad	.LFE184-.LFB184
	.uleb128 0x1
	.byte	0x9c
	.long	0x87c
	.uleb128 0x1b
	.quad	.LVL51
	.long	0xb09
	.uleb128 0x1c
	.quad	.LVL52
	.long	0xa73
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x1
	.byte	0x36
	.byte	0
	.byte	0
	.uleb128 0x29
	.long	.LASF63
	.byte	0x7
	.byte	0x87
	.byte	0x8
	.long	0x66
	.quad	.LFB168
	.quad	.LFE168-.LFB168
	.uleb128 0x1
	.byte	0x9c
	.long	0x8c1
	.uleb128 0x2a
	.string	"str"
	.byte	0x7
	.byte	0x87
	.byte	0x1b
	.long	0x245
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x18
	.string	"len"
	.byte	0x7
	.byte	0x89
	.byte	0x9
	.long	0x66
	.long	.LLST23
	.long	.LVUS23
	.byte	0
	.uleb128 0x29
	.long	.LASF64
	.byte	0x6
	.byte	0x15
	.byte	0x5
	.long	0x4c
	.quad	.LFB152
	.quad	.LFE152-.LFB152
	.uleb128 0x1
	.byte	0x9c
	.long	0x919
	.uleb128 0x1f
	.long	.LASF65
	.byte	0x6
	.byte	0x15
	.byte	0xf
	.long	0x4c
	.long	.LLST22
	.long	.LVUS22
	.uleb128 0x1b
	.quad	.LVL45
	.long	0xb09
	.uleb128 0x1c
	.quad	.LVL46
	.long	0xa73
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x73
	.sleb128 0
	.byte	0
	.byte	0
	.uleb128 0x2b
	.long	.LASF66
	.byte	0x2
	.value	0x3a2
	.byte	0x9
	.long	0x7e
	.quad	.LFB86
	.quad	.LFE86-.LFB86
	.uleb128 0x1
	.byte	0x9c
	.long	0x9b9
	.uleb128 0x2c
	.string	"fd"
	.byte	0x2
	.value	0x3a2
	.byte	0x13
	.long	0x4c
	.long	.LLST6
	.long	.LVUS6
	.uleb128 0x2c
	.string	"buf"
	.byte	0x2
	.value	0x3a2
	.byte	0x23
	.long	0x9b9
	.long	.LLST7
	.long	.LVUS7
	.uleb128 0x2d
	.long	.LASF67
	.byte	0x2
	.value	0x3a2
	.byte	0x2f
	.long	0x66
	.long	.LLST8
	.long	.LVUS8
	.uleb128 0x19
	.long	.Ldebug_ranges0+0
	.uleb128 0x2e
	.long	.LASF68
	.byte	0x2
	.value	0x3a4
	.byte	0x9
	.long	0x7e
	.long	.LLST9
	.long	.LVUS9
	.uleb128 0x1c
	.quad	.LVL13
	.long	0x9c0
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x51
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.long	0x9bf
	.uleb128 0x2f
	.uleb128 0x2b
	.long	.LASF69
	.byte	0x2
	.value	0x39c
	.byte	0x9
	.long	0x7e
	.quad	.LFB85
	.quad	.LFE85-.LFB85
	.uleb128 0x1
	.byte	0x9c
	.long	0xa73
	.uleb128 0x30
	.string	"fd"
	.byte	0x2
	.value	0x39c
	.byte	0x17
	.long	0x4c
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x30
	.string	"buf"
	.byte	0x2
	.value	0x39c
	.byte	0x27
	.long	0x9b9
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x31
	.long	.LASF67
	.byte	0x2
	.value	0x39c
	.byte	0x33
	.long	0x66
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x32
	.quad	.LBB5
	.quad	.LBE5-.LBB5
	.uleb128 0x2e
	.long	.LASF70
	.byte	0x2
	.value	0x39e
	.byte	0x9
	.long	0x8a
	.long	.LLST5
	.long	.LVUS5
	.uleb128 0x33
	.long	.LASF71
	.byte	0x2
	.value	0x39e
	.byte	0x9
	.long	0x8a
	.uleb128 0x1
	.byte	0x50
	.uleb128 0x33
	.long	.LASF72
	.byte	0x2
	.value	0x39e
	.byte	0x9
	.long	0x8a
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x33
	.long	.LASF73
	.byte	0x2
	.value	0x39e
	.byte	0x9
	.long	0x8a
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x33
	.long	.LASF74
	.byte	0x2
	.value	0x39e
	.byte	0x9
	.long	0x8a
	.uleb128 0x1
	.byte	0x51
	.byte	0
	.byte	0
	.uleb128 0x2b
	.long	.LASF75
	.byte	0x2
	.value	0x20a
	.byte	0x5
	.long	0x4c
	.quad	.LFB48
	.quad	.LFE48-.LFB48
	.uleb128 0x1
	.byte	0x9c
	.long	0xb09
	.uleb128 0x30
	.string	"pid"
	.byte	0x2
	.value	0x20a
	.byte	0x14
	.long	0x9d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x31
	.long	.LASF65
	.byte	0x2
	.value	0x20a
	.byte	0x1d
	.long	0x4c
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x32
	.quad	.LBB4
	.quad	.LBE4-.LBB4
	.uleb128 0x2e
	.long	.LASF70
	.byte	0x2
	.value	0x20c
	.byte	0x9
	.long	0x8a
	.long	.LLST4
	.long	.LVUS4
	.uleb128 0x33
	.long	.LASF71
	.byte	0x2
	.value	0x20c
	.byte	0x9
	.long	0x8a
	.uleb128 0x1
	.byte	0x50
	.uleb128 0x33
	.long	.LASF72
	.byte	0x2
	.value	0x20c
	.byte	0x9
	.long	0x8a
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x33
	.long	.LASF73
	.byte	0x2
	.value	0x20c
	.byte	0x9
	.long	0x8a
	.uleb128 0x1
	.byte	0x54
	.byte	0
	.byte	0
	.uleb128 0x2b
	.long	.LASF76
	.byte	0x2
	.value	0x1b6
	.byte	0x7
	.long	0x9d
	.quad	.LFB39
	.quad	.LFE39-.LFB39
	.uleb128 0x1
	.byte	0x9c
	.long	0xb63
	.uleb128 0x32
	.quad	.LBB3
	.quad	.LBE3-.LBB3
	.uleb128 0x2e
	.long	.LASF70
	.byte	0x2
	.value	0x1b8
	.byte	0x9
	.long	0x8a
	.long	.LLST3
	.long	.LVUS3
	.uleb128 0x33
	.long	.LASF71
	.byte	0x2
	.value	0x1b8
	.byte	0x9
	.long	0x8a
	.uleb128 0x1
	.byte	0x50
	.byte	0
	.byte	0
	.uleb128 0x34
	.long	.LASF77
	.byte	0x2
	.value	0x135
	.byte	0x6
	.quad	.LFB26
	.quad	.LFE26-.LFB26
	.uleb128 0x1
	.byte	0x9c
	.long	0xbad
	.uleb128 0x2d
	.long	.LASF78
	.byte	0x2
	.value	0x135
	.byte	0xf
	.long	0x4c
	.long	.LLST2
	.long	.LVUS2
	.uleb128 0x1c
	.quad	.LVL6
	.long	0xbad
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0
	.byte	0
	.uleb128 0x34
	.long	.LASF79
	.byte	0x2
	.value	0x12f
	.byte	0x6
	.quad	.LFB25
	.quad	.LFE25-.LFB25
	.uleb128 0x1
	.byte	0x9c
	.long	0xbf7
	.uleb128 0x2d
	.long	.LASF78
	.byte	0x2
	.value	0x12f
	.byte	0x10
	.long	0x4c
	.long	.LLST1
	.long	.LVUS1
	.uleb128 0x1c
	.quad	.LVL4
	.long	0xbf7
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0
	.byte	0
	.uleb128 0x34
	.long	.LASF80
	.byte	0x2
	.value	0x128
	.byte	0x6
	.quad	.LFB24
	.quad	.LFE24-.LFB24
	.uleb128 0x1
	.byte	0x9c
	.long	0xc69
	.uleb128 0x2d
	.long	.LASF78
	.byte	0x2
	.value	0x128
	.byte	0x13
	.long	0x4c
	.long	.LLST0
	.long	.LVUS0
	.uleb128 0x32
	.quad	.LBB2
	.quad	.LBE2-.LBB2
	.uleb128 0x35
	.long	.LASF70
	.byte	0x2
	.value	0x12a
	.byte	0x2
	.long	0x8a
	.uleb128 0x33
	.long	.LASF71
	.byte	0x2
	.value	0x12a
	.byte	0x2
	.long	0x8a
	.uleb128 0x1
	.byte	0x50
	.uleb128 0x33
	.long	.LASF72
	.byte	0x2
	.value	0x12a
	.byte	0x2
	.long	0x8a
	.uleb128 0x1
	.byte	0x55
	.byte	0
	.byte	0
	.uleb128 0x36
	.long	.LASF95
	.byte	0x5
	.byte	0xa4
	.byte	0x4f
	.quad	.LFB1
	.quad	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x37
	.long	.LASF82
	.byte	0x4
	.byte	0x21
	.byte	0x6
	.quad	.LFB0
	.quad	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.long	0xddd
	.uleb128 0x23
	.string	"sp"
	.byte	0x4
	.byte	0x21
	.byte	0x15
	.long	0xddd
	.long	.LLST14
	.long	.LVUS14
	.uleb128 0x1a
	.long	.LASF83
	.byte	0x4
	.byte	0x23
	.byte	0x7
	.long	0x8a
	.long	.LLST15
	.long	.LVUS15
	.uleb128 0x1a
	.long	.LASF84
	.byte	0x4
	.byte	0x24
	.byte	0x9
	.long	0xbf
	.long	.LLST16
	.long	.LVUS16
	.uleb128 0x1a
	.long	.LASF85
	.byte	0x4
	.byte	0x25
	.byte	0x9
	.long	0xbf
	.long	.LLST17
	.long	.LVUS17
	.uleb128 0x1a
	.long	.LASF86
	.byte	0x4
	.byte	0x26
	.byte	0x6
	.long	0x4c
	.long	.LLST18
	.long	.LVUS18
	.uleb128 0x1a
	.long	.LASF87
	.byte	0x4
	.byte	0x27
	.byte	0x11
	.long	0xde3
	.long	.LLST19
	.long	.LVUS19
	.uleb128 0x1a
	.long	.LASF88
	.byte	0x4
	.byte	0x28
	.byte	0x11
	.long	0xde9
	.long	.LLST20
	.long	.LVUS20
	.uleb128 0x1a
	.long	.LASF89
	.byte	0x4
	.byte	0x29
	.byte	0x17
	.long	0xed
	.long	.LLST21
	.long	.LVUS21
	.uleb128 0x16
	.long	.LASF90
	.byte	0x4
	.byte	0x2b
	.byte	0x6
	.long	.LASF51
	.long	0x4c
	.long	0xd64
	.uleb128 0xb
	.long	0x4c
	.uleb128 0xb
	.long	0xbf
	.uleb128 0xb
	.long	0xbf
	.byte	0
	.uleb128 0x22
	.quad	.LVL31
	.long	0xd84
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x76
	.sleb128 0
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x7d
	.sleb128 0
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x2
	.byte	0x7c
	.sleb128 0
	.byte	0
	.uleb128 0x22
	.quad	.LVL35
	.long	0xda4
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x76
	.sleb128 0
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x7d
	.sleb128 0
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x2
	.byte	0x7c
	.sleb128 0
	.byte	0
	.uleb128 0x21
	.quad	.LVL37
	.long	0x420
	.long	0xdc8
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x76
	.sleb128 0
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x7d
	.sleb128 0
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x51
	.uleb128 0x2
	.byte	0x7c
	.sleb128 0
	.byte	0
	.uleb128 0x1c
	.quad	.LVL43
	.long	0xb63
	.uleb128 0x1d
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x76
	.sleb128 0
	.byte	0
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.long	0x8a
	.uleb128 0x7
	.byte	0x8
	.long	0x109
	.uleb128 0x7
	.byte	0x8
	.long	0x169
	.byte	0
	.section	.debug_abbrev,"",@progbits
.Ldebug_abbrev0:
	.uleb128 0x1
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1b
	.uleb128 0xe
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x21
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x15
	.byte	0x1
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x15
	.byte	0
	.uleb128 0x27
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0xe
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0xf
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0x13
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x12
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1c
	.uleb128 0x7
	.byte	0
	.byte	0
	.uleb128 0x13
	.uleb128 0x13
	.byte	0x1
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x14
	.uleb128 0x15
	.byte	0x1
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x15
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x16
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x17
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x18
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x19
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x55
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x1a
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x1b
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1c
	.uleb128 0x4109
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1d
	.uleb128 0x410a
	.byte	0
	.uleb128 0x2
	.uleb128 0x18
	.uleb128 0x2111
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x1e
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1f
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x20
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x21
	.uleb128 0x4109
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x22
	.uleb128 0x4109
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x23
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x24
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x25
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x26
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x27
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x28
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x87
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x29
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x2a
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x2b
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x2c
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2d
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2e
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2f
	.uleb128 0x26
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x30
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x31
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x32
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.byte	0
	.byte	0
	.uleb128 0x33
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x34
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x87
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x35
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x36
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x87
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x37
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2116
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LVUS32:
	.uleb128 .LVU215
	.uleb128 .LVU217
	.uleb128 .LVU217
	.uleb128 .LVU241
.LLST32:
	.quad	.LVL84
	.quad	.LVL85
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.quad	.LVL85
	.quad	.LVL95
	.value	0x1
	.byte	0x53
	.quad	0
	.quad	0
.LVUS33:
	.uleb128 .LVU224
	.uleb128 .LVU229
	.uleb128 .LVU229
	.uleb128 .LVU233
.LLST33:
	.quad	.LVL88
	.quad	.LVL90
	.value	0x1
	.byte	0x51
	.quad	.LVL90
	.quad	.LVL93-1
	.value	0xa
	.byte	0x73
	.sleb128 0
	.byte	0x72
	.sleb128 0
	.byte	0x14
	.byte	0x14
	.byte	0x1b
	.byte	0x1e
	.byte	0x1c
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS34:
	.uleb128 .LVU225
	.uleb128 .LVU227
	.uleb128 .LVU227
	.uleb128 .LVU232
	.uleb128 .LVU232
	.uleb128 .LVU233
.LLST34:
	.quad	.LVL88
	.quad	.LVL89
	.value	0x1
	.byte	0x50
	.quad	.LVL89
	.quad	.LVL92
	.value	0x1
	.byte	0x54
	.quad	.LVL92
	.quad	.LVL93-1
	.value	0x6
	.byte	0x73
	.sleb128 0
	.byte	0x72
	.sleb128 0
	.byte	0x1b
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS35:
	.uleb128 .LVU231
	.uleb128 .LVU233
.LLST35:
	.quad	.LVL91
	.quad	.LVL93-1
	.value	0x1
	.byte	0x50
	.quad	0
	.quad	0
.LVUS27:
	.uleb128 0
	.uleb128 .LVU186
	.uleb128 .LVU186
	.uleb128 .LVU209
	.uleb128 .LVU209
	.uleb128 0
.LLST27:
	.quad	.LVL65
	.quad	.LVL66-1
	.value	0x1
	.byte	0x55
	.quad	.LVL66-1
	.quad	.LVL81
	.value	0x1
	.byte	0x5c
	.quad	.LVL81
	.quad	.LFE257
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS28:
	.uleb128 0
	.uleb128 .LVU186
	.uleb128 .LVU186
	.uleb128 .LVU211
	.uleb128 .LVU211
	.uleb128 0
.LLST28:
	.quad	.LVL65
	.quad	.LVL66-1
	.value	0x1
	.byte	0x54
	.quad	.LVL66-1
	.quad	.LVL83
	.value	0x1
	.byte	0x5e
	.quad	.LVL83
	.quad	.LFE257
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS29:
	.uleb128 0
	.uleb128 .LVU186
	.uleb128 .LVU186
	.uleb128 .LVU210
	.uleb128 .LVU210
	.uleb128 0
.LLST29:
	.quad	.LVL65
	.quad	.LVL66-1
	.value	0x1
	.byte	0x51
	.quad	.LVL66-1
	.quad	.LVL82
	.value	0x1
	.byte	0x5d
	.quad	.LVL82
	.quad	.LFE257
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x51
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS30:
	.uleb128 .LVU193
	.uleb128 .LVU195
	.uleb128 .LVU196
	.uleb128 .LVU208
.LLST30:
	.quad	.LVL70
	.quad	.LVL71
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.quad	.LVL73
	.quad	.LVL80
	.value	0x1
	.byte	0x56
	.quad	0
	.quad	0
.LVUS31:
	.uleb128 .LVU196
	.uleb128 .LVU198
	.uleb128 .LVU202
	.uleb128 .LVU206
.LLST31:
	.quad	.LVL73
	.quad	.LVL75
	.value	0x1
	.byte	0x53
	.quad	.LVL76
	.quad	.LVL79
	.value	0x1
	.byte	0x53
	.quad	0
	.quad	0
.LVUS24:
	.uleb128 0
	.uleb128 .LVU163
	.uleb128 .LVU163
	.uleb128 .LVU180
	.uleb128 .LVU180
	.uleb128 0
.LLST24:
	.quad	.LVL53
	.quad	.LVL55
	.value	0x1
	.byte	0x55
	.quad	.LVL55
	.quad	.LVL64
	.value	0x1
	.byte	0x56
	.quad	.LVL64
	.quad	.LFE256
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS25:
	.uleb128 .LVU161
	.uleb128 .LVU163
	.uleb128 .LVU163
	.uleb128 .LVU179
.LLST25:
	.quad	.LVL54
	.quad	.LVL55
	.value	0x2
	.byte	0x33
	.byte	0x9f
	.quad	.LVL55
	.quad	.LVL63
	.value	0x1
	.byte	0x53
	.quad	0
	.quad	0
.LVUS26:
	.uleb128 .LVU163
	.uleb128 .LVU164
	.uleb128 .LVU164
	.uleb128 .LVU165
	.uleb128 .LVU165
	.uleb128 .LVU167
	.uleb128 .LVU172
	.uleb128 .LVU175
	.uleb128 .LVU175
	.uleb128 .LVU176
	.uleb128 .LVU176
	.uleb128 .LVU177
.LLST26:
	.quad	.LVL55
	.quad	.LVL56
	.value	0x1
	.byte	0x55
	.quad	.LVL56
	.quad	.LVL57-1
	.value	0x4
	.byte	0x75
	.sleb128 -87
	.byte	0x9f
	.quad	.LVL57-1
	.quad	.LVL58
	.value	0x2b
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x22
	.byte	0x3f
	.byte	0x1a
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x1c
	.byte	0x9f
	.quad	.LVL59
	.quad	.LVL60
	.value	0x1
	.byte	0x55
	.quad	.LVL60
	.quad	.LVL61-1
	.value	0x3
	.byte	0x75
	.sleb128 -48
	.byte	0x9f
	.quad	.LVL61-1
	.quad	.LVL62
	.value	0x2b
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x22
	.byte	0x3f
	.byte	0x1a
	.byte	0x76
	.sleb128 0
	.byte	0x73
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x8
	.byte	0xff
	.byte	0x1a
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x1c
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS13:
	.uleb128 0
	.uleb128 .LVU79
	.uleb128 .LVU79
	.uleb128 0
.LLST13:
	.quad	.LVL20
	.quad	.LVL21-1
	.value	0x1
	.byte	0x55
	.quad	.LVL21-1
	.quad	.LFE221
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS11:
	.uleb128 0
	.uleb128 .LVU65
	.uleb128 .LVU65
	.uleb128 .LVU69
	.uleb128 .LVU69
	.uleb128 0
.LLST11:
	.quad	.LVL16
	.quad	.LVL17
	.value	0x1
	.byte	0x55
	.quad	.LVL17
	.quad	.LVL18-1
	.value	0x1
	.byte	0x50
	.quad	.LVL18-1
	.quad	.LFE220
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS12:
	.uleb128 0
	.uleb128 .LVU69
	.uleb128 .LVU69
	.uleb128 0
.LLST12:
	.quad	.LVL16
	.quad	.LVL18-1
	.value	0x1
	.byte	0x54
	.quad	.LVL18-1
	.quad	.LFE220
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS10:
	.uleb128 .LVU53
	.uleb128 0
.LLST10:
	.quad	.LVL15
	.quad	.LFE215
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS23:
	.uleb128 .LVU144
	.uleb128 .LVU146
	.uleb128 .LVU146
	.uleb128 0
.LLST23:
	.quad	.LVL48
	.quad	.LVL49
	.value	0x2
	.byte	0x30
	.byte	0x9f
	.quad	.LVL49
	.quad	.LFE168
	.value	0x1
	.byte	0x50
	.quad	0
	.quad	0
.LVUS22:
	.uleb128 0
	.uleb128 .LVU137
	.uleb128 .LVU137
	.uleb128 .LVU140
	.uleb128 .LVU140
	.uleb128 0
.LLST22:
	.quad	.LVL44
	.quad	.LVL45-1
	.value	0x1
	.byte	0x55
	.quad	.LVL45-1
	.quad	.LVL47
	.value	0x1
	.byte	0x53
	.quad	.LVL47
	.quad	.LFE152
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS6:
	.uleb128 0
	.uleb128 .LVU44
	.uleb128 .LVU44
	.uleb128 0
.LLST6:
	.quad	.LVL12
	.quad	.LVL13-1
	.value	0x1
	.byte	0x55
	.quad	.LVL13-1
	.quad	.LFE86
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS7:
	.uleb128 0
	.uleb128 .LVU44
	.uleb128 .LVU44
	.uleb128 0
.LLST7:
	.quad	.LVL12
	.quad	.LVL13-1
	.value	0x1
	.byte	0x54
	.quad	.LVL13-1
	.quad	.LFE86
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS8:
	.uleb128 0
	.uleb128 .LVU44
	.uleb128 .LVU44
	.uleb128 0
.LLST8:
	.quad	.LVL12
	.quad	.LVL13-1
	.value	0x1
	.byte	0x51
	.quad	.LVL13-1
	.quad	.LFE86
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x51
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS9:
	.uleb128 .LVU44
	.uleb128 .LVU47
.LLST9:
	.quad	.LVL13
	.quad	.LVL14
	.value	0x1
	.byte	0x50
	.quad	0
	.quad	0
.LVUS5:
	.uleb128 .LVU39
	.uleb128 0
.LLST5:
	.quad	.LVL11
	.quad	.LFE85
	.value	0x1
	.byte	0x50
	.quad	0
	.quad	0
.LVUS4:
	.uleb128 .LVU29
	.uleb128 0
.LLST4:
	.quad	.LVL9
	.quad	.LFE48
	.value	0x1
	.byte	0x50
	.quad	0
	.quad	0
.LVUS3:
	.uleb128 .LVU20
	.uleb128 0
.LLST3:
	.quad	.LVL7
	.quad	.LFE39
	.value	0x1
	.byte	0x50
	.quad	0
	.quad	0
.LVUS2:
	.uleb128 0
	.uleb128 .LVU14
	.uleb128 .LVU14
	.uleb128 0
.LLST2:
	.quad	.LVL5
	.quad	.LVL6-1
	.value	0x1
	.byte	0x55
	.quad	.LVL6-1
	.quad	.LFE26
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS1:
	.uleb128 0
	.uleb128 .LVU11
	.uleb128 .LVU11
	.uleb128 0
.LLST1:
	.quad	.LVL3
	.quad	.LVL4-1
	.value	0x1
	.byte	0x55
	.quad	.LVL4-1
	.quad	.LFE25
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS0:
	.uleb128 0
	.uleb128 .LVU5
	.uleb128 .LVU5
	.uleb128 0
.LLST0:
	.quad	.LVL0
	.quad	.LVL1
	.value	0x1
	.byte	0x55
	.quad	.LVL1
	.quad	.LFE24
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS14:
	.uleb128 0
	.uleb128 .LVU109
	.uleb128 .LVU109
	.uleb128 0
.LLST14:
	.quad	.LVL22
	.quad	.LVL30
	.value	0x1
	.byte	0x55
	.quad	.LVL30
	.quad	.LFE0
	.value	0x3
	.byte	0x7d
	.sleb128 -8
	.byte	0x9f
	.quad	0
	.quad	0
.LVUS15:
	.uleb128 .LVU93
	.uleb128 .LVU121
.LLST15:
	.quad	.LVL23
	.quad	.LVL38
	.value	0x1
	.byte	0x56
	.quad	0
	.quad	0
.LVUS16:
	.uleb128 .LVU95
	.uleb128 0
.LLST16:
	.quad	.LVL24
	.quad	.LFE0
	.value	0x1
	.byte	0x5d
	.quad	0
	.quad	0
.LVUS17:
	.uleb128 .LVU97
	.uleb128 0
.LLST17:
	.quad	.LVL25
	.quad	.LFE0
	.value	0x1
	.byte	0x5c
	.quad	0
	.quad	0
.LVUS18:
	.uleb128 .LVU121
	.uleb128 .LVU124
	.uleb128 .LVU124
	.uleb128 0
.LLST18:
	.quad	.LVL38
	.quad	.LVL40
	.value	0x1
	.byte	0x50
	.quad	.LVL40
	.quad	.LFE0
	.value	0x1
	.byte	0x56
	.quad	0
	.quad	0
.LVUS19:
	.uleb128 .LVU109
	.uleb128 .LVU114
	.uleb128 .LVU115
	.uleb128 .LVU123
.LLST19:
	.quad	.LVL30
	.quad	.LVL33
	.value	0x1
	.byte	0x53
	.quad	.LVL34
	.quad	.LVL39
	.value	0x1
	.byte	0x53
	.quad	0
	.quad	0
.LVUS20:
	.uleb128 .LVU124
	.uleb128 0
.LLST20:
	.quad	.LVL40
	.quad	.LFE0
	.value	0x1
	.byte	0x53
	.quad	0
	.quad	0
.LVUS21:
	.uleb128 .LVU99
	.uleb128 .LVU100
	.uleb128 .LVU100
	.uleb128 .LVU109
.LLST21:
	.quad	.LVL26
	.quad	.LVL27
	.value	0x1
	.byte	0x5c
	.quad	.LVL27
	.quad	.LVL30
	.value	0x1
	.byte	0x50
	.quad	0
	.quad	0
	.section	.debug_aranges,"",@progbits
	.long	0x5c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x8
	.byte	0
	.value	0
	.value	0
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.quad	.LFB152
	.quad	.LFE152-.LFB152
	.quad	.LFB168
	.quad	.LFE168-.LFB168
	.quad	.LFB184
	.quad	.LFE184-.LFB184
	.quad	0
	.quad	0
	.section	.debug_ranges,"",@progbits
.Ldebug_ranges0:
	.quad	.LBB6
	.quad	.LBE6
	.quad	.LBB7
	.quad	.LBE7
	.quad	0
	.quad	0
	.quad	.LBB8
	.quad	.LBE8
	.quad	.LBB9
	.quad	.LBE9
	.quad	0
	.quad	0
	.quad	.LBB10
	.quad	.LBE10
	.quad	.LBB11
	.quad	.LBE11
	.quad	0
	.quad	0
	.quad	.LBB12
	.quad	.LBE12
	.quad	.LBB13
	.quad	.LBE13
	.quad	0
	.quad	0
	.quad	.Ltext0
	.quad	.Letext0
	.quad	.LFB152
	.quad	.LFE152
	.quad	.LFB168
	.quad	.LFE168
	.quad	.LFB184
	.quad	.LFE184
	.quad	0
	.quad	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF73:
	.string	"_arg2"
.LASF74:
	.string	"_arg3"
.LASF30:
	.string	"optind"
.LASF29:
	.string	"optarg"
.LASF66:
	.string	"write"
.LASF42:
	.string	"isdigit"
.LASF85:
	.string	"envp"
.LASF23:
	.string	"__int128 unsigned"
.LASF14:
	.string	"environ"
.LASF3:
	.string	"short int"
.LASF8:
	.string	"size_t"
.LASF11:
	.string	"intptr_t"
.LASF58:
	.string	"putchar"
.LASF44:
	.string	"isalnum"
.LASF46:
	.string	"isspace"
.LASF51:
	.string	"main"
.LASF80:
	.string	"sys_exit"
.LASF93:
	.string	"/home/boricj/Documents/ghidra-delinker-extension/src/test/resources/ascii-table/reference/elf_linux_freestanding"
.LASF22:
	.string	"__int128"
.LASF9:
	.string	"ssize_t"
.LASF34:
	.string	"matches"
.LASF75:
	.string	"sys_kill"
.LASF71:
	.string	"_num"
.LASF94:
	.string	"__stack_chk_init"
.LASF86:
	.string	"exitcode"
.LASF76:
	.string	"sys_getpid"
.LASF90:
	.string	"_nolibc_main"
.LASF83:
	.string	"argc"
.LASF1:
	.string	"signed char"
.LASF28:
	.string	"stderr"
.LASF6:
	.string	"long long int"
.LASF5:
	.string	"long long unsigned int"
.LASF53:
	.string	"properties"
.LASF54:
	.string	"num_ascii_properties"
.LASF81:
	.string	"itoa_buffer"
.LASF10:
	.string	"long int"
.LASF38:
	.string	"s_ascii_properties"
.LASF43:
	.string	"isalpha"
.LASF33:
	.string	"dummy"
.LASF49:
	.string	"isgraph"
.LASF19:
	.string	"__init_array_end"
.LASF61:
	.string	"fileno"
.LASF77:
	.string	"exit"
.LASF87:
	.string	"ctor_func"
.LASF15:
	.string	"_auxv"
.LASF40:
	.string	"islower"
.LASF0:
	.string	"unsigned char"
.LASF88:
	.string	"dtor_func"
.LASF62:
	.string	"abort"
.LASF70:
	.string	"_ret"
.LASF18:
	.string	"__init_array_start"
.LASF4:
	.string	"unsigned int"
.LASF91:
	.string	"GNU C17 14.2.0 -mtune=generic -march=x86-64 -gdwarf-4 -Og -ffreestanding -fno-pic -fno-plt -fasynchronous-unwind-tables"
.LASF69:
	.string	"sys_write"
.LASF17:
	.string	"__preinit_array_end"
.LASF60:
	.string	"stream"
.LASF84:
	.string	"argv"
.LASF31:
	.string	"opterr"
.LASF78:
	.string	"status"
.LASF2:
	.string	"short unsigned int"
.LASF24:
	.string	"errno"
.LASF13:
	.string	"char"
.LASF65:
	.string	"signal"
.LASF63:
	.string	"strlen"
.LASF59:
	.string	"fputc"
.LASF48:
	.string	"isprint"
.LASF79:
	.string	"_exit"
.LASF92:
	.string	"/home/boricj/Documents/ghidra-delinker-extension/src/test/resources/ascii-table/src/main.c"
.LASF41:
	.string	"isupper"
.LASF37:
	.string	"NUM_ASCII_PROPERTIES"
.LASF95:
	.string	"_start"
.LASF56:
	.string	"print_number"
.LASF39:
	.string	"COLUMNS"
.LASF7:
	.string	"long unsigned int"
.LASF36:
	.string	"ascii_property"
.LASF89:
	.string	"auxv"
.LASF50:
	.string	"character"
.LASF21:
	.string	"__fini_array_end"
.LASF82:
	.string	"_start_c"
.LASF67:
	.string	"count"
.LASF20:
	.string	"__fini_array_start"
.LASF26:
	.string	"stdin"
.LASF16:
	.string	"__preinit_array_start"
.LASF47:
	.string	"iscntrl"
.LASF57:
	.string	"digit"
.LASF35:
	.string	"flag"
.LASF32:
	.string	"optopt"
.LASF25:
	.string	"FILE"
.LASF64:
	.string	"raise"
.LASF45:
	.string	"ispunct"
.LASF12:
	.string	"pid_t"
.LASF55:
	.string	"property"
.LASF52:
	.string	"print_ascii_entry"
.LASF27:
	.string	"stdout"
.LASF68:
	.string	"__sysret_arg"
.LASF72:
	.string	"_arg1"
	.ident	"GCC: (Debian 14.2.0-19) 14.2.0"
	.section	.note.GNU-stack,"",@progbits
