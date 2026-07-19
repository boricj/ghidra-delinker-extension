	.file	"allocator.c"
	.section	.ctf,"",@progbits
.Lctf0:
	.value	0xdff2
	.byte	0x4
	.byte	0x2
	.long	0
	.long	0
	.long	0x137
	.long	0
	.long	0
	.long	0
	.long	0x30
	.long	0x30
	.long	0x60
	.long	0x60
	.long	0x274
	.long	0x1b7
	.long	0x1e
	.long	0x14
	.long	0x1a
	.long	0x18
	.long	0x12
	.long	0x1d
	.long	0x19
	.long	0x1b
	.long	0x11
	.long	0x10
	.long	0x15
	.long	0x13
	.long	0x12e
	.long	0xc0
	.long	0x104
	.long	0xea
	.long	0xa3
	.long	0x121
	.long	0xf8
	.long	0x113
	.long	0x95
	.long	0x8e
	.long	0xcc
	.long	0xb2
	.long	0x1
	.long	0x6000000
	.long	0x8
	.long	0x1000040
	.long	0xa
	.long	0x2a000000
	.long	0x1
	.long	0x14
	.long	0x6000000
	.long	0x8
	.long	0x40
	.long	0x26
	.long	0x2a000000
	.long	0x3
	.long	0x2d
	.long	0x6000000
	.long	0x4
	.long	0x1000020
	.long	0x31
	.long	0x6000000
	.long	0x8
	.long	0x1000040
	.long	0x3f
	.long	0xa000000
	.long	0x10
	.long	0x6000080
	.long	0x4b
	.long	0x1a000002
	.long	0x10
	.long	0x65
	.long	0
	.long	0xa
	.long	0x6a
	.long	0x40
	.long	0x2
	.long	0x58
	.long	0x2a000000
	.long	0x8
	.long	0
	.long	0xe000000
	.long	0x9
	.long	0
	.long	0x32000000
	.long	0x9
	.long	0x71
	.long	0x6000000
	.long	0x2
	.long	0x10
	.long	0x84
	.long	0x6000000
	.long	0x1
	.long	0x3000008
	.long	0x89
	.long	0x6000000
	.long	0
	.long	0x1000000
	.long	0
	.long	0xe000000
	.long	0xe
	.long	0x8e
	.long	0x16000003
	.long	0xf
	.long	0xf
	.long	0x5
	.long	0x4
	.long	0
	.long	0x95
	.long	0x16000002
	.long	0xe
	.long	0xf
	.long	0xf
	.long	0xa3
	.long	0x16000002
	.long	0xf
	.long	0xf
	.long	0x4
	.long	0xb2
	.long	0x16000002
	.long	0xe
	.long	0xf
	.long	0x4
	.long	0xc0
	.long	0x16000002
	.long	0xe
	.long	0xa
	.long	0x4
	.long	0xcc
	.long	0x16000001
	.long	0xa
	.long	0xf
	.long	0
	.long	0xdc
	.long	0x6000000
	.long	0x1
	.long	0x2000008
	.long	0
	.long	0xe000000
	.long	0x16
	.long	0xea
	.long	0x16000001
	.long	0x17
	.long	0xa
	.long	0
	.long	0xf8
	.long	0x16000004
	.long	0xe
	.long	0xa
	.long	0xa
	.long	0x4
	.long	0x5
	.long	0x104
	.long	0x16000002
	.long	0xe
	.long	0xa
	.long	0x5
	.long	0x113
	.long	0x16000001
	.long	0x5
	.long	0x1c
	.long	0
	.long	0
	.long	0xe000000
	.long	0xb
	.long	0x121
	.long	0x16000001
	.long	0x4
	.long	0x1c
	.long	0
	.long	0x12e
	.long	0x16000001
	.long	0x4
	.long	0x4
	.long	0
	.string	""
	.string	"long int"
	.string	"ptrdiff_t"
	.string	"long unsigned int"
	.string	"size_t"
	.string	"int"
	.string	"long long int"
	.string	"long double"
	.string	"chunk_header"
	.string	"chunk_header"
	.string	"next"
	.string	"length"
	.string	"short unsigned int"
	.string	"char"
	.string	"void"
	.string	"memset"
	.string	"freelist_free"
	.string	"freelist_alloc"
	.string	"freelist_init"
	.string	"chunk_split"
	.string	"chunk_from_data"
	.string	"unsigned char"
	.string	"chunk_to_data"
	.string	"chunk_write"
	.string	"chunk_set_used"
	.string	"chunk_is_used"
	.string	"chunk_length"
	.string	"align_up"
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/src/allocator.c"
	.text
.Ltext0:
	.file 1 "src/allocator.c"
	.type	align_up, @function
align_up:
.LFB0:
	.loc 1 5 38
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -24(%rbp)
	.loc 1 6 12
	movq	$7, -8(%rbp)
	.loc 1 7 19
	movq	-24(%rbp), %rdx
	movq	-8(%rbp), %rax
	addq	%rax, %rdx
	.loc 1 7 26
	movq	-8(%rbp), %rax
	notq	%rax
	.loc 1 7 24
	andq	%rdx, %rax
	.loc 1 8 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	align_up, .-align_up
	.type	chunk_length, @function
chunk_length:
.LFB1:
	.loc 1 10 55
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	.loc 1 11 47
	movq	-8(%rbp), %rax
	movq	8(%rax), %rax
	.loc 1 11 12
	movq	%rax, %rdx
	negq	%rdx
	cmovns	%rdx, %rax
	.loc 1 12 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	chunk_length, .-chunk_length
	.type	chunk_is_used, @function
chunk_is_used:
.LFB2:
	.loc 1 14 53
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	.loc 1 15 17
	movq	-8(%rbp), %rax
	movq	8(%rax), %rax
	.loc 1 15 26
	shrq	$63, %rax
	movzbl	%al, %eax
	.loc 1 16 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	chunk_is_used, .-chunk_is_used
	.type	chunk_set_used, @function
chunk_set_used:
.LFB3:
	.loc 1 18 59
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movl	%esi, -12(%rbp)
	.loc 1 19 9
	movq	-8(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_is_used
	.loc 1 19 8
	cmpl	%eax, -12(%rbp)
	je	.L10
	.loc 1 23 27
	movq	-8(%rbp), %rax
	movq	8(%rax), %rax
	.loc 1 23 21
	negq	%rax
	movq	%rax, %rdx
	.loc 1 23 19
	movq	-8(%rbp), %rax
	movq	%rdx, 8(%rax)
	jmp	.L7
.L10:
	.loc 1 20 9
	nop
.L7:
	.loc 1 24 1
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	chunk_set_used, .-chunk_set_used
	.type	chunk_write, @function
chunk_write:
.LFB4:
	.loc 1 26 91
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	movq	%rdx, -24(%rbp)
	movl	%ecx, -28(%rbp)
	.loc 1 27 17
	movq	-8(%rbp), %rax
	movq	-16(%rbp), %rdx
	movq	%rdx, (%rax)
	.loc 1 28 50
	cmpl	$0, -28(%rbp)
	je	.L12
	.loc 1 28 30 discriminator 1
	movq	-24(%rbp), %rax
	.loc 1 28 50 discriminator 1
	negq	%rax
	jmp	.L13
.L12:
	.loc 1 28 50 is_stmt 0 discriminator 2
	movq	-24(%rbp), %rax
.L13:
	.loc 1 28 19 is_stmt 1 discriminator 4
	movq	-8(%rbp), %rdx
	movq	%rax, 8(%rdx)
	.loc 1 29 1 discriminator 4
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE4:
	.size	chunk_write, .-chunk_write
	.type	chunk_to_data, @function
chunk_to_data:
.LFB5:
	.loc 1 31 58
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	.loc 1 32 38
	movq	-8(%rbp), %rax
	addq	$16, %rax
	.loc 1 33 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	chunk_to_data, .-chunk_to_data
	.type	chunk_from_data, @function
chunk_from_data:
.LFB6:
	.loc 1 35 49
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -8(%rbp)
	.loc 1 36 12
	movq	-8(%rbp), %rax
	subq	$16, %rax
	.loc 1 37 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE6:
	.size	chunk_from_data, .-chunk_from_data
	.type	chunk_split, @function
chunk_split:
.LFB7:
	.loc 1 39 64
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movq	%rsi, -32(%rbp)
	.loc 1 40 19
	movq	-24(%rbp), %rdx
	movq	-32(%rbp), %rax
	addq	%rdx, %rax
	movq	%rax, -8(%rbp)
	.loc 1 41 19
	movq	-24(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_length
	.loc 1 41 9
	subq	-32(%rbp), %rax
	movq	%rax, -16(%rbp)
	.loc 1 44 5
	cmpq	$31, -16(%rbp)
	jbe	.L21
	.loc 1 48 5
	movq	-24(%rbp), %rax
	movq	(%rax), %rsi
	movq	-16(%rbp), %rdx
	movq	-8(%rbp), %rax
	movl	$0, %ecx
	movq	%rax, %rdi
	call	chunk_write
	.loc 1 49 5
	movq	-24(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_is_used
	movl	%eax, %ecx
	movq	-32(%rbp), %rdx
	movq	-8(%rbp), %rsi
	movq	-24(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_write
	jmp	.L18
.L21:
	.loc 1 45 3
	nop
.L18:
	.loc 1 50 1
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE7:
	.size	chunk_split, .-chunk_split
	.globl	freelist_init
	.type	freelist_init, @function
freelist_init:
.LFB8:
	.loc 1 52 50
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$16, %rsp
	movq	%rdi, -8(%rbp)
	movq	%rsi, -16(%rbp)
	.loc 1 53 5
	movq	-16(%rbp), %rdx
	movq	-8(%rbp), %rax
	movl	$0, %ecx
	movl	$0, %esi
	movq	%rax, %rdi
	call	chunk_write
	.loc 1 54 1
	nop
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE8:
	.size	freelist_init, .-freelist_init
	.globl	freelist_alloc
	.type	freelist_alloc, @function
freelist_alloc:
.LFB9:
	.loc 1 56 47
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movq	%rdi, -24(%rbp)
	movq	%rsi, -32(%rbp)
	.loc 1 57 47
	movq	-32(%rbp), %rax
	movq	%rax, %rdi
	call	align_up
	.loc 1 57 12
	addq	$16, %rax
	movq	%rax, -8(%rbp)
	.loc 1 60 8
	cmpq	$0, -32(%rbp)
	jne	.L24
	.loc 1 61 16
	movl	$0, %eax
	jmp	.L25
.L24:
	.loc 1 65 5
	cmpq	$31, -8(%rbp)
	ja	.L26
	.loc 1 66 13
	movq	$32, -8(%rbp)
.L26:
	.loc 1 70 14
	movq	-24(%rbp), %rax
	movq	%rax, -16(%rbp)
	.loc 1 70 5
	jmp	.L27
.L29:
	.loc 1 71 14
	movq	-16(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_is_used
	.loc 1 71 12
	testl	%eax, %eax
	jne	.L28
	.loc 1 71 36 discriminator 1
	movq	-16(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_length
	.loc 1 71 33 discriminator 1
	cmpq	-8(%rbp), %rax
	jb	.L28
	.loc 1 72 13
	movq	-8(%rbp), %rdx
	movq	-16(%rbp), %rax
	movq	%rdx, %rsi
	movq	%rax, %rdi
	call	chunk_split
	.loc 1 73 13
	movq	-16(%rbp), %rax
	movl	$1, %esi
	movq	%rax, %rdi
	call	chunk_set_used
	.loc 1 75 20
	movq	-16(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_to_data
	jmp	.L25
.L28:
	.loc 1 70 56 discriminator 2
	movq	-16(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -16(%rbp)
.L27:
	.loc 1 70 43 discriminator 1
	cmpq	$0, -16(%rbp)
	jne	.L29
	.loc 1 79 12
	movl	$0, %eax
.L25:
	.loc 1 80 1
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE9:
	.size	freelist_alloc, .-freelist_alloc
	.globl	freelist_free
	.type	freelist_free, @function
freelist_free:
.LFB10:
	.loc 1 82 43
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%rbx
	subq	$40, %rsp
	.cfi_offset 3, -24
	movq	%rdi, -40(%rbp)
	movq	%rsi, -48(%rbp)
	.loc 1 85 8
	cmpq	$0, -48(%rbp)
	je	.L36
	.loc 1 90 13
	movq	-48(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_from_data
	movq	%rax, -24(%rbp)
	.loc 1 91 5
	movq	-24(%rbp), %rax
	movl	$0, %esi
	movq	%rax, %rdi
	call	chunk_set_used
	.loc 1 92 20
	movq	-24(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_length
	.loc 1 92 5
	leaq	-16(%rax), %rdx
	movq	-48(%rbp), %rax
	movl	$0, %esi
	movq	%rax, %rdi
	call	memset@PLT
	.loc 1 95 11
	movq	-40(%rbp), %rax
	movq	%rax, -24(%rbp)
	.loc 1 96 11
	jmp	.L33
.L35:
	.loc 1 97 14
	movq	-24(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_is_used
	.loc 1 97 12
	testl	%eax, %eax
	jne	.L34
	.loc 1 97 58 discriminator 1
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	.loc 1 97 39 discriminator 1
	movq	%rax, %rdi
	call	chunk_is_used
	.loc 1 97 35 discriminator 1
	testl	%eax, %eax
	jne	.L34
.LBB2:
	.loc 1 98 19
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -32(%rbp)
	.loc 1 100 51
	movq	-24(%rbp), %rax
	movq	%rax, %rdi
	call	chunk_length
	movq	%rax, %rbx
	.loc 1 100 91
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	.loc 1 100 73
	movq	%rax, %rdi
	call	chunk_length
	.loc 1 100 13
	leaq	(%rbx,%rax), %rdx
	.loc 1 100 37
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	.loc 1 100 13
	movq	(%rax), %rsi
	movq	-24(%rbp), %rax
	movl	$0, %ecx
	movq	%rax, %rdi
	call	chunk_write
	.loc 1 101 13
	movq	-32(%rbp), %rax
	movl	$16, %edx
	movl	$0, %esi
	movq	%rax, %rdi
	call	memset@PLT
.LBE2:
	.loc 1 97 67
	jmp	.L33
.L34:
	.loc 1 103 19
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	movq	%rax, -24(%rbp)
.L33:
	.loc 1 96 26
	cmpq	$0, -24(%rbp)
	je	.L30
	.loc 1 96 34 discriminator 1
	movq	-24(%rbp), %rax
	movq	(%rax), %rax
	.loc 1 96 26 discriminator 1
	testq	%rax, %rax
	jne	.L35
	jmp	.L30
.L36:
	.loc 1 86 9
	nop
.L30:
	.loc 1 106 1
	movq	-8(%rbp), %rbx
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE10:
	.size	freelist_free, .-freelist_free
.Letext0:
	.file 2 "/usr/lib/gcc/x86_64-linux-gnu/12/include/stddef.h"
	.file 3 "/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/include/allocator.h"
	.file 4 "/usr/include/string.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x3e6
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.long	.LASF32
	.byte	0xc
	.long	.LASF33
	.long	.LASF34
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.long	.LASF0
	.byte	0x2
	.byte	0x91
	.byte	0x1a
	.long	0x39
	.uleb128 0x3
	.byte	0x8
	.byte	0x5
	.long	.LASF2
	.uleb128 0x2
	.long	.LASF1
	.byte	0x2
	.byte	0xd6
	.byte	0x17
	.long	0x4c
	.uleb128 0x3
	.byte	0x8
	.byte	0x7
	.long	.LASF3
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x3
	.byte	0x8
	.byte	0x5
	.long	.LASF4
	.uleb128 0x3
	.byte	0x10
	.byte	0x4
	.long	.LASF5
	.uleb128 0x2
	.long	.LASF6
	.byte	0x3
	.byte	0x9
	.byte	0x1d
	.long	0x79
	.uleb128 0x5
	.long	0x68
	.uleb128 0x6
	.long	.LASF6
	.byte	0x10
	.byte	0x3
	.byte	0xb
	.byte	0x8
	.long	0xa1
	.uleb128 0x7
	.long	.LASF7
	.byte	0x3
	.byte	0xc
	.byte	0x13
	.long	0xa1
	.byte	0
	.uleb128 0x7
	.long	.LASF8
	.byte	0x3
	.byte	0xd
	.byte	0xf
	.long	0x2d
	.byte	0x8
	.byte	0
	.uleb128 0x8
	.byte	0x8
	.long	0x68
	.uleb128 0x3
	.byte	0x2
	.byte	0x7
	.long	.LASF9
	.uleb128 0x3
	.byte	0x1
	.byte	0x6
	.long	.LASF10
	.uleb128 0x9
	.long	.LASF35
	.byte	0x4
	.byte	0x3d
	.byte	0xe
	.long	0xd5
	.long	0xd5
	.uleb128 0xa
	.long	0xd5
	.uleb128 0xa
	.long	0x53
	.uleb128 0xa
	.long	0x40
	.byte	0
	.uleb128 0xb
	.byte	0x8
	.uleb128 0xc
	.long	.LASF16
	.byte	0x1
	.byte	0x52
	.byte	0x6
	.quad	.LFB10
	.quad	.LFE10-.LFB10
	.uleb128 0x1
	.byte	0x9c
	.long	0x144
	.uleb128 0xd
	.long	.LASF11
	.byte	0x1
	.byte	0x52
	.byte	0x1a
	.long	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -56
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x52
	.byte	0x26
	.long	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -64
	.uleb128 0xf
	.long	.LASF12
	.byte	0x1
	.byte	0x53
	.byte	0x13
	.long	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -40
	.uleb128 0x10
	.quad	.LBB2
	.quad	.LBE2-.LBB2
	.uleb128 0xf
	.long	.LASF13
	.byte	0x1
	.byte	0x62
	.byte	0x13
	.long	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -48
	.byte	0
	.byte	0
	.uleb128 0x11
	.long	.LASF36
	.byte	0x1
	.byte	0x38
	.byte	0x7
	.long	0xd5
	.quad	.LFB9
	.quad	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.long	0x1a3
	.uleb128 0xd
	.long	.LASF11
	.byte	0x1
	.byte	0x38
	.byte	0x1c
	.long	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -40
	.uleb128 0xd
	.long	.LASF14
	.byte	0x1
	.byte	0x38
	.byte	0x29
	.long	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -48
	.uleb128 0xf
	.long	.LASF15
	.byte	0x1
	.byte	0x39
	.byte	0xc
	.long	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0x12
	.string	"cur"
	.byte	0x1
	.byte	0x3a
	.byte	0x13
	.long	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.byte	0
	.uleb128 0xc
	.long	.LASF17
	.byte	0x1
	.byte	0x34
	.byte	0x6
	.quad	.LFB8
	.quad	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.long	0x1e0
	.uleb128 0xd
	.long	.LASF11
	.byte	0x1
	.byte	0x34
	.byte	0x1a
	.long	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xd
	.long	.LASF18
	.byte	0x1
	.byte	0x34
	.byte	0x27
	.long	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.byte	0
	.uleb128 0x13
	.long	.LASF24
	.byte	0x1
	.byte	0x27
	.byte	0xd
	.quad	.LFB7
	.quad	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.long	0x23b
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x27
	.byte	0x27
	.long	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -40
	.uleb128 0xd
	.long	.LASF15
	.byte	0x1
	.byte	0x27
	.byte	0x35
	.long	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -48
	.uleb128 0xf
	.long	.LASF19
	.byte	0x1
	.byte	0x28
	.byte	0x13
	.long	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xf
	.long	.LASF20
	.byte	0x1
	.byte	0x29
	.byte	0x9
	.long	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.byte	0
	.uleb128 0x14
	.long	.LASF21
	.byte	0x1
	.byte	0x23
	.byte	0x16
	.long	0xa1
	.quad	.LFB6
	.quad	.LFE6-.LFB6
	.uleb128 0x1
	.byte	0x9c
	.long	0x26d
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x23
	.byte	0x2c
	.long	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0x14
	.long	.LASF22
	.byte	0x1
	.byte	0x1f
	.byte	0x17
	.long	0x29f
	.quad	.LFB5
	.quad	.LFE5-.LFB5
	.uleb128 0x1
	.byte	0x9c
	.long	0x29f
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x1f
	.byte	0x33
	.long	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0x8
	.byte	0x8
	.long	0x2a5
	.uleb128 0x3
	.byte	0x1
	.byte	0x8
	.long	.LASF23
	.uleb128 0x15
	.long	.LASF25
	.byte	0x1
	.byte	0x1a
	.byte	0xd
	.quad	.LFB4
	.quad	.LFE4-.LFB4
	.uleb128 0x1
	.byte	0x9c
	.long	0x307
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x1a
	.byte	0x27
	.long	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xd
	.long	.LASF7
	.byte	0x1
	.byte	0x1a
	.byte	0x3c
	.long	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0xd
	.long	.LASF8
	.byte	0x1
	.byte	0x1a
	.byte	0x49
	.long	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -40
	.uleb128 0xd
	.long	.LASF26
	.byte	0x1
	.byte	0x1a
	.byte	0x55
	.long	0x53
	.uleb128 0x2
	.byte	0x91
	.sleb128 -44
	.byte	0
	.uleb128 0x13
	.long	.LASF27
	.byte	0x1
	.byte	0x12
	.byte	0xd
	.quad	.LFB3
	.quad	.LFE3-.LFB3
	.uleb128 0x1
	.byte	0x9c
	.long	0x344
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x12
	.byte	0x2a
	.long	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xd
	.long	.LASF26
	.byte	0x1
	.byte	0x12
	.byte	0x35
	.long	0x53
	.uleb128 0x2
	.byte	0x91
	.sleb128 -28
	.byte	0
	.uleb128 0x14
	.long	.LASF28
	.byte	0x1
	.byte	0xe
	.byte	0xc
	.long	0x53
	.quad	.LFB2
	.quad	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.long	0x376
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0xe
	.byte	0x2e
	.long	0x376
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0x8
	.byte	0x8
	.long	0x74
	.uleb128 0x14
	.long	.LASF29
	.byte	0x1
	.byte	0xa
	.byte	0xf
	.long	0x40
	.quad	.LFB1
	.quad	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.long	0x3ae
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0xa
	.byte	0x30
	.long	0x376
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0x16
	.long	.LASF30
	.byte	0x1
	.byte	0x5
	.byte	0xf
	.long	0x40
	.quad	.LFB0
	.quad	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.long	.LASF31
	.byte	0x1
	.byte	0x5
	.byte	0x1f
	.long	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -40
	.uleb128 0x12
	.string	"m"
	.byte	0x1
	.byte	0x6
	.byte	0xc
	.long	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
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
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
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
	.uleb128 0x3
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
	.uleb128 0x4
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
	.uleb128 0x5
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
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
	.uleb128 0x7
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
	.uleb128 0x8
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x9
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
	.uleb128 0xa
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0xc
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
	.uleb128 0xd
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
	.uleb128 0xe
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
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.byte	0
	.byte	0
	.uleb128 0x11
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
	.uleb128 0x2116
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x12
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
	.uleb128 0x13
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
	.uleb128 0x14
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
	.uleb128 0x15
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
	.uleb128 0x16
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
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.long	0x2c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x8
	.byte	0
	.value	0
	.value	0
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.quad	0
	.quad	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF18:
	.string	"heap_size"
.LASF1:
	.string	"size_t"
.LASF7:
	.string	"next"
.LASF31:
	.string	"value"
.LASF15:
	.string	"requested"
.LASF36:
	.string	"freelist_alloc"
.LASF16:
	.string	"freelist_free"
.LASF22:
	.string	"chunk_to_data"
.LASF27:
	.string	"chunk_set_used"
.LASF14:
	.string	"size"
.LASF3:
	.string	"long unsigned int"
.LASF29:
	.string	"chunk_length"
.LASF9:
	.string	"short unsigned int"
.LASF19:
	.string	"new_chunk"
.LASF13:
	.string	"old_next"
.LASF6:
	.string	"chunk_header"
.LASF35:
	.string	"memset"
.LASF28:
	.string	"chunk_is_used"
.LASF0:
	.string	"ptrdiff_t"
.LASF20:
	.string	"new_len"
.LASF12:
	.string	"chunk"
.LASF23:
	.string	"unsigned char"
.LASF10:
	.string	"char"
.LASF11:
	.string	"heap"
.LASF37:
	.string	"void"
.LASF4:
	.string	"long long int"
.LASF34:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator"
.LASF17:
	.string	"freelist_init"
.LASF38:
	.string	"unknown"
.LASF21:
	.string	"chunk_from_data"
.LASF26:
	.string	"used"
.LASF24:
	.string	"chunk_split"
.LASF33:
	.string	"src/allocator.c"
.LASF25:
	.string	"chunk_write"
.LASF2:
	.string	"long int"
.LASF30:
	.string	"align_up"
.LASF5:
	.string	"long double"
.LASF32:
	.string	"GNU C17 12.2.0 -mtune=generic -march=x86-64 -gdwarf-4 -gctf -fasynchronous-unwind-tables"
.LASF8:
	.string	"length"
	.ident	"GCC: (Debian 12.2.0-14+deb12u1) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
