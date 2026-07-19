	.file	"allocator.c"
	.section	.ctf,"",@progbits
.Lctf0:
	.value	0xdff2
	.byte	0x4
	.byte	0x2
	.long	0
	.long	0
	.long	0x13a
	.long	0
	.long	0
	.long	0
	.long	0x30
	.long	0x30
	.long	0x60
	.long	0x60
	.long	0x280
	.long	0x1ba
	.long	0x19
	.long	0x14
	.long	0x13
	.long	0x11
	.long	0x1e
	.long	0x16
	.long	0x1b
	.long	0x12
	.long	0x1f
	.long	0x1c
	.long	0x15
	.long	0x1a
	.long	0xed
	.long	0xb5
	.long	0xa6
	.long	0x91
	.long	0x124
	.long	0xcf
	.long	0x107
	.long	0x98
	.long	0x131
	.long	0x116
	.long	0xc3
	.long	0xfb
	.long	0x1
	.long	0x6000000
	.long	0x4
	.long	0x1000020
	.long	0x5
	.long	0x2a000000
	.long	0x1
	.long	0xf
	.long	0x6000000
	.long	0x4
	.long	0x20
	.long	0x1c
	.long	0x2a000000
	.long	0x3
	.long	0x23
	.long	0x6000000
	.long	0x4
	.long	0x1000020
	.long	0x2c
	.long	0x6000000
	.long	0x8
	.long	0x1000040
	.long	0x3a
	.long	0xa000000
	.long	0x10
	.long	0x6000060
	.long	0x46
	.long	0x2000000
	.long	0
	.long	0x4e
	.long	0x1a000002
	.long	0x8
	.long	0x68
	.long	0
	.long	0xb
	.long	0x6d
	.long	0x20
	.long	0x2
	.long	0x5b
	.long	0x2a000000
	.long	0x9
	.long	0
	.long	0xe000000
	.long	0xa
	.long	0
	.long	0x32000000
	.long	0xa
	.long	0x74
	.long	0x6000000
	.long	0x2
	.long	0x10
	.long	0x87
	.long	0x6000000
	.long	0x1
	.long	0x3000008
	.long	0x8c
	.long	0x6000000
	.long	0
	.long	0x1000000
	.long	0
	.long	0xe000000
	.long	0xf
	.long	0x91
	.long	0x16000003
	.long	0x10
	.long	0x10
	.long	0x1
	.long	0x4
	.long	0
	.long	0x98
	.long	0x16000002
	.long	0xf
	.long	0x10
	.long	0x10
	.long	0xa6
	.long	0x16000002
	.long	0x10
	.long	0x10
	.long	0x4
	.long	0xb5
	.long	0x16000002
	.long	0xf
	.long	0x10
	.long	0x4
	.long	0xc3
	.long	0x16000002
	.long	0xf
	.long	0xb
	.long	0x4
	.long	0xcf
	.long	0x16000001
	.long	0xb
	.long	0x10
	.long	0
	.long	0xdf
	.long	0x6000000
	.long	0x1
	.long	0x2000008
	.long	0
	.long	0xe000000
	.long	0x17
	.long	0xed
	.long	0x16000001
	.long	0x18
	.long	0xb
	.long	0
	.long	0xfb
	.long	0x16000004
	.long	0xf
	.long	0xb
	.long	0xb
	.long	0x4
	.long	0x1
	.long	0x107
	.long	0x16000002
	.long	0xf
	.long	0xb
	.long	0x1
	.long	0x116
	.long	0x16000001
	.long	0x1
	.long	0x1d
	.long	0
	.long	0
	.long	0xe000000
	.long	0xc
	.long	0x124
	.long	0x16000001
	.long	0x4
	.long	0x1d
	.long	0
	.long	0x131
	.long	0x16000001
	.long	0x4
	.long	0x4
	.long	0
	.string	""
	.string	"int"
	.string	"ptrdiff_t"
	.string	"unsigned int"
	.string	"size_t"
	.string	"long int"
	.string	"long long int"
	.string	"long double"
	.string	"unknown"
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
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	subl	$16, %esp
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	.loc 1 6 12
	movl	$3, -4(%ebp)
	.loc 1 7 19
	movl	8(%ebp), %edx
	movl	-4(%ebp), %eax
	addl	%eax, %edx
	.loc 1 7 26
	movl	-4(%ebp), %eax
	notl	%eax
	.loc 1 7 24
	andl	%edx, %eax
	.loc 1 8 1
	leave
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE0:
	.size	align_up, .-align_up
	.type	chunk_length, @function
chunk_length:
.LFB1:
	.loc 1 10 55
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	.loc 1 11 47
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	.loc 1 11 12
	movl	%eax, %edx
	negl	%edx
	cmovns	%edx, %eax
	.loc 1 12 1
	popl	%ebp
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE1:
	.size	chunk_length, .-chunk_length
	.type	chunk_is_used, @function
chunk_is_used:
.LFB2:
	.loc 1 14 53
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	.loc 1 15 17
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	.loc 1 15 26
	shrl	$31, %eax
	movzbl	%al, %eax
	.loc 1 16 1
	popl	%ebp
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE2:
	.size	chunk_is_used, .-chunk_is_used
	.type	chunk_set_used, @function
chunk_set_used:
.LFB3:
	.loc 1 18 59
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	.loc 1 19 9
	pushl	8(%ebp)
	call	chunk_is_used
	addl	$4, %esp
	.loc 1 19 8
	cmpl	%eax, 12(%ebp)
	je	.L10
	.loc 1 23 27
	movl	8(%ebp), %eax
	movl	4(%eax), %eax
	.loc 1 23 21
	negl	%eax
	movl	%eax, %edx
	.loc 1 23 19
	movl	8(%ebp), %eax
	movl	%edx, 4(%eax)
	jmp	.L7
.L10:
	.loc 1 20 9
	nop
.L7:
	.loc 1 24 1
	leave
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE3:
	.size	chunk_set_used, .-chunk_set_used
	.type	chunk_write, @function
chunk_write:
.LFB4:
	.loc 1 26 91
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	.loc 1 27 17
	movl	8(%ebp), %eax
	movl	12(%ebp), %edx
	movl	%edx, (%eax)
	.loc 1 28 50
	cmpl	$0, 20(%ebp)
	je	.L12
	.loc 1 28 30 discriminator 1
	movl	16(%ebp), %eax
	.loc 1 28 50 discriminator 1
	negl	%eax
	jmp	.L13
.L12:
	.loc 1 28 50 is_stmt 0 discriminator 2
	movl	16(%ebp), %eax
.L13:
	.loc 1 28 19 is_stmt 1 discriminator 4
	movl	8(%ebp), %edx
	movl	%eax, 4(%edx)
	.loc 1 29 1 discriminator 4
	nop
	popl	%ebp
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE4:
	.size	chunk_write, .-chunk_write
	.type	chunk_to_data, @function
chunk_to_data:
.LFB5:
	.loc 1 31 58
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	.loc 1 32 38
	movl	8(%ebp), %eax
	addl	$8, %eax
	.loc 1 33 1
	popl	%ebp
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE5:
	.size	chunk_to_data, .-chunk_to_data
	.type	chunk_from_data, @function
chunk_from_data:
.LFB6:
	.loc 1 35 49
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	.loc 1 36 12
	movl	8(%ebp), %eax
	subl	$8, %eax
	.loc 1 37 1
	popl	%ebp
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE6:
	.size	chunk_from_data, .-chunk_from_data
	.type	chunk_split, @function
chunk_split:
.LFB7:
	.loc 1 39 64
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	subl	$16, %esp
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	.loc 1 40 19
	movl	8(%ebp), %edx
	movl	12(%ebp), %eax
	addl	%edx, %eax
	movl	%eax, -4(%ebp)
	.loc 1 41 19
	pushl	8(%ebp)
	call	chunk_length
	addl	$4, %esp
	.loc 1 41 9
	subl	12(%ebp), %eax
	movl	%eax, -8(%ebp)
	.loc 1 44 5
	cmpl	$15, -8(%ebp)
	jbe	.L21
	.loc 1 48 5
	movl	8(%ebp), %eax
	movl	(%eax), %eax
	pushl	$0
	pushl	-8(%ebp)
	pushl	%eax
	pushl	-4(%ebp)
	call	chunk_write
	addl	$16, %esp
	.loc 1 49 5
	pushl	8(%ebp)
	call	chunk_is_used
	addl	$4, %esp
	pushl	%eax
	pushl	12(%ebp)
	pushl	-4(%ebp)
	pushl	8(%ebp)
	call	chunk_write
	addl	$16, %esp
	jmp	.L18
.L21:
	.loc 1 45 3
	nop
.L18:
	.loc 1 50 1
	leave
	.cfi_restore 5
	.cfi_def_cfa 4, 4
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
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	.loc 1 53 5
	pushl	$0
	pushl	12(%ebp)
	pushl	$0
	pushl	8(%ebp)
	call	chunk_write
	addl	$16, %esp
	.loc 1 54 1
	nop
	leave
	.cfi_restore 5
	.cfi_def_cfa 4, 4
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
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	subl	$16, %esp
	call	__x86.get_pc_thunk.ax
	addl	$_GLOBAL_OFFSET_TABLE_, %eax
	.loc 1 57 47
	pushl	12(%ebp)
	call	align_up
	addl	$4, %esp
	.loc 1 57 12
	addl	$8, %eax
	movl	%eax, -4(%ebp)
	.loc 1 60 8
	cmpl	$0, 12(%ebp)
	jne	.L24
	.loc 1 61 16
	movl	$0, %eax
	jmp	.L25
.L24:
	.loc 1 65 5
	cmpl	$15, -4(%ebp)
	ja	.L26
	.loc 1 66 13
	movl	$16, -4(%ebp)
.L26:
	.loc 1 70 14
	movl	8(%ebp), %eax
	movl	%eax, -8(%ebp)
	.loc 1 70 5
	jmp	.L27
.L29:
	.loc 1 71 14
	pushl	-8(%ebp)
	call	chunk_is_used
	addl	$4, %esp
	.loc 1 71 12
	testl	%eax, %eax
	jne	.L28
	.loc 1 71 36 discriminator 1
	pushl	-8(%ebp)
	call	chunk_length
	addl	$4, %esp
	.loc 1 71 33 discriminator 1
	cmpl	-4(%ebp), %eax
	jb	.L28
	.loc 1 72 13
	pushl	-4(%ebp)
	pushl	-8(%ebp)
	call	chunk_split
	addl	$8, %esp
	.loc 1 73 13
	pushl	$1
	pushl	-8(%ebp)
	call	chunk_set_used
	addl	$8, %esp
	.loc 1 75 20
	pushl	-8(%ebp)
	call	chunk_to_data
	addl	$4, %esp
	jmp	.L25
.L28:
	.loc 1 70 56 discriminator 2
	movl	-8(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, -8(%ebp)
.L27:
	.loc 1 70 43 discriminator 1
	cmpl	$0, -8(%ebp)
	jne	.L29
	.loc 1 79 12
	movl	$0, %eax
.L25:
	.loc 1 80 1
	leave
	.cfi_restore 5
	.cfi_def_cfa 4, 4
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
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	pushl	%esi
	pushl	%ebx
	subl	$16, %esp
	.cfi_offset 6, -12
	.cfi_offset 3, -16
	call	__x86.get_pc_thunk.bx
	addl	$_GLOBAL_OFFSET_TABLE_, %ebx
	.loc 1 85 8
	cmpl	$0, 12(%ebp)
	je	.L36
	.loc 1 90 13
	pushl	12(%ebp)
	call	chunk_from_data
	addl	$4, %esp
	movl	%eax, -12(%ebp)
	.loc 1 91 5
	pushl	$0
	pushl	-12(%ebp)
	call	chunk_set_used
	addl	$8, %esp
	.loc 1 92 20
	pushl	-12(%ebp)
	call	chunk_length
	addl	$4, %esp
	.loc 1 92 5
	subl	$8, %eax
	subl	$4, %esp
	pushl	%eax
	pushl	$0
	pushl	12(%ebp)
	call	memset@PLT
	addl	$16, %esp
	.loc 1 95 11
	movl	8(%ebp), %eax
	movl	%eax, -12(%ebp)
	.loc 1 96 11
	jmp	.L33
.L35:
	.loc 1 97 14
	subl	$12, %esp
	pushl	-12(%ebp)
	call	chunk_is_used
	addl	$16, %esp
	.loc 1 97 12
	testl	%eax, %eax
	jne	.L34
	.loc 1 97 58 discriminator 1
	movl	-12(%ebp), %eax
	movl	(%eax), %eax
	.loc 1 97 39 discriminator 1
	subl	$12, %esp
	pushl	%eax
	call	chunk_is_used
	addl	$16, %esp
	.loc 1 97 35 discriminator 1
	testl	%eax, %eax
	jne	.L34
.LBB2:
	.loc 1 98 19
	movl	-12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, -16(%ebp)
	.loc 1 100 51
	subl	$12, %esp
	pushl	-12(%ebp)
	call	chunk_length
	addl	$16, %esp
	movl	%eax, %esi
	.loc 1 100 91
	movl	-12(%ebp), %eax
	movl	(%eax), %eax
	.loc 1 100 73
	subl	$12, %esp
	pushl	%eax
	call	chunk_length
	addl	$16, %esp
	.loc 1 100 13
	leal	(%esi,%eax), %edx
	.loc 1 100 37
	movl	-12(%ebp), %eax
	movl	(%eax), %eax
	.loc 1 100 13
	movl	(%eax), %eax
	pushl	$0
	pushl	%edx
	pushl	%eax
	pushl	-12(%ebp)
	call	chunk_write
	addl	$16, %esp
	.loc 1 101 13
	subl	$4, %esp
	pushl	$8
	pushl	$0
	pushl	-16(%ebp)
	call	memset@PLT
	addl	$16, %esp
.LBE2:
	.loc 1 97 67
	jmp	.L33
.L34:
	.loc 1 103 19
	movl	-12(%ebp), %eax
	movl	(%eax), %eax
	movl	%eax, -12(%ebp)
.L33:
	.loc 1 96 26
	cmpl	$0, -12(%ebp)
	je	.L30
	.loc 1 96 34 discriminator 1
	movl	-12(%ebp), %eax
	movl	(%eax), %eax
	.loc 1 96 26 discriminator 1
	testl	%eax, %eax
	jne	.L35
	jmp	.L30
.L36:
	.loc 1 86 9
	nop
.L30:
	.loc 1 106 1
	leal	-8(%ebp), %esp
	popl	%ebx
	.cfi_restore 3
	popl	%esi
	.cfi_restore 6
	popl	%ebp
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE10:
	.size	freelist_free, .-freelist_free
	.section	.text.__x86.get_pc_thunk.ax,"axG",@progbits,__x86.get_pc_thunk.ax,comdat
	.globl	__x86.get_pc_thunk.ax
	.hidden	__x86.get_pc_thunk.ax
	.type	__x86.get_pc_thunk.ax, @function
__x86.get_pc_thunk.ax:
.LFB11:
	.cfi_startproc
	movl	(%esp), %eax
	ret
	.cfi_endproc
.LFE11:
	.section	.text.__x86.get_pc_thunk.bx,"axG",@progbits,__x86.get_pc_thunk.bx,comdat
	.globl	__x86.get_pc_thunk.bx
	.hidden	__x86.get_pc_thunk.bx
	.type	__x86.get_pc_thunk.bx, @function
__x86.get_pc_thunk.bx:
.LFB12:
	.cfi_startproc
	movl	(%esp), %ebx
	ret
	.cfi_endproc
.LFE12:
	.text
.Letext0:
	.file 2 "/usr/lib/gcc-cross/i686-linux-gnu/12/include/stddef.h"
	.file 3 "/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/include/allocator.h"
	.file 4 "/usr/i686-linux-gnu/include/string.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x385
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF33
	.byte	0xc
	.long	.LASF34
	.long	.LASF35
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.long	.LASF0
	.byte	0x2
	.byte	0x91
	.byte	0x1a
	.long	0x31
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x2
	.long	.LASF1
	.byte	0x2
	.byte	0xd6
	.byte	0x17
	.long	0x44
	.uleb128 0x4
	.byte	0x4
	.byte	0x7
	.long	.LASF2
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.long	.LASF3
	.uleb128 0x4
	.byte	0x8
	.byte	0x5
	.long	.LASF4
	.uleb128 0x4
	.byte	0xc
	.byte	0x4
	.long	.LASF5
	.uleb128 0x4
	.byte	0x10
	.byte	0x4
	.long	.LASF6
	.uleb128 0x2
	.long	.LASF7
	.byte	0x3
	.byte	0x9
	.byte	0x1d
	.long	0x78
	.uleb128 0x5
	.long	0x67
	.uleb128 0x6
	.long	.LASF7
	.byte	0x8
	.byte	0x3
	.byte	0xb
	.byte	0x8
	.long	0xa0
	.uleb128 0x7
	.long	.LASF8
	.byte	0x3
	.byte	0xc
	.byte	0x13
	.long	0xa0
	.byte	0
	.uleb128 0x7
	.long	.LASF9
	.byte	0x3
	.byte	0xd
	.byte	0xf
	.long	0x25
	.byte	0x4
	.byte	0
	.uleb128 0x8
	.byte	0x4
	.long	0x67
	.uleb128 0x4
	.byte	0x2
	.byte	0x7
	.long	.LASF10
	.uleb128 0x4
	.byte	0x1
	.byte	0x6
	.long	.LASF11
	.uleb128 0x9
	.long	.LASF36
	.byte	0x4
	.byte	0x3d
	.byte	0xe
	.long	0xd4
	.long	0xd4
	.uleb128 0xa
	.long	0xd4
	.uleb128 0xa
	.long	0x31
	.uleb128 0xa
	.long	0x38
	.byte	0
	.uleb128 0xb
	.byte	0x4
	.uleb128 0xc
	.long	.LASF17
	.byte	0x1
	.byte	0x52
	.byte	0x6
	.long	.LFB10
	.long	.LFE10-.LFB10
	.uleb128 0x1
	.byte	0x9c
	.long	0x133
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x52
	.byte	0x1a
	.long	0xd4
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x52
	.byte	0x26
	.long	0xd4
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0xf
	.long	.LASF13
	.byte	0x1
	.byte	0x53
	.byte	0x13
	.long	0xa0
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0x10
	.long	.LBB2
	.long	.LBE2-.LBB2
	.uleb128 0xf
	.long	.LASF14
	.byte	0x1
	.byte	0x62
	.byte	0x13
	.long	0xd4
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.byte	0
	.uleb128 0x11
	.long	.LASF37
	.byte	0x1
	.byte	0x38
	.byte	0x7
	.long	0xd4
	.long	.LFB9
	.long	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.long	0x18a
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x38
	.byte	0x1c
	.long	0xd4
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF15
	.byte	0x1
	.byte	0x38
	.byte	0x29
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0xf
	.long	.LASF16
	.byte	0x1
	.byte	0x39
	.byte	0xc
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.uleb128 0x12
	.string	"cur"
	.byte	0x1
	.byte	0x3a
	.byte	0x13
	.long	0xa0
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0xc
	.long	.LASF18
	.byte	0x1
	.byte	0x34
	.byte	0x6
	.long	.LFB8
	.long	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.long	0x1bf
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x34
	.byte	0x1a
	.long	0xd4
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF19
	.byte	0x1
	.byte	0x34
	.byte	0x27
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.byte	0
	.uleb128 0x13
	.long	.LASF25
	.byte	0x1
	.byte	0x27
	.byte	0xd
	.long	.LFB7
	.long	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.long	0x212
	.uleb128 0xd
	.long	.LASF13
	.byte	0x1
	.byte	0x27
	.byte	0x27
	.long	0xa0
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF16
	.byte	0x1
	.byte	0x27
	.byte	0x35
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0xf
	.long	.LASF20
	.byte	0x1
	.byte	0x28
	.byte	0x13
	.long	0xa0
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.uleb128 0xf
	.long	.LASF21
	.byte	0x1
	.byte	0x29
	.byte	0x9
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0x14
	.long	.LASF22
	.byte	0x1
	.byte	0x23
	.byte	0x16
	.long	0xa0
	.long	.LFB6
	.long	.LFE6-.LFB6
	.uleb128 0x1
	.byte	0x9c
	.long	0x23c
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x23
	.byte	0x2c
	.long	0xd4
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0x14
	.long	.LASF23
	.byte	0x1
	.byte	0x1f
	.byte	0x17
	.long	0x266
	.long	.LFB5
	.long	.LFE5-.LFB5
	.uleb128 0x1
	.byte	0x9c
	.long	0x266
	.uleb128 0xd
	.long	.LASF13
	.byte	0x1
	.byte	0x1f
	.byte	0x33
	.long	0xa0
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0x8
	.byte	0x4
	.long	0x26c
	.uleb128 0x4
	.byte	0x1
	.byte	0x8
	.long	.LASF24
	.uleb128 0x15
	.long	.LASF26
	.byte	0x1
	.byte	0x1a
	.byte	0xd
	.long	.LFB4
	.long	.LFE4-.LFB4
	.uleb128 0x1
	.byte	0x9c
	.long	0x2c6
	.uleb128 0xd
	.long	.LASF13
	.byte	0x1
	.byte	0x1a
	.byte	0x27
	.long	0xa0
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF8
	.byte	0x1
	.byte	0x1a
	.byte	0x3c
	.long	0xa0
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0xd
	.long	.LASF9
	.byte	0x1
	.byte	0x1a
	.byte	0x49
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 8
	.uleb128 0xd
	.long	.LASF27
	.byte	0x1
	.byte	0x1a
	.byte	0x55
	.long	0x31
	.uleb128 0x2
	.byte	0x91
	.sleb128 12
	.byte	0
	.uleb128 0x13
	.long	.LASF28
	.byte	0x1
	.byte	0x12
	.byte	0xd
	.long	.LFB3
	.long	.LFE3-.LFB3
	.uleb128 0x1
	.byte	0x9c
	.long	0x2fb
	.uleb128 0xd
	.long	.LASF13
	.byte	0x1
	.byte	0x12
	.byte	0x2a
	.long	0xa0
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF27
	.byte	0x1
	.byte	0x12
	.byte	0x35
	.long	0x31
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.byte	0
	.uleb128 0x14
	.long	.LASF29
	.byte	0x1
	.byte	0xe
	.byte	0xc
	.long	0x31
	.long	.LFB2
	.long	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.long	0x325
	.uleb128 0xd
	.long	.LASF13
	.byte	0x1
	.byte	0xe
	.byte	0x2e
	.long	0x325
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0x8
	.byte	0x4
	.long	0x73
	.uleb128 0x14
	.long	.LASF30
	.byte	0x1
	.byte	0xa
	.byte	0xf
	.long	0x38
	.long	.LFB1
	.long	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.long	0x355
	.uleb128 0xd
	.long	.LASF13
	.byte	0x1
	.byte	0xa
	.byte	0x30
	.long	0x325
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0x16
	.long	.LASF31
	.byte	0x1
	.byte	0x5
	.byte	0xf
	.long	0x38
	.long	.LFB0
	.long	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.long	.LASF32
	.byte	0x1
	.byte	0x5
	.byte	0x1f
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x12
	.string	"m"
	.byte	0x1
	.byte	0x6
	.byte	0xc
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
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
	.uleb128 0x6
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
	.uleb128 0x8
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
	.uleb128 0xe
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
	.uleb128 0x6
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
	.uleb128 0x6
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
	.uleb128 0x6
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
	.uleb128 0x6
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
	.uleb128 0x6
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
	.uleb128 0x6
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
	.uleb128 0x6
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.long	0x1c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x4
	.byte	0
	.value	0
	.value	0
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF19:
	.string	"heap_size"
.LASF1:
	.string	"size_t"
.LASF8:
	.string	"next"
.LASF6:
	.string	"_Float128"
.LASF32:
	.string	"value"
.LASF16:
	.string	"requested"
.LASF37:
	.string	"freelist_alloc"
.LASF17:
	.string	"freelist_free"
.LASF23:
	.string	"chunk_to_data"
.LASF28:
	.string	"chunk_set_used"
.LASF33:
	.string	"GNU C17 12.2.0 -mtune=generic -march=i686 -gdwarf-4 -gctf -fasynchronous-unwind-tables"
.LASF38:
	.string	"void"
.LASF30:
	.string	"chunk_length"
.LASF10:
	.string	"short unsigned int"
.LASF20:
	.string	"new_chunk"
.LASF14:
	.string	"old_next"
.LASF7:
	.string	"chunk_header"
.LASF36:
	.string	"memset"
.LASF29:
	.string	"chunk_is_used"
.LASF0:
	.string	"ptrdiff_t"
.LASF21:
	.string	"new_len"
.LASF13:
	.string	"chunk"
.LASF24:
	.string	"unsigned char"
.LASF2:
	.string	"unsigned int"
.LASF11:
	.string	"char"
.LASF12:
	.string	"heap"
.LASF4:
	.string	"long long int"
.LASF35:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator"
.LASF18:
	.string	"freelist_init"
.LASF39:
	.string	"unknown"
.LASF22:
	.string	"chunk_from_data"
.LASF27:
	.string	"used"
.LASF25:
	.string	"chunk_split"
.LASF34:
	.string	"src/allocator.c"
.LASF26:
	.string	"chunk_write"
.LASF3:
	.string	"long int"
.LASF31:
	.string	"align_up"
.LASF5:
	.string	"long double"
.LASF15:
	.string	"size"
.LASF9:
	.string	"length"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
