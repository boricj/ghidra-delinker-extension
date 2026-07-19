	.file	"main.c"
	.section	.ctf,"",@progbits
.Lctf0:
	.value	0xdff2
	.byte	0x4
	.byte	0x2
	.long	0
	.long	0
	.long	0xc2
	.long	0
	.long	0
	.long	0x8
	.long	0x14
	.long	0x1c
	.long	0x28
	.long	0x38
	.long	0x17c
	.long	0x13a
	.long	0xf
	.long	0x11
	.long	0x12
	.long	0x14
	.long	0x15
	.long	0x8e
	.long	0x97
	.long	0xaa
	.long	0xaf
	.long	0xb4
	.long	0x97
	.long	0x11
	.long	0x8e
	.long	0xf
	.long	0x1
	.long	0x6000000
	.long	0x4
	.long	0x20
	.long	0xe
	.long	0x6000000
	.long	0x1
	.long	0x3000008
	.long	0
	.long	0x32000000
	.long	0x2
	.long	0x13
	.long	0x6000000
	.long	0x1
	.long	0x2000008
	.long	0x21
	.long	0x6000000
	.long	0x2
	.long	0x10
	.long	0x34
	.long	0x6000000
	.long	0x4
	.long	0x20
	.long	0x46
	.long	0x6000000
	.long	0x1
	.long	0x3000008
	.long	0x52
	.long	0x6000000
	.long	0x2
	.long	0x1000010
	.long	0x5c
	.long	0x6000000
	.long	0x4
	.long	0x1000020
	.long	0
	.long	0x32000000
	.long	0x9
	.long	0x60
	.long	0x6000000
	.long	0x8
	.long	0x1000040
	.long	0x6e
	.long	0x6000000
	.long	0x8
	.long	0x40
	.long	0x85
	.long	0x6000000
	.long	0x4
	.long	0x1000020
	.long	0
	.long	0x12000000
	.long	0
	.long	0xa
	.long	0x1
	.long	0xa
	.long	0
	.long	0x32000000
	.long	0xe
	.long	0
	.long	0xe000000
	.long	0xa
	.long	0
	.long	0x32000000
	.long	0x10
	.long	0xaa
	.long	0x16000001
	.long	0x9
	.long	0x13
	.long	0
	.long	0
	.long	0xe000000
	.long	0x3
	.long	0xaf
	.long	0x16000000
	.long	0x9
	.long	0xb4
	.long	0x16000001
	.long	0x1
	.long	0x13
	.long	0
	.string	""
	.string	"unsigned int"
	.string	"char"
	.string	"unsigned char"
	.string	"short unsigned int"
	.string	"long unsigned int"
	.string	"signed char"
	.string	"short int"
	.string	"int"
	.string	"long long int"
	.string	"long long unsigned int"
	.string	"long int"
	.string	"s_digits"
	.string	"s_ascii_digit_bias"
	.string	"puts"
	.string	"main"
	.string	"parse_decimal"
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing/src/main.c"
	.text
.Ltext0:
	.file 1 "src/main.c"
	.globl	s_ascii_digit_bias
	.section	.data.rel.ro,"aw"
	.align 4
	.type	s_ascii_digit_bias, @object
	.size	s_ascii_digit_bias, 4
s_ascii_digit_bias:
	.long	s_digits-192
	.text
	.globl	parse_decimal
	.type	parse_decimal, @function
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	pushl	%ebx
	subl	$16, %esp
	.cfi_offset 3, -12
	call	__x86.get_pc_thunk.cx
	addl	$_GLOBAL_OFFSET_TABLE_, %ecx
	.loc 1 12 18
	movl	$0, -8(%ebp)
	.loc 1 14 8
	jmp	.L2
.L3:
	.loc 1 15 18
	movl	-8(%ebp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	addl	%eax, %eax
	movl	%eax, %ebx
	.loc 1 15 44
	movl	s_digits@GOT(%ecx), %eax
	leal	-192(%eax), %edx
	.loc 1 15 61
	movl	8(%ebp), %eax
	movzbl	(%eax), %eax
	.loc 1 15 45
	movzbl	%al, %eax
	.loc 1 15 44
	sall	$2, %eax
	addl	%edx, %eax
	movl	(%eax), %eax
	.loc 1 15 9
	addl	%ebx, %eax
	movl	%eax, -8(%ebp)
	.loc 1 16 4
	addl	$1, 8(%ebp)
.L2:
	.loc 1 14 9
	movl	8(%ebp), %eax
	movzbl	(%eax), %eax
	.loc 1 14 12
	testb	%al, %al
	jne	.L3
	.loc 1 19 12
	movl	-8(%ebp), %eax
	.loc 1 20 1
	movl	-4(%ebp), %ebx
	leave
	.cfi_restore 5
	.cfi_restore 3
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE0:
	.size	parse_decimal, .-parse_decimal
	.section	.rodata
.LC0:
	.string	"0"
.LC1:
	.string	"123"
.LC2:
	.string	"65535"
.LC3:
	.string	"All tests passed."
	.text
	.globl	main
	.type	main, @function
main:
.LFB1:
	.loc 1 22 16
	.cfi_startproc
	leal	4(%esp), %ecx
	.cfi_def_cfa 1, 0
	andl	$-16, %esp
	pushl	-4(%ecx)
	pushl	%ebp
	movl	%esp, %ebp
	.cfi_escape 0x10,0x5,0x2,0x75,0
	pushl	%ebx
	pushl	%ecx
	.cfi_escape 0xf,0x3,0x75,0x78,0x6
	.cfi_escape 0x10,0x3,0x2,0x75,0x7c
	call	__x86.get_pc_thunk.bx
	addl	$_GLOBAL_OFFSET_TABLE_, %ebx
	.loc 1 23 9
	leal	.LC0@GOTOFF(%ebx), %eax
	pushl	%eax
	call	parse_decimal
	addl	$4, %esp
	.loc 1 23 8
	testl	%eax, %eax
	je	.L6
	.loc 1 24 16
	movl	$1, %eax
	jmp	.L7
.L6:
	.loc 1 26 9
	leal	.LC1@GOTOFF(%ebx), %eax
	pushl	%eax
	call	parse_decimal
	addl	$4, %esp
	.loc 1 26 8
	cmpl	$123, %eax
	je	.L8
	.loc 1 27 16
	movl	$2, %eax
	jmp	.L7
.L8:
	.loc 1 29 9
	leal	.LC2@GOTOFF(%ebx), %eax
	pushl	%eax
	call	parse_decimal
	addl	$4, %esp
	.loc 1 29 8
	cmpl	$65535, %eax
	je	.L9
	.loc 1 30 16
	movl	$3, %eax
	jmp	.L7
.L9:
	.loc 1 33 5
	subl	$12, %esp
	leal	.LC3@GOTOFF(%ebx), %eax
	pushl	%eax
	call	puts@PLT
	addl	$16, %esp
	.loc 1 34 12
	movl	$0, %eax
.L7:
	.loc 1 35 1
	leal	-8(%ebp), %esp
	popl	%ecx
	.cfi_restore 1
	.cfi_def_cfa 1, 0
	popl	%ebx
	.cfi_restore 3
	popl	%ebp
	.cfi_restore 5
	leal	-4(%ecx), %esp
	.cfi_def_cfa 4, 4
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
	.section	.text.__x86.get_pc_thunk.cx,"axG",@progbits,__x86.get_pc_thunk.cx,comdat
	.globl	__x86.get_pc_thunk.cx
	.hidden	__x86.get_pc_thunk.cx
	.type	__x86.get_pc_thunk.cx, @function
__x86.get_pc_thunk.cx:
.LFB2:
	.cfi_startproc
	movl	(%esp), %ecx
	ret
	.cfi_endproc
.LFE2:
	.section	.text.__x86.get_pc_thunk.bx,"axG",@progbits,__x86.get_pc_thunk.bx,comdat
	.globl	__x86.get_pc_thunk.bx
	.hidden	__x86.get_pc_thunk.bx
	.type	__x86.get_pc_thunk.bx, @function
__x86.get_pc_thunk.bx:
.LFB3:
	.cfi_startproc
	movl	(%esp), %ebx
	ret
	.cfi_endproc
.LFE3:
	.text
.Letext0:
	.file 2 "/usr/i686-linux-gnu/include/stdio.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x11d
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF12
	.byte	0xc
	.long	.LASF13
	.long	.LASF14
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF0
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF1
	.uleb128 0x3
	.long	0x2c
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF2
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF3
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF4
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF5
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.long	.LASF6
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x3
	.long	0x5b
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF7
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF8
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.long	.LASF9
	.uleb128 0x5
	.long	0x62
	.long	0x8c
	.uleb128 0x6
	.long	0x25
	.byte	0x9
	.byte	0
	.uleb128 0x3
	.long	0x7c
	.uleb128 0x7
	.long	.LASF10
	.byte	0x1
	.byte	0x8
	.byte	0x12
	.long	0x8c
	.uleb128 0x8
	.long	.LASF11
	.byte	0x1
	.byte	0x9
	.byte	0x13
	.long	0xb5
	.uleb128 0x5
	.byte	0x3
	.long	s_ascii_digit_bias
	.uleb128 0x9
	.byte	0x4
	.long	0x62
	.uleb128 0x3
	.long	0xaf
	.uleb128 0xa
	.long	.LASF15
	.byte	0x2
	.value	0x295
	.byte	0xc
	.long	0x5b
	.long	0xd1
	.uleb128 0xb
	.long	0xd1
	.byte	0
	.uleb128 0x9
	.byte	0x4
	.long	0x33
	.uleb128 0xc
	.long	.LASF16
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.long	0x5b
	.long	.LFB1
	.long	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.long	.LASF17
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.long	0x25
	.long	.LFB0
	.long	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.string	"s"
	.byte	0x1
	.byte	0xb
	.byte	0x28
	.long	0xd1
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xf
	.long	.LASF18
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.long	0x25
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
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
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
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
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x7
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
	.uleb128 0x8
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
	.uleb128 0x9
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x2e
	.byte	0x1
	.uleb128 0x3f
	.uleb128 0x19
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
	.uleb128 0x3c
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
	.byte	0
	.byte	0
	.uleb128 0xd
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
	.uleb128 0x2117
	.uleb128 0x19
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
.LASF7:
	.string	"long long int"
.LASF14:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing"
.LASF0:
	.string	"unsigned int"
.LASF17:
	.string	"parse_decimal"
.LASF15:
	.string	"puts"
.LASF12:
	.string	"GNU C17 12.2.0 -mtune=generic -march=i686 -gdwarf-4 -gctf -fasynchronous-unwind-tables"
.LASF4:
	.string	"long unsigned int"
.LASF8:
	.string	"long long unsigned int"
.LASF13:
	.string	"src/main.c"
.LASF11:
	.string	"s_ascii_digit_bias"
.LASF2:
	.string	"unsigned char"
.LASF16:
	.string	"main"
.LASF19:
	.string	"void"
.LASF9:
	.string	"long int"
.LASF20:
	.string	"unknown"
.LASF3:
	.string	"short unsigned int"
.LASF5:
	.string	"signed char"
.LASF18:
	.string	"value"
.LASF6:
	.string	"short int"
.LASF10:
	.string	"s_digits"
.LASF1:
	.string	"char"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
