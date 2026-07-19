	.file	"main.c"
	.section	.ctf,"",@progbits
.Lctf0:
	.value	0xdff2
	.byte	0x4
	.byte	0x2
	.long	0
	.long	0
	.long	0x9d
	.long	0
	.long	0
	.long	0x8
	.long	0x14
	.long	0x1c
	.long	0x28
	.long	0x38
	.long	0x15c
	.long	0x115
	.long	0xd
	.long	0xf
	.long	0x13
	.long	0x10
	.long	0x12
	.long	0x69
	.long	0x72
	.long	0x8f
	.long	0x85
	.long	0x8a
	.long	0x72
	.long	0xf
	.long	0x69
	.long	0xd
	.long	0x1
	.long	0x6000000
	.long	0x8
	.long	0x40
	.long	0x13
	.long	0x6000000
	.long	0x4
	.long	0x20
	.long	0x20
	.long	0x6000000
	.long	0x1
	.long	0x2000008
	.long	0x2e
	.long	0x6000000
	.long	0x2
	.long	0x10
	.long	0x41
	.long	0x6000000
	.long	0x1
	.long	0x3000008
	.long	0x4d
	.long	0x6000000
	.long	0x2
	.long	0x1000010
	.long	0x57
	.long	0x6000000
	.long	0x4
	.long	0x1000020
	.long	0
	.long	0x32000000
	.long	0x7
	.long	0x5b
	.long	0x6000000
	.long	0x8
	.long	0x1000040
	.long	0x64
	.long	0x6000000
	.long	0x1
	.long	0x3000008
	.long	0
	.long	0x32000000
	.long	0xa
	.long	0
	.long	0x12000000
	.long	0
	.long	0x8
	.long	0x1
	.long	0xa
	.long	0
	.long	0x32000000
	.long	0xc
	.long	0
	.long	0xe000000
	.long	0x8
	.long	0
	.long	0x32000000
	.long	0xe
	.long	0x85
	.long	0x16000001
	.long	0x7
	.long	0x11
	.long	0
	.long	0
	.long	0xe000000
	.long	0xb
	.long	0x8a
	.long	0x16000000
	.long	0x7
	.long	0x8f
	.long	0x16000001
	.long	0x2
	.long	0x11
	.long	0
	.string	""
	.string	"long unsigned int"
	.string	"unsigned int"
	.string	"unsigned char"
	.string	"short unsigned int"
	.string	"signed char"
	.string	"short int"
	.string	"int"
	.string	"long int"
	.string	"char"
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
	.align 8
	.type	s_ascii_digit_bias, @object
	.size	s_ascii_digit_bias, 8
s_ascii_digit_bias:
	.quad	s_digits-192
	.text
	.globl	parse_decimal
	.type	parse_decimal, @function
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -24(%rbp)
	.loc 1 12 18
	movl	$0, -4(%rbp)
	.loc 1 14 8
	jmp	.L2
.L3:
	.loc 1 15 18
	movl	-4(%rbp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	addl	%eax, %eax
	movl	%eax, %ecx
	.loc 1 15 44
	leaq	-192+s_digits(%rip), %rdx
	.loc 1 15 61
	movq	-24(%rbp), %rax
	movzbl	(%rax), %eax
	.loc 1 15 45
	movzbl	%al, %eax
	.loc 1 15 44
	salq	$2, %rax
	addq	%rdx, %rax
	movl	(%rax), %eax
	.loc 1 15 9
	addl	%ecx, %eax
	movl	%eax, -4(%rbp)
	.loc 1 16 4
	addq	$1, -24(%rbp)
.L2:
	.loc 1 14 9
	movq	-24(%rbp), %rax
	movzbl	(%rax), %eax
	.loc 1 14 12
	testb	%al, %al
	jne	.L3
	.loc 1 19 12
	movl	-4(%rbp), %eax
	.loc 1 20 1
	popq	%rbp
	.cfi_def_cfa 7, 8
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
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	.loc 1 23 9
	leaq	.LC0(%rip), %rax
	movq	%rax, %rdi
	call	parse_decimal
	.loc 1 23 8
	testl	%eax, %eax
	je	.L6
	.loc 1 24 16
	movl	$1, %eax
	jmp	.L7
.L6:
	.loc 1 26 9
	leaq	.LC1(%rip), %rax
	movq	%rax, %rdi
	call	parse_decimal
	.loc 1 26 8
	cmpl	$123, %eax
	je	.L8
	.loc 1 27 16
	movl	$2, %eax
	jmp	.L7
.L8:
	.loc 1 29 9
	leaq	.LC2(%rip), %rax
	movq	%rax, %rdi
	call	parse_decimal
	.loc 1 29 8
	cmpl	$65535, %eax
	je	.L9
	.loc 1 30 16
	movl	$3, %eax
	jmp	.L7
.L9:
	.loc 1 33 5
	leaq	.LC3(%rip), %rax
	movq	%rax, %rdi
	call	puts@PLT
	.loc 1 34 12
	movl	$0, %eax
.L7:
	.loc 1 35 1
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/include/stdio.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x12b
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.long	.LASF10
	.byte	0xc
	.long	.LASF11
	.long	.LASF12
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.long	.LASF1
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.long	.LASF2
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF3
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF4
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.long	.LASF5
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x4
	.long	0x57
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF6
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF7
	.uleb128 0x4
	.long	0x6a
	.uleb128 0x5
	.long	0x5e
	.long	0x86
	.uleb128 0x6
	.long	0x2d
	.byte	0x9
	.byte	0
	.uleb128 0x4
	.long	0x76
	.uleb128 0x7
	.long	.LASF8
	.byte	0x1
	.byte	0x8
	.byte	0x12
	.long	0x86
	.uleb128 0x8
	.long	.LASF9
	.byte	0x1
	.byte	0x9
	.byte	0x13
	.long	0xb3
	.uleb128 0x9
	.byte	0x3
	.quad	s_ascii_digit_bias
	.uleb128 0x9
	.byte	0x8
	.long	0x5e
	.uleb128 0x4
	.long	0xad
	.uleb128 0xa
	.long	.LASF13
	.byte	0x2
	.value	0x295
	.byte	0xc
	.long	0x57
	.long	0xcf
	.uleb128 0xb
	.long	0xcf
	.byte	0
	.uleb128 0x9
	.byte	0x8
	.long	0x71
	.uleb128 0xc
	.long	.LASF14
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.long	0x57
	.quad	.LFB1
	.quad	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.long	.LASF15
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.long	0x34
	.quad	.LFB0
	.quad	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.string	"s"
	.byte	0x1
	.byte	0xb
	.byte	0x28
	.long	0xcf
	.uleb128 0x2
	.byte	0x91
	.sleb128 -40
	.uleb128 0xf
	.long	.LASF16
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.long	0x34
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
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
	.uleb128 0x7
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
	.uleb128 0x7
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
.LASF12:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing"
.LASF1:
	.string	"unsigned int"
.LASF15:
	.string	"parse_decimal"
.LASF13:
	.string	"puts"
.LASF0:
	.string	"long unsigned int"
.LASF11:
	.string	"src/main.c"
.LASF9:
	.string	"s_ascii_digit_bias"
.LASF2:
	.string	"unsigned char"
.LASF14:
	.string	"main"
.LASF17:
	.string	"void"
.LASF6:
	.string	"long int"
.LASF18:
	.string	"unknown"
.LASF3:
	.string	"short unsigned int"
.LASF4:
	.string	"signed char"
.LASF16:
	.string	"value"
.LASF10:
	.string	"GNU C17 12.2.0 -mtune=generic -march=x86-64 -gdwarf-4 -gctf -fasynchronous-unwind-tables"
.LASF5:
	.string	"short int"
.LASF8:
	.string	"s_digits"
.LASF7:
	.string	"char"
	.ident	"GCC: (Debian 12.2.0-14+deb12u1) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
