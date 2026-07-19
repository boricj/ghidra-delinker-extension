	.file	"main.c"
	.machinemode zarch
	.machine "z196"
	.section	.ctf,"",@progbits
.Lctf0:
	.2byte	0xdff2
	.byte	0x4
	.byte	0x2
	.4byte	0
	.4byte	0
	.4byte	0x9d
	.4byte	0
	.4byte	0
	.4byte	0x8
	.4byte	0x14
	.4byte	0x1c
	.4byte	0x28
	.4byte	0x38
	.4byte	0x15c
	.4byte	0x115
	.4byte	0xd
	.4byte	0xf
	.4byte	0x13
	.4byte	0x12
	.4byte	0x10
	.4byte	0x69
	.4byte	0x72
	.4byte	0x8f
	.4byte	0x8a
	.4byte	0x85
	.4byte	0x72
	.4byte	0xf
	.4byte	0x69
	.4byte	0xd
	.4byte	0x1
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x40
	.4byte	0x13
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x1000040
	.4byte	0x1c
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0x2a
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x10
	.4byte	0x3d
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x20
	.4byte	0x4a
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x3000008
	.4byte	0x56
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x1000010
	.4byte	0x60
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x1000020
	.4byte	0
	.4byte	0x32000000
	.4byte	0x8
	.4byte	0x64
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0
	.4byte	0x32000000
	.4byte	0xa
	.4byte	0
	.4byte	0x12000000
	.4byte	0
	.4byte	0x9
	.4byte	0x1
	.4byte	0xa
	.4byte	0
	.4byte	0x32000000
	.4byte	0xc
	.4byte	0
	.4byte	0xe000000
	.4byte	0x9
	.4byte	0
	.4byte	0x32000000
	.4byte	0xe
	.4byte	0x85
	.4byte	0x16000001
	.4byte	0x8
	.4byte	0x11
	.4byte	0
	.4byte	0
	.4byte	0xe000000
	.4byte	0xb
	.4byte	0x8a
	.4byte	0x16000000
	.4byte	0x8
	.4byte	0x8f
	.4byte	0x16000001
	.4byte	0x5
	.4byte	0x11
	.4byte	0
	.string	""
	.string	"long unsigned int"
	.string	"long int"
	.string	"unsigned char"
	.string	"short unsigned int"
	.string	"unsigned int"
	.string	"signed char"
	.string	"short int"
	.string	"int"
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
.globl s_ascii_digit_bias
	.section	.data.rel.ro,"aw"
	.align	8
	.type	s_ascii_digit_bias, @object
	.size	s_ascii_digit_bias, 8
s_ascii_digit_bias:
	.quad	s_digits-192
.text
	.align	8
.globl parse_decimal
	.type	parse_decimal, @function
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
	ldgr	%f2,%r11
	.cfi_register 11, 17
	ldgr	%f0,%r15
	.cfi_register 15, 16
	lay	%r15,-176(%r15)
	.cfi_def_cfa_offset 336
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,160(%r11)
	.loc 1 12 18
	mvhi	172(%r11),0
	.loc 1 14 8
	j	.L2
.L3:
	.loc 1 15 18
	l	%r2,172(%r11)
	lr	%r1,%r2
	sll	%r1,2
	ar	%r1,%r2
	sll	%r1,1
	lr	%r2,%r1
	.loc 1 15 44
	lgrl	%r1,s_digits@GOTENT
	aghi	%r1,-192
	lgr	%r3,%r1
	.loc 1 15 61
	lg	%r1,160(%r11)
	ic	%r1,0(%r1)
	.loc 1 15 45
	llgcr	%r1,%r1
	.loc 1 15 44
	sllg	%r1,%r1,2
	agr	%r1,%r3
	l	%r1,0(%r1)
	.loc 1 15 9
	ark	%r1,%r2,%r1
	st	%r1,172(%r11)
	.loc 1 16 4
	agsi	160(%r11),1
.L2:
	.loc 1 14 9
	lg	%r1,160(%r11)
	ic	%r1,0(%r1)
	.loc 1 14 12
	llcr	%r1,%r1
	ltr	%r1,%r1
	jne	.L3
	.loc 1 19 12
	l	%r1,172(%r11)
	llgfr	%r1,%r1
	.loc 1 20 1
	lgr	%r2,%r1
	lgdr	%r15,%f0
	.cfi_restore 15
	.cfi_def_cfa 15, 160
	lgdr	%r11,%f2
	.cfi_restore 11
	br	%r14
	.cfi_endproc
.LFE0:
	.size	parse_decimal, .-parse_decimal
	.section	.rodata
	.align	2
.LC0:
	.string	"0"
	.align	2
.LC1:
	.string	"123"
	.align	2
.LC2:
	.string	"65535"
	.align	2
.LC3:
	.string	"All tests passed."
.text
	.align	8
.globl main
	.type	main, @function
main:
.LFB1:
	.loc 1 22 16
	.cfi_startproc
	stmg	%r11,%r15,88(%r15)
	.cfi_offset 11, -72
	.cfi_offset 12, -64
	.cfi_offset 13, -56
	.cfi_offset 14, -48
	.cfi_offset 15, -40
	lay	%r15,-160(%r15)
	.cfi_def_cfa_offset 320
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	.loc 1 23 9
	larl	%r2,.LC0
	brasl	%r14,parse_decimal@PLT
	lgr	%r1,%r2
	.loc 1 23 8
	ltr	%r1,%r1
	je	.L7
	.loc 1 24 16
	lhi	%r1,1
	j	.L8
.L7:
	.loc 1 26 9
	larl	%r2,.LC1
	brasl	%r14,parse_decimal@PLT
	lgr	%r1,%r2
	.loc 1 26 8
	chi	%r1,123
	je	.L9
	.loc 1 27 16
	lhi	%r1,2
	j	.L8
.L9:
	.loc 1 29 9
	larl	%r2,.LC2
	brasl	%r14,parse_decimal@PLT
	lgr	%r1,%r2
	.loc 1 29 8
	cfi	%r1,65535
	je	.L10
	.loc 1 30 16
	lhi	%r1,3
	j	.L8
.L10:
	.loc 1 33 5
	larl	%r2,.LC3
	brasl	%r14,puts@PLT
	.loc 1 34 12
	lhi	%r1,0
.L8:
	.loc 1 35 1
	lgfr	%r1,%r1
	lgr	%r2,%r1
	lmg	%r11,%r15,248(%r11)
	.cfi_restore 15
	.cfi_restore 14
	.cfi_restore 13
	.cfi_restore 12
	.cfi_restore 11
	.cfi_def_cfa 15, 160
	br	%r14
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/s390x-linux-gnu/include/stdio.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x12d
	.2byte	0x4
	.4byte	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.4byte	.LASF10
	.byte	0xc
	.4byte	.LASF11
	.4byte	.LASF12
	.8byte	.Ltext0
	.8byte	.Letext0-.Ltext0
	.4byte	.Ldebug_line0
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	.LASF0
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	.LASF1
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	.LASF2
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.4byte	.LASF3
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	.LASF4
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	.LASF5
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.4byte	.LASF6
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x4
	.4byte	0x5e
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	.LASF7
	.uleb128 0x4
	.4byte	0x6a
	.uleb128 0x5
	.4byte	0x65
	.4byte	0x86
	.uleb128 0x6
	.4byte	0x2d
	.byte	0x9
	.byte	0
	.uleb128 0x4
	.4byte	0x76
	.uleb128 0x7
	.4byte	.LASF8
	.byte	0x1
	.byte	0x8
	.byte	0x12
	.4byte	0x86
	.uleb128 0x8
	.4byte	.LASF9
	.byte	0x1
	.byte	0x9
	.byte	0x13
	.4byte	0xb3
	.uleb128 0x9
	.byte	0x3
	.8byte	s_ascii_digit_bias
	.uleb128 0x9
	.byte	0x8
	.4byte	0x65
	.uleb128 0x4
	.4byte	0xad
	.uleb128 0xa
	.4byte	.LASF13
	.byte	0x2
	.2byte	0x295
	.byte	0xc
	.4byte	0x5e
	.4byte	0xcf
	.uleb128 0xb
	.4byte	0xcf
	.byte	0
	.uleb128 0x9
	.byte	0x8
	.4byte	0x71
	.uleb128 0xc
	.4byte	.LASF14
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.4byte	0x5e
	.8byte	.LFB1
	.8byte	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.4byte	.LASF15
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.4byte	0x49
	.8byte	.LFB0
	.8byte	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.string	"s"
	.byte	0x1
	.byte	0xb
	.byte	0x28
	.4byte	0xcf
	.uleb128 0x3
	.byte	0x91
	.sleb128 -176
	.uleb128 0xf
	.4byte	.LASF16
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.4byte	0x49
	.uleb128 0x3
	.byte	0x91
	.sleb128 -164
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
	.4byte	0x2c
	.2byte	0x2
	.4byte	.Ldebug_info0
	.byte	0x8
	.byte	0
	.2byte	0
	.2byte	0
	.8byte	.Ltext0
	.8byte	.Letext0-.Ltext0
	.8byte	0
	.8byte	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF12:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing"
.LASF4:
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
.LASF1:
	.string	"long int"
.LASF18:
	.string	"unknown"
.LASF3:
	.string	"short unsigned int"
.LASF5:
	.string	"signed char"
.LASF16:
	.string	"value"
.LASF6:
	.string	"short int"
.LASF8:
	.string	"s_digits"
.LASF10:
	.string	"GNU C17 12.2.0 -march=z196 -m64 -mzarch -gdwarf-4 -gctf -fasynchronous-unwind-tables"
.LASF7:
	.string	"char"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
