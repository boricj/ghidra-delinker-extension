#NO_APP
	.file	"main.c"
	.section	.ctf,"",@progbits
.Lctf0:
	.word	0xdff2
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
	.long	0x11
	.long	0xf
	.long	0x14
	.long	0x15
	.long	0x12
	.long	0x97
	.long	0x8e
	.long	0xaf
	.long	0xb4
	.long	0xaa
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
	.long	0x2000008
	.long	0x1c
	.long	0x6000000
	.long	0x2
	.long	0x10
	.long	0x2f
	.long	0x6000000
	.long	0x4
	.long	0x20
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
	.long	0x69
	.long	0x6000000
	.long	0x8
	.long	0x40
	.long	0x80
	.long	0x6000000
	.long	0x4
	.long	0x1000020
	.long	0x89
	.long	0x6000000
	.long	0x1
	.long	0x3000008
	.long	0
	.long	0x32000000
	.long	0xc
	.long	0
	.long	0x12000000
	.long	0
	.long	0x8
	.long	0x1
	.long	0xa
	.long	0
	.long	0x32000000
	.long	0xe
	.long	0
	.long	0xe000000
	.long	0x8
	.long	0
	.long	0x32000000
	.long	0x10
	.long	0xaa
	.long	0x16000001
	.long	0x7
	.long	0x13
	.long	0
	.long	0
	.long	0xe000000
	.long	0xd
	.long	0xaf
	.long	0x16000000
	.long	0x7
	.long	0xb4
	.long	0x16000001
	.long	0x1
	.long	0x13
	.long	0
	.string	""
	.string	"unsigned int"
	.string	"unsigned char"
	.string	"short unsigned int"
	.string	"long unsigned int"
	.string	"signed char"
	.string	"short int"
	.string	"int"
	.string	"long long int"
	.string	"long long unsigned int"
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
	.cfi_sections	.debug_frame
	.file 1 "src/main.c"
	.globl	s_ascii_digit_bias
	.section	.rodata
	.align	2
	.type	s_ascii_digit_bias, @object
	.size	s_ascii_digit_bias, 4
s_ascii_digit_bias:
	.long	s_digits-192
	.text
	.align	2
	.globl	parse_decimal
	.type	parse_decimal, @function
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
	link.w %fp,#-4
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	move.l %d2,-(%sp)
	.cfi_offset 2, -16
	.loc 1 12 18
	clr.l -4(%fp)
	.loc 1 14 8
	jra .L2
.L3:
	.loc 1 15 18
	move.l -4(%fp),%d1
	move.l %d1,%d0
	lsl.l #2,%d0
	add.l %d1,%d0
	add.l %d0,%d0
	move.l %d0,%d1
	.loc 1 15 44
	lea s_digits-192,%a1
	.loc 1 15 61
	move.l 8(%fp),%a0
	move.b (%a0),%d0
	.loc 1 15 45
	move.b %d0,%d0
	and.l #255,%d0
	.loc 1 15 44
	lsl.l #2,%d0
	lea (%a1,%d0.l),%a0
	move.l (%a0),%d0
	.loc 1 15 9
	move.l %d1,%d2
	add.l %d0,%d2
	move.l %d2,-4(%fp)
	.loc 1 16 4
	addq.l #1,8(%fp)
.L2:
	.loc 1 14 9
	move.l 8(%fp),%a0
	move.b (%a0),%d0
	.loc 1 14 12
	jne .L3
	.loc 1 19 12
	move.l -4(%fp),%d0
	.loc 1 20 1
	move.l (%sp)+,%d2
	unlk %fp
	rts
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
	.align	2
	.globl	main
	.type	main, @function
main:
.LFB1:
	.loc 1 22 16
	.cfi_startproc
	link.w %fp,#0
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 23 9
	pea .LC0
	jsr parse_decimal
	addq.l #4,%sp
	.loc 1 23 8
	tst.l %d0
	jeq .L6
	.loc 1 24 16
	moveq #1,%d0
	jra .L7
.L6:
	.loc 1 26 9
	pea .LC1
	jsr parse_decimal
	addq.l #4,%sp
	.loc 1 26 8
	moveq #123,%d1
	cmp.l %d0,%d1
	jeq .L8
	.loc 1 27 16
	moveq #2,%d0
	jra .L7
.L8:
	.loc 1 29 9
	pea .LC2
	jsr parse_decimal
	addq.l #4,%sp
	.loc 1 29 8
	cmp.l #65535,%d0
	jeq .L9
	.loc 1 30 16
	moveq #3,%d0
	jra .L7
.L9:
	.loc 1 33 5
	pea .LC3
	jsr puts
	addq.l #4,%sp
	.loc 1 34 12
	clr.l %d0
.L7:
	.loc 1 35 1
	unlk %fp
	rts
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/m68k-linux-gnu/include/stdio.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x11d
	.word	0x4
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
	.byte	0x8
	.long	.LASF1
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.long	.LASF2
	.uleb128 0x2
	.byte	0x4
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
	.long	0x4f
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.long	.LASF6
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.long	.LASF7
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.long	.LASF8
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.long	.LASF9
	.uleb128 0x4
	.long	0x70
	.uleb128 0x5
	.long	0x56
	.long	0x8c
	.uleb128 0x6
	.long	0x25
	.byte	0x9
	.byte	0
	.uleb128 0x4
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
	.long	0x56
	.uleb128 0x4
	.long	0xaf
	.uleb128 0xa
	.long	.LASF15
	.byte	0x2
	.word	0x295
	.byte	0xc
	.long	0x4f
	.long	0xd1
	.uleb128 0xb
	.long	0xd1
	.byte	0
	.uleb128 0x9
	.byte	0x4
	.long	0x77
	.uleb128 0xc
	.long	.LASF16
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.long	0x4f
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
	.byte	0x7e
	.sleb128 -4
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
	.word	0x2
	.long	.Ldebug_info0
	.byte	0x4
	.byte	0
	.word	0
	.word	0
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF6:
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
	.string	"GNU C17 12.2.0 -mcpu=68020 -gdwarf-4 -gctf"
.LASF3:
	.string	"long unsigned int"
.LASF7:
	.string	"long long unsigned int"
.LASF13:
	.string	"src/main.c"
.LASF11:
	.string	"s_ascii_digit_bias"
.LASF1:
	.string	"unsigned char"
.LASF16:
	.string	"main"
.LASF19:
	.string	"void"
.LASF8:
	.string	"long int"
.LASF20:
	.string	"unknown"
.LASF2:
	.string	"short unsigned int"
.LASF4:
	.string	"signed char"
.LASF18:
	.string	"value"
.LASF5:
	.string	"short int"
.LASF10:
	.string	"s_digits"
.LASF9:
	.string	"char"
	.ident	"GCC: (Debian 12.2.0-13) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
