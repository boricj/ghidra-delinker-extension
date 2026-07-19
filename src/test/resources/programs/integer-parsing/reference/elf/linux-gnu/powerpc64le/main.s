	.file	"main.c"
	.machine power8
	.abiversion 2
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
	.4byte	0x12
	.4byte	0x13
	.4byte	0x10
	.4byte	0x69
	.4byte	0x72
	.4byte	0x8a
	.4byte	0x8f
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
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0
	.4byte	0x32000000
	.4byte	0x2
	.4byte	0x18
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0x26
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x10
	.4byte	0x39
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x20
	.4byte	0x46
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x3000008
	.4byte	0x52
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x1000010
	.4byte	0x5c
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x1000020
	.4byte	0
	.4byte	0x32000000
	.4byte	0x9
	.4byte	0x60
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x1000040
	.4byte	0
	.4byte	0x12000000
	.4byte	0
	.4byte	0xa
	.4byte	0x1
	.4byte	0xa
	.4byte	0
	.4byte	0x32000000
	.4byte	0xc
	.4byte	0
	.4byte	0xe000000
	.4byte	0xa
	.4byte	0
	.4byte	0x32000000
	.4byte	0xe
	.4byte	0x85
	.4byte	0x16000001
	.4byte	0x9
	.4byte	0x11
	.4byte	0
	.4byte	0
	.4byte	0xe000000
	.4byte	0x3
	.4byte	0x8a
	.4byte	0x16000000
	.4byte	0x9
	.4byte	0x8f
	.4byte	0x16000001
	.4byte	0x6
	.4byte	0x11
	.4byte	0
	.string	""
	.string	"long unsigned int"
	.string	"char"
	.string	"unsigned char"
	.string	"short unsigned int"
	.string	"unsigned int"
	.string	"signed char"
	.string	"short int"
	.string	"int"
	.string	"long int"
	.string	"s_digits"
	.string	"s_ascii_digit_bias"
	.string	"puts"
	.string	"main"
	.string	"parse_decimal"
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing/src/main.c"
	.section	".text"
.Ltext0:
	.file 1 "src/main.c"
	.globl s_ascii_digit_bias
	.section	.data.rel.ro,"aw"
	.align 3
	.type	s_ascii_digit_bias, @object
	.size	s_ascii_digit_bias, 8
s_ascii_digit_bias:
	.quad	s_digits-192
	.section	".toc","aw"
	.align 3
.LC0:
	.quad	s_digits-192
	.section	".text"
	.align 2
	.globl parse_decimal
	.type	parse_decimal, @function
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
.LCF0:
0:	addis 2,12,.TOC.-.LCF0@ha
	addi 2,2,.TOC.-.LCF0@l
	.localentry	parse_decimal,.-parse_decimal
	std 31,-8(1)
	stdu 1,-80(1)
	.cfi_def_cfa_offset 80
	.cfi_offset 31, -8
	mr 31,1
	.cfi_def_cfa_register 31
	std 3,48(31)
	.loc 1 12 18
	li 9,0
	stw 9,32(31)
	.loc 1 14 8
	b .L2
.L3:
	.loc 1 15 18
	lwz 9,32(31)
	mulli 9,9,10
	.loc 1 15 44
	addis 10,2,.LC0@toc@ha
	ld 8,.LC0@toc@l(10)
	.loc 1 15 61
	ld 10,48(31)
	lbz 10,0(10)
	.loc 1 15 45
	rlwinm 10,10,0,0xff
	.loc 1 15 44
	sldi 10,10,2
	add 10,8,10
	lwz 10,0(10)
	.loc 1 15 9
	add 9,9,10
	stw 9,32(31)
	.loc 1 16 4
	ld 9,48(31)
	addi 9,9,1
	std 9,48(31)
.L2:
	.loc 1 14 9
	ld 9,48(31)
	lbz 9,0(9)
	.loc 1 14 12
	rlwinm 9,9,0,0xff
	cmpwi 0,9,0
	bne 0,.L3
	.loc 1 19 12
	lwz 9,32(31)
	rldicl 9,9,0,32
	.loc 1 20 1
	mr 3,9
	addi 1,31,80
	.cfi_def_cfa 1, 0
	ld 31,-8(1)
	blr
	.long 0
	.byte 0,0,0,0,128,1,0,1
	.cfi_endproc
.LFE0:
	.size	parse_decimal,.-parse_decimal
	.section	.rodata
	.align 3
.LC1:
	.string	"0"
	.align 3
.LC2:
	.string	"123"
	.align 3
.LC3:
	.string	"65535"
	.align 3
.LC4:
	.string	"All tests passed."
	.section	".text"
	.align 2
	.globl main
	.type	main, @function
main:
.LFB1:
	.loc 1 22 16
	.cfi_startproc
.LCF1:
0:	addis 2,12,.TOC.-.LCF1@ha
	addi 2,2,.TOC.-.LCF1@l
	.localentry	main,.-main
	mflr 0
	std 0,16(1)
	std 31,-8(1)
	stdu 1,-48(1)
	.cfi_def_cfa_offset 48
	.cfi_offset 65, 16
	.cfi_offset 31, -8
	mr 31,1
	.cfi_def_cfa_register 31
	.loc 1 23 9
	addis 3,2,.LC1@toc@ha
	addi 3,3,.LC1@toc@l
	bl parse_decimal
	mr 9,3
	.loc 1 23 8
	cmpwi 0,9,0
	beq 0,.L6
	.loc 1 24 16
	li 9,1
	b .L7
.L6:
	.loc 1 26 9
	addis 3,2,.LC2@toc@ha
	addi 3,3,.LC2@toc@l
	bl parse_decimal
	mr 9,3
	.loc 1 26 8
	cmplwi 0,9,123
	beq 0,.L8
	.loc 1 27 16
	li 9,2
	b .L7
.L8:
	.loc 1 29 9
	addis 3,2,.LC3@toc@ha
	addi 3,3,.LC3@toc@l
	bl parse_decimal
	mr 9,3
	mr 10,9
	.loc 1 29 8
	li 9,0
	ori 9,9,0xffff
	cmpw 0,10,9
	beq 0,.L9
	.loc 1 30 16
	li 9,3
	b .L7
.L9:
	.loc 1 33 5
	addis 3,2,.LC4@toc@ha
	addi 3,3,.LC4@toc@l
	bl puts
	nop
	.loc 1 34 12
	li 9,0
.L7:
	.loc 1 35 1
	extsw 9,9
	mr 3,9
	addi 1,31,48
	.cfi_def_cfa 1, 0
	ld 0,16(1)
	mtlr 0
	ld 31,-8(1)
	blr
	.long 0
	.byte 0,0,0,1,128,1,0,1
	.cfi_endproc
.LFE1:
	.size	main,.-main
.Letext0:
	.file 2 "/usr/powerpc64le-linux-gnu/include/stdio.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x12b
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
	.byte	0x1
	.byte	0x8
	.4byte	.LASF1
	.uleb128 0x3
	.4byte	0x34
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
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x3
	.4byte	0x63
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	.LASF7
	.uleb128 0x5
	.4byte	0x6a
	.4byte	0x86
	.uleb128 0x6
	.4byte	0x2d
	.byte	0x9
	.byte	0
	.uleb128 0x3
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
	.4byte	0x6a
	.uleb128 0x3
	.4byte	0xad
	.uleb128 0xa
	.4byte	.LASF13
	.byte	0x2
	.2byte	0x295
	.byte	0xc
	.4byte	0x63
	.4byte	0xcf
	.uleb128 0xb
	.4byte	0xcf
	.byte	0
	.uleb128 0x9
	.byte	0x8
	.4byte	0x3b
	.uleb128 0xc
	.4byte	.LASF14
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.4byte	0x63
	.8byte	.LFB1
	.8byte	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.4byte	.LASF15
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.4byte	0x4e
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
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0xf
	.4byte	.LASF16
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.4byte	0x4e
	.uleb128 0x2
	.byte	0x91
	.sleb128 -48
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
.LASF10:
	.string	"GNU C17 12.2.0 -msecure-plt -gdwarf-4 -gctf -fasynchronous-unwind-tables"
.LASF9:
	.string	"s_ascii_digit_bias"
.LASF2:
	.string	"unsigned char"
.LASF14:
	.string	"main"
.LASF17:
	.string	"void"
.LASF7:
	.string	"long int"
.LASF11:
	.string	"src/main.c"
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
.LASF1:
	.string	"char"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
