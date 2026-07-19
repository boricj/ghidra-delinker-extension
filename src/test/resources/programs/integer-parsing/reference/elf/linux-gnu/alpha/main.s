	.set noreorder
	.set volatile
	.set noat
	.set nomacro
	.section	.ctf,"",@progbits
$Lctf0:
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
	.4byte	0xf
	.4byte	0xd
	.4byte	0x12
	.4byte	0x10
	.4byte	0x13
	.4byte	0x72
	.4byte	0x69
	.4byte	0x8a
	.4byte	0x85
	.4byte	0x8f
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
	.4byte	0x4
	.4byte	0x1000020
	.4byte	0
	.4byte	0x32000000
	.4byte	0x2
	.4byte	0x17
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0x25
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x10
	.4byte	0x38
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x20
	.4byte	0x45
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x3000008
	.4byte	0x51
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x1000010
	.4byte	0x5b
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x1000040
	.4byte	0x64
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x3000008
	.4byte	0
	.4byte	0x32000000
	.4byte	0xa
	.4byte	0
	.4byte	0x12000000
	.4byte	0
	.4byte	0x3
	.4byte	0x1
	.4byte	0xa
	.4byte	0
	.4byte	0x32000000
	.4byte	0xc
	.4byte	0
	.4byte	0xe000000
	.4byte	0x3
	.4byte	0
	.4byte	0x32000000
	.4byte	0xe
	.4byte	0x85
	.4byte	0x16000001
	.4byte	0x2
	.4byte	0x11
	.4byte	0
	.4byte	0
	.4byte	0xe000000
	.4byte	0xb
	.4byte	0x8a
	.4byte	0x16000000
	.4byte	0x2
	.4byte	0x8f
	.4byte	0x16000001
	.4byte	0x6
	.4byte	0x11
	.4byte	0
	.string	""
	.string	"long unsigned int"
	.string	"int"
	.string	"unsigned char"
	.string	"short unsigned int"
	.string	"unsigned int"
	.string	"signed char"
	.string	"short int"
	.string	"long int"
	.string	"char"
	.string	"s_digits"
	.string	"s_ascii_digit_bias"
	.string	"puts"
	.string	"main"
	.string	"parse_decimal"
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing/src/main.c"
	.text
$Ltext0:
	.file 1 "src/main.c"
	.globl s_ascii_digit_bias
	.section	.sdata,"aws"
	.align 3
	.type	s_ascii_digit_bias, @object
	.size	s_ascii_digit_bias, 8
s_ascii_digit_bias:
	.quad	s_digits-192
	.text
	.align 2
	.globl parse_decimal
	.ent parse_decimal
parse_decimal:
	.eflag 48
	.frame $15,48,$26,0
	.mask 0x4008000,-48
$LFB0:
	.loc 1 11 43
	.cfi_startproc
	ldah $29,0($27)		!gpdisp!1
	lda $29,0($29)		!gpdisp!1
$parse_decimal..ng:
	lda $30,-48($30)
	.cfi_def_cfa_offset 48
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -48
	.cfi_offset 15, -40
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 1
	stq $16,32($15)
	.loc 1 12 18
	stl $31,16($15)
	.loc 1 14 8
	br $31,$L2
$L3:
	.loc 1 15 18
	ldl $2,16($15)
	bis $31,$2,$1
	s4addl $1,0,$1
	addl $1,$2,$1
	addl $1,$1,$1
	addl $31,$1,$2
	.loc 1 15 44
	ldq $1,s_digits($29)		!literal
	lda $3,-192($1)
	.loc 1 15 61
	ldq $1,32($15)
	lda $4,1($1)
	ldq_u $1,0($1)
	extqh $1,$4,$1
	sra $1,56,$1
	.loc 1 15 45
	and $1,0xff,$1
	.loc 1 15 44
	s4addq $1,0,$1
	addq $3,$1,$1
	ldl $1,0($1)
	addl $31,$1,$1
	.loc 1 15 9
	addl $2,$1,$1
	stl $1,16($15)
	.loc 1 16 4
	ldq $1,32($15)
	lda $1,1($1)
	stq $1,32($15)
$L2:
	.loc 1 14 9
	ldq $1,32($15)
	lda $2,1($1)
	ldq_u $1,0($1)
	extqh $1,$2,$1
	sra $1,56,$1
	.loc 1 14 12
	bne $1,$L3
	.loc 1 19 12
	ldl $1,16($15)
	.loc 1 20 1
	mov $1,$0
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,48($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE0:
	.end parse_decimal
	.section	.rodata
$LC0:
	.string	"0"
$LC1:
	.string	"123"
$LC2:
	.string	"65535"
$LC3:
	.string	"All tests passed."
	.text
	.align 2
	.globl main
	.ent main
main:
	.eflag 48
	.frame $15,16,$26,0
	.mask 0x4008000,-16
$LFB1:
	.loc 1 22 16
	.cfi_startproc
	ldah $29,0($27)		!gpdisp!2
	lda $29,0($29)		!gpdisp!2
$main..ng:
	lda $30,-16($30)
	.cfi_def_cfa_offset 16
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -16
	.cfi_offset 15, -8
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 1
	.loc 1 23 9
	ldah $1,$LC0($29)		!gprelhigh
	lda $16,$LC0($1)		!gprellow
	ldq $27,parse_decimal($29)		!literal!3
	jsr $26,($27),0		!lituse_jsr!3
	ldah $29,0($26)		!gpdisp!4
	lda $29,0($29)		!gpdisp!4
	mov $0,$1
	addl $31,$1,$1
	.loc 1 23 8
	beq $1,$L6
	.loc 1 24 16
	lda $1,1($31)
	br $31,$L7
$L6:
	.loc 1 26 9
	ldah $1,$LC1($29)		!gprelhigh
	lda $16,$LC1($1)		!gprellow
	ldq $27,parse_decimal($29)		!literal!5
	jsr $26,($27),0		!lituse_jsr!5
	ldah $29,0($26)		!gpdisp!6
	lda $29,0($29)		!gpdisp!6
	mov $0,$1
	addl $31,$1,$1
	.loc 1 26 8
	zapnot $1,15,$1
	cmpeq $1,123,$1
	bne $1,$L8
	.loc 1 27 16
	lda $1,2($31)
	br $31,$L7
$L8:
	.loc 1 29 9
	ldah $1,$LC2($29)		!gprelhigh
	lda $16,$LC2($1)		!gprellow
	ldq $27,parse_decimal($29)		!literal!7
	jsr $26,($27),0		!lituse_jsr!7
	ldah $29,0($26)		!gpdisp!8
	lda $29,0($29)		!gpdisp!8
	mov $0,$1
	addl $31,$1,$1
	.loc 1 29 8
	zapnot $1,15,$2
	ldah $1,1($31)
	lda $1,-1($1)
	cmpeq $2,$1,$1
	bne $1,$L9
	.loc 1 30 16
	lda $1,3($31)
	br $31,$L7
$L9:
	.loc 1 33 5
	ldah $1,$LC3($29)		!gprelhigh
	lda $16,$LC3($1)		!gprellow
	ldq $27,puts($29)		!literal!9
	jsr $26,($27),0		!lituse_jsr!9
	ldah $29,0($26)		!gpdisp!10
	lda $29,0($29)		!gpdisp!10
	.loc 1 34 12
	mov $31,$1
$L7:
	.loc 1 35 1
	mov $1,$0
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,16($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE1:
	.end main
$Letext0:
	.file 2 "/usr/alpha-linux-gnu/include/stdio.h"
	.section	.debug_info,"",@progbits
$Ldebug_info0:
	.4byte	0x12b
	.2byte	0x4
	.4byte	$Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.4byte	$LASF10
	.byte	0xc
	.4byte	$LASF11
	.4byte	$LASF12
	.8byte	$Ltext0
	.8byte	$Letext0-$Ltext0
	.4byte	$Ldebug_line0
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	$LASF0
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x4
	.4byte	0x34
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	$LASF1
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.4byte	$LASF2
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	$LASF3
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	$LASF4
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.4byte	$LASF5
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	$LASF6
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	$LASF7
	.uleb128 0x4
	.4byte	0x6a
	.uleb128 0x5
	.4byte	0x3b
	.4byte	0x86
	.uleb128 0x6
	.4byte	0x2d
	.byte	0x9
	.byte	0
	.uleb128 0x4
	.4byte	0x76
	.uleb128 0x7
	.4byte	$LASF8
	.byte	0x1
	.byte	0x8
	.byte	0x12
	.4byte	0x86
	.uleb128 0x8
	.4byte	$LASF9
	.byte	0x1
	.byte	0x9
	.byte	0x13
	.4byte	0xb3
	.uleb128 0x9
	.byte	0x3
	.8byte	s_ascii_digit_bias
	.uleb128 0x9
	.byte	0x8
	.4byte	0x3b
	.uleb128 0x4
	.4byte	0xad
	.uleb128 0xa
	.4byte	$LASF13
	.byte	0x2
	.2byte	0x295
	.byte	0xc
	.4byte	0x34
	.4byte	0xcf
	.uleb128 0xb
	.4byte	0xcf
	.byte	0
	.uleb128 0x9
	.byte	0x8
	.4byte	0x71
	.uleb128 0xc
	.4byte	$LASF14
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.4byte	0x34
	.8byte	$LFB1
	.8byte	$LFE1-$LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.4byte	$LASF15
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.4byte	0x4e
	.8byte	$LFB0
	.8byte	$LFE0-$LFB0
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
	.sleb128 -16
	.uleb128 0xf
	.4byte	$LASF16
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.4byte	0x4e
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.byte	0
	.byte	0
	.section	.debug_abbrev,"",@progbits
$Ldebug_abbrev0:
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
	.4byte	$Ldebug_info0
	.byte	0x8
	.byte	0
	.2byte	0
	.2byte	0
	.8byte	$Ltext0
	.8byte	$Letext0-$Ltext0
	.8byte	0
	.8byte	0
	.section	.debug_line,"",@progbits
$Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
$LASF12:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing"
$LASF3:
	.string	"unsigned int"
$LASF15:
	.string	"parse_decimal"
$LASF13:
	.string	"puts"
$LASF0:
	.string	"long unsigned int"
$LASF11:
	.string	"src/main.c"
$LASF9:
	.string	"s_ascii_digit_bias"
$LASF10:
	.string	"GNU C17 12.2.0 -gdwarf-4 -gctf"
$LASF1:
	.string	"unsigned char"
$LASF14:
	.string	"main"
$LASF17:
	.string	"void"
$LASF6:
	.string	"long int"
$LASF18:
	.string	"unknown"
$LASF2:
	.string	"short unsigned int"
$LASF4:
	.string	"signed char"
$LASF16:
	.string	"value"
$LASF5:
	.string	"short int"
$LASF8:
	.string	"s_digits"
$LASF7:
	.string	"char"
	.ident	"GCC: (Debian 12.2.0-13) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
