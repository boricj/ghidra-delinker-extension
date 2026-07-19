	.section .mdebug.abi32
	.previous
	.nan	legacy
	.module	fp=xx
	.module	nooddspreg
	.module	arch=mips32r2
	.abicalls
	.section	.ctf,"",@progbits
$Lctf0:
	.2byte	0xdff2
	.byte	0x4
	.byte	0x2
	.4byte	0
	.4byte	0
	.4byte	0xc2
	.4byte	0
	.4byte	0
	.4byte	0x8
	.4byte	0x14
	.4byte	0x1c
	.4byte	0x28
	.4byte	0x38
	.4byte	0x17c
	.4byte	0x13a
	.4byte	0x11
	.4byte	0xf
	.4byte	0x15
	.4byte	0x14
	.4byte	0x12
	.4byte	0x97
	.4byte	0x8e
	.4byte	0xb4
	.4byte	0xaf
	.4byte	0xaa
	.4byte	0x97
	.4byte	0x11
	.4byte	0x8e
	.4byte	0xf
	.4byte	0x1
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x20
	.4byte	0xe
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0x1c
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x10
	.4byte	0x2f
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x20
	.4byte	0x41
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x3000008
	.4byte	0x4d
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x1000010
	.4byte	0x57
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x1000020
	.4byte	0
	.4byte	0x32000000
	.4byte	0x7
	.4byte	0x5b
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x1000040
	.4byte	0x69
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x40
	.4byte	0x80
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x1000020
	.4byte	0x89
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x3000008
	.4byte	0
	.4byte	0x32000000
	.4byte	0xc
	.4byte	0
	.4byte	0x12000000
	.4byte	0
	.4byte	0x8
	.4byte	0x1
	.4byte	0xa
	.4byte	0
	.4byte	0x32000000
	.4byte	0xe
	.4byte	0
	.4byte	0xe000000
	.4byte	0x8
	.4byte	0
	.4byte	0x32000000
	.4byte	0x10
	.4byte	0xaa
	.4byte	0x16000001
	.4byte	0x7
	.4byte	0x13
	.4byte	0
	.4byte	0
	.4byte	0xe000000
	.4byte	0xd
	.4byte	0xaf
	.4byte	0x16000000
	.4byte	0x7
	.4byte	0xb4
	.4byte	0x16000001
	.4byte	0x1
	.4byte	0x13
	.4byte	0
	.ascii	"\000"
	.ascii	"unsigned int\000"
	.ascii	"unsigned char\000"
	.ascii	"short unsigned int\000"
	.ascii	"long unsigned int\000"
	.ascii	"signed char\000"
	.ascii	"short int\000"
	.ascii	"int\000"
	.ascii	"long long int\000"
	.ascii	"long long unsigned int\000"
	.ascii	"long int\000"
	.ascii	"char\000"
	.ascii	"s_digits\000"
	.ascii	"s_ascii_digit_bias\000"
	.ascii	"puts\000"
	.ascii	"main\000"
	.ascii	"parse_decimal\000"
	.ascii	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-e"
	.ascii	"xtension/src/test/resources/programs/integer-parsing/src"
	.ascii	"/main.c\000"
	.text
$Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "src/main.c"
	.globl	s_ascii_digit_bias
	.section	.data.rel.ro,"aw"
	.align	2
	.type	s_ascii_digit_bias, @object
	.size	s_ascii_digit_bias, 4
s_ascii_digit_bias:
	.word	s_digits-192
	.text
	.align	2
	.globl	parse_decimal
$LFB0 = .
	.loc 1 11 43
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	parse_decimal
	.type	parse_decimal, @function
parse_decimal:
	.frame	$fp,24,$31		# vars= 8, regs= 1/0, args= 0, gp= 8
	.mask	0x40000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.cpload	$25
	.set	nomacro
	addiu	$sp,$sp,-24
	.cfi_def_cfa_offset 24
	sw	$fp,20($sp)
	.cfi_offset 30, -4
	move	$fp,$sp
	.cfi_def_cfa_register 30
	.cprestore	0
	sw	$4,24($fp)
	.loc 1 12 18
	sw	$0,8($fp)
	.loc 1 14 8
	b	$L2
	nop

$L3:
	.loc 1 15 18
	lw	$3,8($fp)
	move	$2,$3
	sll	$2,$2,2
	addu	$2,$2,$3
	sll	$2,$2,1
	move	$4,$2
	.loc 1 15 44
	lw	$2,%got(s_digits)($28)
	addiu	$3,$2,-192
	.loc 1 15 61
	lw	$2,24($fp)
	lb	$2,0($2)
	.loc 1 15 45
	andi	$2,$2,0x00ff
	.loc 1 15 44
	sll	$2,$2,2
	addu	$2,$3,$2
	lw	$2,0($2)
	.loc 1 15 9
	addu	$2,$4,$2
	sw	$2,8($fp)
	.loc 1 16 4
	lw	$2,24($fp)
	addiu	$2,$2,1
	sw	$2,24($fp)
$L2:
	.loc 1 14 9
	lw	$2,24($fp)
	lb	$2,0($2)
	.loc 1 14 12
	bne	$2,$0,$L3
	nop

	.loc 1 19 12
	lw	$2,8($fp)
	.loc 1 20 1
	move	$sp,$fp
	.cfi_def_cfa_register 29
	lw	$fp,20($sp)
	addiu	$sp,$sp,24
	.cfi_restore 30
	.cfi_def_cfa_offset 0
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	parse_decimal
	.cfi_endproc
$LFE0:
	.size	parse_decimal, .-parse_decimal
	.rdata
	.align	2
$LC0:
	.ascii	"0\000"
	.align	2
$LC1:
	.ascii	"123\000"
	.align	2
$LC2:
	.ascii	"65535\000"
	.align	2
$LC3:
	.ascii	"All tests passed.\000"
	.text
	.align	2
	.globl	main
$LFB1 = .
	.loc 1 22 16
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	main
	.type	main, @function
main:
	.frame	$fp,32,$31		# vars= 0, regs= 2/0, args= 16, gp= 8
	.mask	0xc0000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.cpload	$25
	.set	nomacro
	addiu	$sp,$sp,-32
	.cfi_def_cfa_offset 32
	sw	$31,28($sp)
	sw	$fp,24($sp)
	.cfi_offset 31, -4
	.cfi_offset 30, -8
	move	$fp,$sp
	.cfi_def_cfa_register 30
	.cprestore	16
	.loc 1 23 9
	lw	$2,%got($LC0)($28)
	addiu	$4,$2,%lo($LC0)
	lw	$2,%got(parse_decimal)($28)
	move	$25,$2
	.reloc	1f,R_MIPS_JALR,parse_decimal
1:	jalr	$25
	nop

$LVL0 = .
	lw	$28,16($fp)
	.loc 1 23 8
	beq	$2,$0,$L6
	nop

	.loc 1 24 16
	li	$2,1			# 0x1
	b	$L7
	nop

$L6:
	.loc 1 26 9
	lw	$2,%got($LC1)($28)
	addiu	$4,$2,%lo($LC1)
	lw	$2,%got(parse_decimal)($28)
	move	$25,$2
	.reloc	1f,R_MIPS_JALR,parse_decimal
1:	jalr	$25
	nop

$LVL1 = .
	lw	$28,16($fp)
	move	$3,$2
	.loc 1 26 8
	li	$2,123			# 0x7b
	beq	$3,$2,$L8
	nop

	.loc 1 27 16
	li	$2,2			# 0x2
	b	$L7
	nop

$L8:
	.loc 1 29 9
	lw	$2,%got($LC2)($28)
	addiu	$4,$2,%lo($LC2)
	lw	$2,%got(parse_decimal)($28)
	move	$25,$2
	.reloc	1f,R_MIPS_JALR,parse_decimal
1:	jalr	$25
	nop

$LVL2 = .
	lw	$28,16($fp)
	move	$3,$2
	.loc 1 29 8
	li	$2,65535			# 0xffff
	beq	$3,$2,$L9
	nop

	.loc 1 30 16
	li	$2,3			# 0x3
	b	$L7
	nop

$L9:
	.loc 1 33 5
	lw	$2,%got($LC3)($28)
	addiu	$4,$2,%lo($LC3)
	lw	$2,%call16(puts)($28)
	move	$25,$2
	.reloc	1f,R_MIPS_JALR,puts
1:	jalr	$25
	nop

$LVL3 = .
	lw	$28,16($fp)
	.loc 1 34 12
	move	$2,$0
$L7:
	.loc 1 35 1
	move	$sp,$fp
	.cfi_def_cfa_register 29
	lw	$31,28($sp)
	lw	$fp,24($sp)
	addiu	$sp,$sp,32
	.cfi_restore 30
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	main
	.cfi_endproc
$LFE1:
	.size	main, .-main
$Letext0:
	.file 2 "/usr/mipsel-linux-gnu/include/stdio.h"
	.section	.debug_info,"",@progbits
$Ldebug_info0:
	.4byte	0x11d
	.2byte	0x4
	.4byte	$Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	$LASF12
	.byte	0xc
	.4byte	$LASF13
	.4byte	$LASF14
	.4byte	$Ltext0
	.4byte	$Letext0-$Ltext0
	.4byte	$Ldebug_line0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	$LASF0
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
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.ascii	"int\000"
	.uleb128 0x4
	.4byte	0x4f
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	$LASF6
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	$LASF7
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.4byte	$LASF8
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	$LASF9
	.uleb128 0x4
	.4byte	0x70
	.uleb128 0x5
	.4byte	0x56
	.4byte	0x8c
	.uleb128 0x6
	.4byte	0x25
	.byte	0x9
	.byte	0
	.uleb128 0x4
	.4byte	0x7c
	.uleb128 0x7
	.4byte	$LASF10
	.byte	0x1
	.byte	0x8
	.byte	0x12
	.4byte	0x8c
	.uleb128 0x8
	.4byte	$LASF11
	.byte	0x1
	.byte	0x9
	.byte	0x13
	.4byte	0xb5
	.uleb128 0x5
	.byte	0x3
	.4byte	s_ascii_digit_bias
	.uleb128 0x9
	.byte	0x4
	.4byte	0x56
	.uleb128 0x4
	.4byte	0xaf
	.uleb128 0xa
	.4byte	$LASF15
	.byte	0x2
	.2byte	0x295
	.byte	0xc
	.4byte	0x4f
	.4byte	0xd1
	.uleb128 0xb
	.4byte	0xd1
	.byte	0
	.uleb128 0x9
	.byte	0x4
	.4byte	0x77
	.uleb128 0xc
	.4byte	$LASF16
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.4byte	0x4f
	.4byte	$LFB1
	.4byte	$LFE1-$LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.4byte	$LASF17
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.4byte	0x25
	.4byte	$LFB0
	.4byte	$LFE0-$LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.ascii	"s\000"
	.byte	0x1
	.byte	0xb
	.byte	0x28
	.4byte	0xd1
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xf
	.4byte	$LASF18
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.4byte	0x25
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
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
	.4byte	0x1c
	.2byte	0x2
	.4byte	$Ldebug_info0
	.byte	0x4
	.byte	0
	.2byte	0
	.2byte	0
	.4byte	$Ltext0
	.4byte	$Letext0-$Ltext0
	.4byte	0
	.4byte	0
	.section	.debug_line,"",@progbits
$Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
$LASF6:
	.ascii	"long long int\000"
$LASF14:
	.ascii	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-e"
	.ascii	"xtension/src/test/resources/programs/integer-parsing\000"
$LASF0:
	.ascii	"unsigned int\000"
$LASF17:
	.ascii	"parse_decimal\000"
$LASF15:
	.ascii	"puts\000"
$LASF3:
	.ascii	"long unsigned int\000"
$LASF7:
	.ascii	"long long unsigned int\000"
$LASF13:
	.ascii	"src/main.c\000"
$LASF11:
	.ascii	"s_ascii_digit_bias\000"
$LASF1:
	.ascii	"unsigned char\000"
$LASF16:
	.ascii	"main\000"
$LASF19:
	.ascii	"void\000"
$LASF8:
	.ascii	"long int\000"
$LASF20:
	.ascii	"unknown\000"
$LASF2:
	.ascii	"short unsigned int\000"
$LASF4:
	.ascii	"signed char\000"
$LASF12:
	.ascii	"GNU C17 12.2.0 -mel -mno-check-zero-division -march=mips"
	.ascii	"32r2 -mfpxx -mllsc -mno-lxc1-sxc1 -mno-madd4 -mips32r2 -"
	.ascii	"mabi=32 -gdwarf-4 -gctf\000"
$LASF18:
	.ascii	"value\000"
$LASF5:
	.ascii	"short int\000"
$LASF10:
	.ascii	"s_digits\000"
$LASF9:
	.ascii	"char\000"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
