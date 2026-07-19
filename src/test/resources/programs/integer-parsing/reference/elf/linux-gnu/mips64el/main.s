	.section .mdebug.abi64
	.previous
	.nan	legacy
	.module	fp=64
	.module	oddspreg
	.module	arch=mips64r2
	.abicalls
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
	.4byte	0xf
	.4byte	0xd
	.4byte	0x13
	.4byte	0x12
	.4byte	0x10
	.4byte	0x72
	.4byte	0x69
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
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0x21
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x10
	.4byte	0x34
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
	.4byte	0x8
	.4byte	0x1
	.4byte	0xa
	.4byte	0
	.4byte	0x32000000
	.4byte	0xc
	.4byte	0
	.4byte	0xe000000
	.4byte	0x8
	.4byte	0
	.4byte	0x32000000
	.4byte	0xe
	.4byte	0x85
	.4byte	0x16000001
	.4byte	0x7
	.4byte	0x11
	.4byte	0
	.4byte	0
	.4byte	0xe000000
	.4byte	0xb
	.4byte	0x8a
	.4byte	0x16000000
	.4byte	0x7
	.4byte	0x8f
	.4byte	0x16000001
	.4byte	0x4
	.4byte	0x11
	.4byte	0
	.ascii	"\000"
	.ascii	"long unsigned int\000"
	.ascii	"unsigned char\000"
	.ascii	"short unsigned int\000"
	.ascii	"unsigned int\000"
	.ascii	"signed char\000"
	.ascii	"short int\000"
	.ascii	"int\000"
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
.Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "src/main.c"
	.globl	s_ascii_digit_bias
	.section	.data.rel.ro,"aw"
	.align	3
	.type	s_ascii_digit_bias, @object
	.size	s_ascii_digit_bias, 8
s_ascii_digit_bias:
	.dword	s_digits-192
	.text
	.align	2
	.globl	parse_decimal
.LFB0 = .
	.loc 1 11 43
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	parse_decimal
	.type	parse_decimal, @function
parse_decimal:
	.frame	$fp,48,$31		# vars= 32, regs= 1/0, args= 0, gp= 0
	.mask	0x40000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	daddiu	$sp,$sp,-48
	.cfi_def_cfa_offset 48
	sd	$fp,40($sp)
	.cfi_offset 30, -8
	move	$fp,$sp
	.cfi_def_cfa_register 30
	lui	$5,%hi(%neg(%gp_rel(parse_decimal)))
	daddu	$5,$5,$25
	daddiu	$5,$5,%lo(%neg(%gp_rel(parse_decimal)))
	sd	$4,16($fp)
	.loc 1 12 18
	sw	$0,0($fp)
	.loc 1 14 8
	b	.L2
	nop

.L3:
	.loc 1 15 18
	lw	$3,0($fp)
	move	$2,$3
	sll	$2,$2,2
	addu	$2,$2,$3
	sll	$2,$2,1
	move	$3,$2
	.loc 1 15 44
	ld	$2,%got_disp(s_digits)($5)
	daddiu	$4,$2,-192
	.loc 1 15 61
	ld	$2,16($fp)
	lb	$2,0($2)
	.loc 1 15 45
	andi	$2,$2,0x00ff
	.loc 1 15 44
	dsll	$2,$2,2
	daddu	$2,$4,$2
	lw	$2,0($2)
	.loc 1 15 9
	addu	$2,$3,$2
	sw	$2,0($fp)
	.loc 1 16 4
	ld	$2,16($fp)
	daddiu	$2,$2,1
	sd	$2,16($fp)
.L2:
	.loc 1 14 9
	ld	$2,16($fp)
	lb	$2,0($2)
	.loc 1 14 12
	bne	$2,$0,.L3
	nop

	.loc 1 19 12
	lw	$2,0($fp)
	.loc 1 20 1
	move	$sp,$fp
	.cfi_def_cfa_register 29
	ld	$fp,40($sp)
	daddiu	$sp,$sp,48
	.cfi_restore 30
	.cfi_def_cfa_offset 0
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	parse_decimal
	.cfi_endproc
.LFE0:
	.size	parse_decimal, .-parse_decimal
	.rdata
	.align	3
.LC0:
	.ascii	"0\000"
	.align	3
.LC1:
	.ascii	"123\000"
	.align	3
.LC2:
	.ascii	"65535\000"
	.align	3
.LC3:
	.ascii	"All tests passed.\000"
	.text
	.align	2
	.globl	main
.LFB1 = .
	.loc 1 22 16
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	main
	.type	main, @function
main:
	.frame	$fp,32,$31		# vars= 0, regs= 3/0, args= 0, gp= 0
	.mask	0xd0000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	daddiu	$sp,$sp,-32
	.cfi_def_cfa_offset 32
	sd	$31,24($sp)
	sd	$fp,16($sp)
	sd	$28,8($sp)
	.cfi_offset 31, -8
	.cfi_offset 30, -16
	.cfi_offset 28, -24
	move	$fp,$sp
	.cfi_def_cfa_register 30
	lui	$28,%hi(%neg(%gp_rel(main)))
	daddu	$28,$28,$25
	daddiu	$28,$28,%lo(%neg(%gp_rel(main)))
	.loc 1 23 9
	ld	$2,%got_page(.LC0)($28)
	daddiu	$4,$2,%got_ofst(.LC0)
	ld	$2,%got_disp(parse_decimal)($28)
	move	$25,$2
	.reloc	1f,R_MIPS_JALR,parse_decimal
1:	jalr	$25
	nop

.LVL0 = .
	.loc 1 23 8
	beq	$2,$0,.L6
	nop

	.loc 1 24 16
	li	$2,1			# 0x1
	b	.L7
	nop

.L6:
	.loc 1 26 9
	ld	$2,%got_page(.LC1)($28)
	daddiu	$4,$2,%got_ofst(.LC1)
	ld	$2,%got_disp(parse_decimal)($28)
	move	$25,$2
	.reloc	1f,R_MIPS_JALR,parse_decimal
1:	jalr	$25
	nop

.LVL1 = .
	move	$3,$2
	.loc 1 26 8
	li	$2,123			# 0x7b
	beq	$3,$2,.L8
	nop

	.loc 1 27 16
	li	$2,2			# 0x2
	b	.L7
	nop

.L8:
	.loc 1 29 9
	ld	$2,%got_page(.LC2)($28)
	daddiu	$4,$2,%got_ofst(.LC2)
	ld	$2,%got_disp(parse_decimal)($28)
	move	$25,$2
	.reloc	1f,R_MIPS_JALR,parse_decimal
1:	jalr	$25
	nop

.LVL2 = .
	move	$3,$2
	.loc 1 29 8
	li	$2,65535			# 0xffff
	beq	$3,$2,.L9
	nop

	.loc 1 30 16
	li	$2,3			# 0x3
	b	.L7
	nop

.L9:
	.loc 1 33 5
	ld	$2,%got_page(.LC3)($28)
	daddiu	$4,$2,%got_ofst(.LC3)
	ld	$2,%call16(puts)($28)
	move	$25,$2
	.reloc	1f,R_MIPS_JALR,puts
1:	jalr	$25
	nop

.LVL3 = .
	.loc 1 34 12
	move	$2,$0
.L7:
	.loc 1 35 1
	move	$sp,$fp
	.cfi_def_cfa_register 29
	ld	$31,24($sp)
	ld	$fp,16($sp)
	ld	$28,8($sp)
	daddiu	$sp,$sp,32
	.cfi_restore 28
	.cfi_restore 30
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	main
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/mips64el-linux-gnuabi64/include/stdio.h"
	.file 3 "<built-in>"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x173
	.2byte	0x4
	.4byte	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.4byte	.LASF12
	.byte	0xc
	.4byte	.LASF13
	.4byte	.LASF14
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
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.4byte	.LASF2
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	.LASF3
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	.LASF4
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.4byte	.LASF5
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.ascii	"int\000"
	.uleb128 0x4
	.4byte	0x57
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	.LASF6
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	.LASF7
	.uleb128 0x4
	.4byte	0x6a
	.uleb128 0x5
	.4byte	0x5e
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
	.4byte	0x5e
	.uleb128 0x4
	.4byte	0xad
	.uleb128 0xa
	.4byte	.LASF15
	.byte	0x2
	.2byte	0x295
	.byte	0xc
	.4byte	0x57
	.4byte	0xcf
	.uleb128 0xb
	.4byte	0xcf
	.byte	0
	.uleb128 0x9
	.byte	0x8
	.4byte	0x71
	.uleb128 0xc
	.4byte	.LASF10
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.4byte	0x57
	.8byte	.LFB1
	.8byte	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x12c
	.uleb128 0xd
	.8byte	.LVL0
	.4byte	0x12c
	.uleb128 0xd
	.8byte	.LVL1
	.4byte	0x12c
	.uleb128 0xd
	.8byte	.LVL2
	.4byte	0x12c
	.uleb128 0xd
	.8byte	.LVL3
	.4byte	0x16b
	.byte	0
	.uleb128 0xc
	.4byte	.LASF11
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.4byte	0x42
	.8byte	.LFB0
	.8byte	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x16b
	.uleb128 0xe
	.ascii	"s\000"
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
	.4byte	0x42
	.uleb128 0x2
	.byte	0x91
	.sleb128 -48
	.byte	0
	.uleb128 0x10
	.4byte	.LASF15
	.4byte	.LASF17
	.byte	0x3
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
	.uleb128 0xd
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
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
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x6e
	.uleb128 0xe
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
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
.LASF14:
	.ascii	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-e"
	.ascii	"xtension/src/test/resources/programs/integer-parsing\000"
.LASF3:
	.ascii	"unsigned int\000"
.LASF11:
	.ascii	"parse_decimal\000"
.LASF15:
	.ascii	"puts\000"
.LASF17:
	.ascii	"__builtin_puts\000"
.LASF0:
	.ascii	"long unsigned int\000"
.LASF13:
	.ascii	"src/main.c\000"
.LASF9:
	.ascii	"s_ascii_digit_bias\000"
.LASF1:
	.ascii	"unsigned char\000"
.LASF10:
	.ascii	"main\000"
.LASF18:
	.ascii	"void\000"
.LASF6:
	.ascii	"long int\000"
.LASF12:
	.ascii	"GNU C17 12.2.0 -mel -mno-check-zero-division -march=mips"
	.ascii	"64r2 -mllsc -mno-madd4 -mips64r2 -mabi=64 -gdwarf-4 -gct"
	.ascii	"f\000"
.LASF19:
	.ascii	"unknown\000"
.LASF2:
	.ascii	"short unsigned int\000"
.LASF4:
	.ascii	"signed char\000"
.LASF16:
	.ascii	"value\000"
.LASF5:
	.ascii	"short int\000"
.LASF8:
	.ascii	"s_digits\000"
.LASF7:
	.ascii	"char\000"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
