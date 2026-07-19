	.file	"main.c"
	.option pic
	.attribute arch, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zifencei2p0"
	.attribute unaligned_access, 0
	.attribute stack_align, 16
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
	.4byte	0x2000008
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
	.string	""
	.string	"long unsigned int"
	.string	"unsigned char"
	.string	"short unsigned int"
	.string	"unsigned int"
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
	.align	1
	.globl	parse_decimal
	.type	parse_decimal, @function
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
	addi	sp,sp,-48
	.cfi_def_cfa_offset 48
	sd	s0,40(sp)
	.cfi_offset 8, -8
	addi	s0,sp,48
	.cfi_def_cfa 8, 0
	sd	a0,-40(s0)
	.loc 1 12 18
	sw	zero,-20(s0)
	.loc 1 14 8
	j	.L2
.L3:
	.loc 1 15 18
	lw	a5,-20(s0)
	mv	a4,a5
	mv	a5,a4
	slliw	a5,a5,2
	addw	a5,a5,a4
	slliw	a5,a5,1
	sext.w	a4,a5
	.loc 1 15 44
	la	a5,s_digits
	addi	a3,a5,-192
	.loc 1 15 61
	ld	a5,-40(s0)
	lbu	a5,0(a5)
	.loc 1 15 44
	slli	a5,a5,2
	add	a5,a3,a5
	lw	a5,0(a5)
	sext.w	a5,a5
	.loc 1 15 9
	addw	a5,a4,a5
	sw	a5,-20(s0)
	.loc 1 16 4
	ld	a5,-40(s0)
	addi	a5,a5,1
	sd	a5,-40(s0)
.L2:
	.loc 1 14 9
	ld	a5,-40(s0)
	lbu	a5,0(a5)
	.loc 1 14 12
	bne	a5,zero,.L3
	.loc 1 19 12
	lw	a5,-20(s0)
	.loc 1 20 1
	mv	a0,a5
	ld	s0,40(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 48
	addi	sp,sp,48
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE0:
	.size	parse_decimal, .-parse_decimal
	.section	.rodata
	.align	3
.LC0:
	.string	"0"
	.align	3
.LC1:
	.string	"123"
	.align	3
.LC2:
	.string	"65535"
	.align	3
.LC3:
	.string	"All tests passed."
	.text
	.align	1
	.globl	main
	.type	main, @function
main:
.LFB1:
	.loc 1 22 16
	.cfi_startproc
	addi	sp,sp,-16
	.cfi_def_cfa_offset 16
	sd	ra,8(sp)
	sd	s0,0(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	addi	s0,sp,16
	.cfi_def_cfa 8, 0
	.loc 1 23 9
	lla	a0,.LC0
	call	parse_decimal
	mv	a5,a0
	sext.w	a5,a5
	.loc 1 23 8
	beq	a5,zero,.L6
	.loc 1 24 16
	li	a5,1
	j	.L7
.L6:
	.loc 1 26 9
	lla	a0,.LC1
	call	parse_decimal
	mv	a5,a0
	sext.w	a5,a5
	.loc 1 26 8
	mv	a4,a5
	li	a5,123
	beq	a4,a5,.L8
	.loc 1 27 16
	li	a5,2
	j	.L7
.L8:
	.loc 1 29 9
	lla	a0,.LC2
	call	parse_decimal
	mv	a5,a0
	sext.w	a5,a5
	.loc 1 29 8
	mv	a4,a5
	li	a5,65536
	addi	a5,a5,-1
	beq	a4,a5,.L9
	.loc 1 30 16
	li	a5,3
	j	.L7
.L9:
	.loc 1 33 5
	lla	a0,.LC3
	call	puts@plt
	.loc 1 34 12
	li	a5,0
.L7:
	.loc 1 35 1
	mv	a0,a5
	ld	ra,8(sp)
	.cfi_restore 1
	ld	s0,0(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 16
	addi	sp,sp,16
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/riscv64-linux-gnu/include/stdio.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x12b
	.2byte	0x4
	.4byte	.Ldebug_abbrev0
	.byte	0x8
	.byte	0x1
	.4byte	.LASF10
	.byte	0xc
	.4byte	.LASF11
	.4byte	.LASF12
	.8byte	.Ltext0
	.8byte	.Letext0-.Ltext0
	.4byte	.Ldebug_line0
	.byte	0x2
	.byte	0x8
	.byte	0x7
	.4byte	.LASF0
	.byte	0x2
	.byte	0x1
	.byte	0x8
	.4byte	.LASF1
	.byte	0x2
	.byte	0x2
	.byte	0x7
	.4byte	.LASF2
	.byte	0x2
	.byte	0x4
	.byte	0x7
	.4byte	.LASF3
	.byte	0x2
	.byte	0x1
	.byte	0x6
	.4byte	.LASF4
	.byte	0x2
	.byte	0x2
	.byte	0x5
	.4byte	.LASF5
	.byte	0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.byte	0x4
	.4byte	0x57
	.byte	0x2
	.byte	0x8
	.byte	0x5
	.4byte	.LASF6
	.byte	0x2
	.byte	0x1
	.byte	0x8
	.4byte	.LASF7
	.byte	0x4
	.4byte	0x6a
	.byte	0x5
	.4byte	0x5e
	.4byte	0x86
	.byte	0x6
	.4byte	0x2d
	.byte	0x9
	.byte	0
	.byte	0x4
	.4byte	0x76
	.byte	0x7
	.4byte	.LASF8
	.byte	0x1
	.byte	0x8
	.byte	0x12
	.4byte	0x86
	.byte	0x8
	.4byte	.LASF9
	.byte	0x1
	.byte	0x9
	.byte	0x13
	.4byte	0xb3
	.byte	0x9
	.byte	0x3
	.8byte	s_ascii_digit_bias
	.byte	0x9
	.byte	0x8
	.4byte	0x5e
	.byte	0x4
	.4byte	0xad
	.byte	0xa
	.4byte	.LASF13
	.byte	0x2
	.2byte	0x295
	.byte	0xc
	.4byte	0x57
	.4byte	0xcf
	.byte	0xb
	.4byte	0xcf
	.byte	0
	.byte	0x9
	.byte	0x8
	.4byte	0x71
	.byte	0xc
	.4byte	.LASF14
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.4byte	0x57
	.8byte	.LFB1
	.8byte	.LFE1-.LFB1
	.byte	0x1
	.byte	0x9c
	.byte	0xd
	.4byte	.LASF15
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.4byte	0x42
	.8byte	.LFB0
	.8byte	.LFE0-.LFB0
	.byte	0x1
	.byte	0x9c
	.byte	0xe
	.string	"s"
	.byte	0x1
	.byte	0xb
	.byte	0x28
	.4byte	0xcf
	.byte	0x2
	.byte	0x91
	.byte	0x58
	.byte	0xf
	.4byte	.LASF16
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.4byte	0x42
	.byte	0x2
	.byte	0x91
	.byte	0x6c
	.byte	0
	.byte	0
	.section	.debug_abbrev,"",@progbits
.Ldebug_abbrev0:
	.byte	0x1
	.byte	0x11
	.byte	0x1
	.byte	0x25
	.byte	0xe
	.byte	0x13
	.byte	0xb
	.byte	0x3
	.byte	0xe
	.byte	0x1b
	.byte	0xe
	.byte	0x11
	.byte	0x1
	.byte	0x12
	.byte	0x7
	.byte	0x10
	.byte	0x17
	.byte	0
	.byte	0
	.byte	0x2
	.byte	0x24
	.byte	0
	.byte	0xb
	.byte	0xb
	.byte	0x3e
	.byte	0xb
	.byte	0x3
	.byte	0xe
	.byte	0
	.byte	0
	.byte	0x3
	.byte	0x24
	.byte	0
	.byte	0xb
	.byte	0xb
	.byte	0x3e
	.byte	0xb
	.byte	0x3
	.byte	0x8
	.byte	0
	.byte	0
	.byte	0x4
	.byte	0x26
	.byte	0
	.byte	0x49
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x5
	.byte	0x1
	.byte	0x1
	.byte	0x49
	.byte	0x13
	.byte	0x1
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x6
	.byte	0x21
	.byte	0
	.byte	0x49
	.byte	0x13
	.byte	0x2f
	.byte	0xb
	.byte	0
	.byte	0
	.byte	0x7
	.byte	0x34
	.byte	0
	.byte	0x3
	.byte	0xe
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x39
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0x3f
	.byte	0x19
	.byte	0x3c
	.byte	0x19
	.byte	0
	.byte	0
	.byte	0x8
	.byte	0x34
	.byte	0
	.byte	0x3
	.byte	0xe
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x39
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0x3f
	.byte	0x19
	.byte	0x2
	.byte	0x18
	.byte	0
	.byte	0
	.byte	0x9
	.byte	0xf
	.byte	0
	.byte	0xb
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0xa
	.byte	0x2e
	.byte	0x1
	.byte	0x3f
	.byte	0x19
	.byte	0x3
	.byte	0xe
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0x5
	.byte	0x39
	.byte	0xb
	.byte	0x27
	.byte	0x19
	.byte	0x49
	.byte	0x13
	.byte	0x3c
	.byte	0x19
	.byte	0x1
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0xb
	.byte	0x5
	.byte	0
	.byte	0x49
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0xc
	.byte	0x2e
	.byte	0
	.byte	0x3f
	.byte	0x19
	.byte	0x3
	.byte	0xe
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x39
	.byte	0xb
	.byte	0x27
	.byte	0x19
	.byte	0x49
	.byte	0x13
	.byte	0x11
	.byte	0x1
	.byte	0x12
	.byte	0x7
	.byte	0x40
	.byte	0x18
	.byte	0x96,0x42
	.byte	0x19
	.byte	0
	.byte	0
	.byte	0xd
	.byte	0x2e
	.byte	0x1
	.byte	0x3f
	.byte	0x19
	.byte	0x3
	.byte	0xe
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x39
	.byte	0xb
	.byte	0x27
	.byte	0x19
	.byte	0x49
	.byte	0x13
	.byte	0x11
	.byte	0x1
	.byte	0x12
	.byte	0x7
	.byte	0x40
	.byte	0x18
	.byte	0x97,0x42
	.byte	0x19
	.byte	0
	.byte	0
	.byte	0xe
	.byte	0x5
	.byte	0
	.byte	0x3
	.byte	0x8
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x39
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0x2
	.byte	0x18
	.byte	0
	.byte	0
	.byte	0xf
	.byte	0x34
	.byte	0
	.byte	0x3
	.byte	0xe
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x39
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0x2
	.byte	0x18
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
.LASF3:
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
.LASF10:
	.string	"GNU C17 12.2.0 -mabi=lp64d -misa-spec=20191213 -march=rv64imafdc_zicsr_zifencei -gdwarf-4 -gctf"
.LASF1:
	.string	"unsigned char"
.LASF14:
	.string	"main"
.LASF17:
	.string	"void"
.LASF6:
	.string	"long int"
.LASF18:
	.string	"unknown"
.LASF2:
	.string	"short unsigned int"
.LASF4:
	.string	"signed char"
.LASF16:
	.string	"value"
.LASF5:
	.string	"short int"
.LASF8:
	.string	"s_digits"
.LASF7:
	.string	"char"
	.ident	"GCC: (Debian 12.2.0-13) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
