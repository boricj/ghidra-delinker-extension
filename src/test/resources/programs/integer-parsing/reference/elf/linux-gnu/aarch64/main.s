	.arch armv8-a
	.file	"main.c"
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
	.4byte	0x10
	.4byte	0x12
	.4byte	0x13
	.4byte	0x69
	.4byte	0x72
	.4byte	0x85
	.4byte	0x8a
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
	.4byte	0x2000008
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
.Ltext0:
	.file 1 "src/main.c"
	.global	s_ascii_digit_bias
	.section	.data.rel.ro,"aw"
	.align	3
	.type	s_ascii_digit_bias, %object
	.size	s_ascii_digit_bias, 8
s_ascii_digit_bias:
	.xword	s_digits-192
	.text
	.align	2
	.global	parse_decimal
	.type	parse_decimal, %function
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
	sub	sp, sp, #32
	.cfi_def_cfa_offset 32
	str	x0, [sp, 8]
	.loc 1 12 18
	str	wzr, [sp, 28]
	.loc 1 14 8
	b	.L2
.L3:
	.loc 1 15 18
	ldr	w1, [sp, 28]
	mov	w0, w1
	lsl	w0, w0, 2
	add	w0, w0, w1
	lsl	w0, w0, 1
	mov	w2, w0
	.loc 1 15 44
	adrp	x0, :got:s_digits
	ldr	x0, [x0, :got_lo12:s_digits]
	sub	x1, x0, #192
	.loc 1 15 61
	ldr	x0, [sp, 8]
	ldrb	w0, [x0]
	.loc 1 15 45
	and	x0, x0, 255
	.loc 1 15 44
	lsl	x0, x0, 2
	add	x0, x1, x0
	ldr	w0, [x0]
	.loc 1 15 9
	add	w0, w2, w0
	str	w0, [sp, 28]
	.loc 1 16 4
	ldr	x0, [sp, 8]
	add	x0, x0, 1
	str	x0, [sp, 8]
.L2:
	.loc 1 14 9
	ldr	x0, [sp, 8]
	ldrb	w0, [x0]
	.loc 1 14 12
	cmp	w0, 0
	bne	.L3
	.loc 1 19 12
	ldr	w0, [sp, 28]
	.loc 1 20 1
	add	sp, sp, 32
	.cfi_def_cfa_offset 0
	ret
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
	.align	2
	.global	main
	.type	main, %function
main:
.LFB1:
	.loc 1 22 16
	.cfi_startproc
	stp	x29, x30, [sp, -16]!
	.cfi_def_cfa_offset 16
	.cfi_offset 29, -16
	.cfi_offset 30, -8
	mov	x29, sp
	.loc 1 23 9
	adrp	x0, .LC0
	add	x0, x0, :lo12:.LC0
	bl	parse_decimal
	.loc 1 23 8
	cmp	w0, 0
	beq	.L6
	.loc 1 24 16
	mov	w0, 1
	b	.L7
.L6:
	.loc 1 26 9
	adrp	x0, .LC1
	add	x0, x0, :lo12:.LC1
	bl	parse_decimal
	.loc 1 26 8
	cmp	w0, 123
	beq	.L8
	.loc 1 27 16
	mov	w0, 2
	b	.L7
.L8:
	.loc 1 29 9
	adrp	x0, .LC2
	add	x0, x0, :lo12:.LC2
	bl	parse_decimal
	mov	w1, w0
	.loc 1 29 8
	mov	w0, 65535
	cmp	w1, w0
	beq	.L9
	.loc 1 30 16
	mov	w0, 3
	b	.L7
.L9:
	.loc 1 33 5
	adrp	x0, .LC3
	add	x0, x0, :lo12:.LC3
	bl	puts
	.loc 1 34 12
	mov	w0, 0
.L7:
	.loc 1 35 1
	ldp	x29, x30, [sp], 16
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/aarch64-linux-gnu/include/stdio.h"
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
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x4
	.4byte	0x34
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
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	.LASF6
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	.LASF7
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
	.4byte	0x3b
	.uleb128 0x4
	.4byte	0xad
	.uleb128 0xa
	.4byte	.LASF13
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
	.4byte	.LASF14
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.4byte	0x34
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
	.sleb128 -24
	.uleb128 0xf
	.4byte	.LASF16
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.4byte	0x4e
	.uleb128 0x2
	.byte	0x91
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
.LASF1:
	.string	"unsigned char"
.LASF14:
	.string	"main"
.LASF17:
	.string	"void"
.LASF6:
	.string	"long int"
.LASF10:
	.string	"GNU C17 12.2.0 -mlittle-endian -mabi=lp64 -gdwarf-4 -gctf -fasynchronous-unwind-tables"
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
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
