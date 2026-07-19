	.file	"main.c"
	.section	.ctf,"",@progbits
.Lctf0:
	.uahalf	0xdff2
	.byte	0x4
	.byte	0x2
	.uaword	0
	.uaword	0
	.uaword	0x9d
	.uaword	0
	.uaword	0
	.uaword	0x8
	.uaword	0x14
	.uaword	0x1c
	.uaword	0x28
	.uaword	0x38
	.uaword	0x15c
	.uaword	0x115
	.uaword	0xd
	.uaword	0xf
	.uaword	0x12
	.uaword	0x10
	.uaword	0x13
	.uaword	0x69
	.uaword	0x72
	.uaword	0x8a
	.uaword	0x85
	.uaword	0x8f
	.uaword	0x72
	.uaword	0xf
	.uaword	0x69
	.uaword	0xd
	.uaword	0x1
	.uaword	0x6000000
	.uaword	0x8
	.uaword	0x40
	.uaword	0x13
	.uaword	0x6000000
	.uaword	0x1
	.uaword	0x2000008
	.uaword	0x21
	.uaword	0x6000000
	.uaword	0x2
	.uaword	0x10
	.uaword	0x34
	.uaword	0x6000000
	.uaword	0x4
	.uaword	0x20
	.uaword	0x41
	.uaword	0x6000000
	.uaword	0x1
	.uaword	0x3000008
	.uaword	0x4d
	.uaword	0x6000000
	.uaword	0x2
	.uaword	0x1000010
	.uaword	0x57
	.uaword	0x6000000
	.uaword	0x4
	.uaword	0x1000020
	.uaword	0
	.uaword	0x32000000
	.uaword	0x7
	.uaword	0x5b
	.uaword	0x6000000
	.uaword	0x8
	.uaword	0x1000040
	.uaword	0x64
	.uaword	0x6000000
	.uaword	0x1
	.uaword	0x3000008
	.uaword	0
	.uaword	0x32000000
	.uaword	0xa
	.uaword	0
	.uaword	0x12000000
	.uaword	0
	.uaword	0x8
	.uaword	0x1
	.uaword	0xa
	.uaword	0
	.uaword	0x32000000
	.uaword	0xc
	.uaword	0
	.uaword	0xe000000
	.uaword	0x8
	.uaword	0
	.uaword	0x32000000
	.uaword	0xe
	.uaword	0x85
	.uaword	0x16000001
	.uaword	0x7
	.uaword	0x11
	.uaword	0
	.uaword	0
	.uaword	0xe000000
	.uaword	0xb
	.uaword	0x8a
	.uaword	0x16000000
	.uaword	0x7
	.uaword	0x8f
	.uaword	0x16000001
	.uaword	0x4
	.uaword	0x11
	.uaword	0
	.asciz	""
	.asciz	"long unsigned int"
	.asciz	"unsigned char"
	.asciz	"short unsigned int"
	.asciz	"unsigned int"
	.asciz	"signed char"
	.asciz	"short int"
	.asciz	"int"
	.asciz	"long int"
	.asciz	"char"
	.asciz	"s_digits"
	.asciz	"s_ascii_digit_bias"
	.asciz	"puts"
	.asciz	"main"
	.asciz	"parse_decimal"
	.asciz	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing/src/main.c"
	.section	".text"
.Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "src/main.c"
	.global s_ascii_digit_bias
	.section	.data.rel.ro,"aw"
	.align 8
	.type	s_ascii_digit_bias, #object
	.size	s_ascii_digit_bias, 8
s_ascii_digit_bias:
	.xword	s_digits-192
	.section	".text"
	.align 4
	.global parse_decimal
	.type	parse_decimal, #function
	.proc	016
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
	.register	%g2, #scratch
	.register	%g3, #scratch
	save	%sp, -192, %sp
	.cfi_window_save
	.cfi_register 15, 31
	.cfi_def_cfa_register 30
	sethi	%hi(_GLOBAL_OFFSET_TABLE_-8), %l7
	add	%l7, %lo(_GLOBAL_OFFSET_TABLE_-4), %l7
	call	__sparc_get_pc_thunk.l7
	 nop
	mov	%l7, %g3
	stx	%i0, [%fp+2175]
	.loc 1 12 18
	st	%g0, [%fp+2043]
	.loc 1 14 8
	ba,pt	%xcc, .L2
	 nop
.L3:
	.loc 1 15 18
	ld	[%fp+2043], %g2
	mov	%g2, %g1
	sll	%g1, 2, %g1
	add	%g1, %g2, %g1
	add	%g1, %g1, %g1
	mov	%g1, %g4
	.loc 1 15 44
	sethi	%gdop_hix22(s_digits), %g1
	xor	%g1, %gdop_lox10(s_digits), %g1
	ldx	[%g3 + %g1], %g1, %gdop(s_digits)
	add	%g1, -192, %g2
	.loc 1 15 61
	ldx	[%fp+2175], %g1
	ldub	[%g1], %g1
	.loc 1 15 45
	and	%g1, 0xff, %g1
	.loc 1 15 44
	sllx	%g1, 2, %g1
	add	%g2, %g1, %g1
	ld	[%g1], %g1
	.loc 1 15 9
	add	%g4, %g1, %g1
	st	%g1, [%fp+2043]
	.loc 1 16 4
	ldx	[%fp+2175], %g1
	add	%g1, 1, %g1
	stx	%g1, [%fp+2175]
.L2:
	.loc 1 14 9
	ldx	[%fp+2175], %g1
	ldub	[%g1], %g1
	.loc 1 14 12
	sll	%g1, 24, %g1
	sra	%g1, 24, %g1
	cmp	%g1, 0
	bne	%icc, .L3
	 nop
	.loc 1 19 12
	ld	[%fp+2043], %g1
	srl	%g1, 0, %g1
	.loc 1 20 1
	mov	%g1, %i0
	return	%i7+8
	 nop
	.cfi_endproc
.LFE0:
	.size	parse_decimal, .-parse_decimal
	.section	".rodata"
	.align 8
.LC0:
	.asciz	"0"
	.align 8
.LC1:
	.asciz	"123"
	.align 8
.LC2:
	.asciz	"65535"
	.align 8
.LC3:
	.asciz	"All tests passed."
	.section	".text"
	.align 4
	.global main
	.type	main, #function
	.proc	04
main:
.LFB1:
	.loc 1 22 16
	.cfi_startproc
	save	%sp, -176, %sp
	.cfi_window_save
	.cfi_register 15, 31
	.cfi_def_cfa_register 30
	sethi	%hi(_GLOBAL_OFFSET_TABLE_-8), %l7
	add	%l7, %lo(_GLOBAL_OFFSET_TABLE_-4), %l7
	call	__sparc_get_pc_thunk.l7
	 nop
	mov	%l7, %i5
	.loc 1 23 9
	sethi	%gdop_hix22(.LC0), %g1
	xor	%g1, %gdop_lox10(.LC0), %g1
	ldx	[%i5 + %g1], %g1, %gdop(.LC0)
	mov	%g1, %o0
	call	parse_decimal, 0
	 nop
	mov	%o0, %g1
	.loc 1 23 8
	cmp	%g1, 0
	be	%icc, .L6
	 nop
	.loc 1 24 16
	mov	1, %g1
	ba,pt	%xcc, .L7
	 nop
.L6:
	.loc 1 26 9
	sethi	%gdop_hix22(.LC1), %g1
	xor	%g1, %gdop_lox10(.LC1), %g1
	ldx	[%i5 + %g1], %g1, %gdop(.LC1)
	mov	%g1, %o0
	call	parse_decimal, 0
	 nop
	mov	%o0, %g1
	.loc 1 26 8
	cmp	%g1, 123
	be	%icc, .L8
	 nop
	.loc 1 27 16
	mov	2, %g1
	ba,pt	%xcc, .L7
	 nop
.L8:
	.loc 1 29 9
	sethi	%gdop_hix22(.LC2), %g1
	xor	%g1, %gdop_lox10(.LC2), %g1
	ldx	[%i5 + %g1], %g1, %gdop(.LC2)
	mov	%g1, %o0
	call	parse_decimal, 0
	 nop
	mov	%o0, %g1
	mov	%g1, %g2
	.loc 1 29 8
	sethi	%hi(64512), %g1
	or	%g1, 1023, %g1
	cmp	%g2, %g1
	be	%icc, .L9
	 nop
	.loc 1 30 16
	mov	3, %g1
	ba,pt	%xcc, .L7
	 nop
.L9:
	.loc 1 33 5
	sethi	%gdop_hix22(.LC3), %g1
	xor	%g1, %gdop_lox10(.LC3), %g1
	ldx	[%i5 + %g1], %g1, %gdop(.LC3)
	mov	%g1, %o0
	call	puts, 0
	 nop
	.loc 1 34 12
	mov	0, %g1
.L7:
	.loc 1 35 1
	sra	%g1, 0, %g1
	mov	%g1, %i0
	return	%i7+8
	 nop
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/sparc64-linux-gnu/include/stdio.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.uaword	0x12c
	.uahalf	0x4
	.uaword	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.uaword	.LASF10
	.byte	0xc
	.uaword	.LASF11
	.uaword	.LASF12
	.uaxword	.Ltext0
	.uaxword	.Letext0-.Ltext0
	.uaword	.Ldebug_line0
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.uaword	.LASF0
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.uaword	.LASF1
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.uaword	.LASF2
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.uaword	.LASF3
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.uaword	.LASF4
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.uaword	.LASF5
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.asciz	"int"
	.uleb128 0x4
	.uaword	0x57
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.uaword	.LASF6
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.uaword	.LASF7
	.uleb128 0x4
	.uaword	0x6a
	.uleb128 0x5
	.uaword	0x5e
	.uaword	0x86
	.uleb128 0x6
	.uaword	0x2d
	.byte	0x9
	.byte	0
	.uleb128 0x4
	.uaword	0x76
	.uleb128 0x7
	.uaword	.LASF8
	.byte	0x1
	.byte	0x8
	.byte	0x12
	.uaword	0x86
	.uleb128 0x8
	.uaword	.LASF9
	.byte	0x1
	.byte	0x9
	.byte	0x13
	.uaword	0xb3
	.uleb128 0x9
	.byte	0x3
	.uaxword	s_ascii_digit_bias
	.uleb128 0x9
	.byte	0x8
	.uaword	0x5e
	.uleb128 0x4
	.uaword	0xad
	.uleb128 0xa
	.uaword	.LASF13
	.byte	0x2
	.uahalf	0x295
	.byte	0xc
	.uaword	0x57
	.uaword	0xcf
	.uleb128 0xb
	.uaword	0xcf
	.byte	0
	.uleb128 0x9
	.byte	0x8
	.uaword	0x71
	.uleb128 0xc
	.uaword	.LASF14
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.uaword	0x57
	.uaxword	.LFB1
	.uaxword	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.uaword	.LASF15
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.uaword	0x42
	.uaxword	.LFB0
	.uaxword	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.asciz	"s"
	.byte	0x1
	.byte	0xb
	.byte	0x28
	.uaword	0xcf
	.uleb128 0x3
	.byte	0x91
	.sleb128 128
	.uleb128 0xf
	.uaword	.LASF16
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.uaword	0x42
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
	.uaword	0x2c
	.uahalf	0x2
	.uaword	.Ldebug_info0
	.byte	0x8
	.byte	0
	.uahalf	0
	.uahalf	0
	.uaxword	.Ltext0
	.uaxword	.Letext0-.Ltext0
	.uaxword	0
	.uaxword	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF12:
	.asciz	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing"
.LASF3:
	.asciz	"unsigned int"
.LASF15:
	.asciz	"parse_decimal"
.LASF13:
	.asciz	"puts"
.LASF10:
	.asciz	"GNU C17 12.2.0 -mcpu=v9 -gdwarf-4 -gctf"
.LASF0:
	.asciz	"long unsigned int"
.LASF11:
	.asciz	"src/main.c"
.LASF9:
	.asciz	"s_ascii_digit_bias"
.LASF1:
	.asciz	"unsigned char"
.LASF14:
	.asciz	"main"
.LASF17:
	.asciz	"void"
.LASF6:
	.asciz	"long int"
.LASF18:
	.asciz	"unknown"
.LASF2:
	.asciz	"short unsigned int"
.LASF4:
	.asciz	"signed char"
.LASF16:
	.asciz	"value"
.LASF5:
	.asciz	"short int"
.LASF8:
	.asciz	"s_digits"
.LASF7:
	.asciz	"char"
	.ident	"GCC: (Debian 12.2.0-13) 12.2.0"
	.section	.text.__sparc_get_pc_thunk.l7,"axG",@progbits,__sparc_get_pc_thunk.l7,comdat
	.align 4
	.weak	__sparc_get_pc_thunk.l7
	.hidden	__sparc_get_pc_thunk.l7
	.type	__sparc_get_pc_thunk.l7, #function
	.proc	020
__sparc_get_pc_thunk.l7:
	.cfi_startproc
	add	%o7, %l7, %l7
	jmp	%o7+8
	 nop
	.cfi_endproc
	.section	.note.GNU-stack,"",@progbits
