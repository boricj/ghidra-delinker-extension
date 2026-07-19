	.file	"main.c"
	.text
	.little
	.section	.ctf,"",@progbits
.Lctf0:
	.uaword	0xdff2
	.byte	0x4
	.byte	0x2
	.ualong	0
	.ualong	0
	.ualong	0xc2
	.ualong	0
	.ualong	0
	.ualong	0x8
	.ualong	0x14
	.ualong	0x1c
	.ualong	0x28
	.ualong	0x38
	.ualong	0x17c
	.ualong	0x13a
	.ualong	0x11
	.ualong	0xf
	.ualong	0x14
	.ualong	0x15
	.ualong	0x12
	.ualong	0x97
	.ualong	0x8e
	.ualong	0xaf
	.ualong	0xb4
	.ualong	0xaa
	.ualong	0x97
	.ualong	0x11
	.ualong	0x8e
	.ualong	0xf
	.ualong	0x1
	.ualong	0x6000000
	.ualong	0x4
	.ualong	0x20
	.ualong	0xe
	.ualong	0x6000000
	.ualong	0x1
	.ualong	0x2000008
	.ualong	0x1c
	.ualong	0x6000000
	.ualong	0x2
	.ualong	0x10
	.ualong	0x2f
	.ualong	0x6000000
	.ualong	0x4
	.ualong	0x20
	.ualong	0x41
	.ualong	0x6000000
	.ualong	0x1
	.ualong	0x3000008
	.ualong	0x4d
	.ualong	0x6000000
	.ualong	0x2
	.ualong	0x1000010
	.ualong	0x57
	.ualong	0x6000000
	.ualong	0x4
	.ualong	0x1000020
	.ualong	0
	.ualong	0x32000000
	.ualong	0x7
	.ualong	0x5b
	.ualong	0x6000000
	.ualong	0x8
	.ualong	0x1000040
	.ualong	0x69
	.ualong	0x6000000
	.ualong	0x8
	.ualong	0x40
	.ualong	0x80
	.ualong	0x6000000
	.ualong	0x4
	.ualong	0x1000020
	.ualong	0x89
	.ualong	0x6000000
	.ualong	0x1
	.ualong	0x3000008
	.ualong	0
	.ualong	0x32000000
	.ualong	0xc
	.ualong	0
	.ualong	0x12000000
	.ualong	0
	.ualong	0x8
	.ualong	0x1
	.ualong	0xa
	.ualong	0
	.ualong	0x32000000
	.ualong	0xe
	.ualong	0
	.ualong	0xe000000
	.ualong	0x8
	.ualong	0
	.ualong	0x32000000
	.ualong	0x10
	.ualong	0xaa
	.ualong	0x16000001
	.ualong	0x7
	.ualong	0x13
	.ualong	0
	.ualong	0
	.ualong	0xe000000
	.ualong	0xd
	.ualong	0xaf
	.ualong	0x16000000
	.ualong	0x7
	.ualong	0xb4
	.ualong	0x16000001
	.ualong	0x1
	.ualong	0x13
	.ualong	0
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
	.global	s_ascii_digit_bias
	.section	.rodata
	.align 2
	.type	s_ascii_digit_bias, @object
	.size	s_ascii_digit_bias, 4
s_ascii_digit_bias:
	.long	s_digits-192
	.text
	.align 1
	.global	parse_decimal
	.type	parse_decimal, @function
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
	mov.l	r14,@-r15
	.cfi_def_cfa_offset 4
	.cfi_offset 14, -4
	add	#-8,r15
	.cfi_def_cfa_offset 12
	mov	r15,r14
	.cfi_def_cfa_register 14
	mov	r14,r1
	add	#-56,r1
	mov.l	r4,@(56,r1)
	.loc 1 12 18
	mov	r14,r1
	add	#-56,r1
	mov	#0,r2
	mov.l	r2,@(60,r1)
	.loc 1 14 8
	bra	.L2
	nop
	.align 1
.L3:
	.loc 1 15 18
	mov	r14,r1
	add	#-56,r1
	mov.l	@(60,r1),r2
	mov	r2,r1
	shll2	r1
	add	r2,r1
	add	r1,r1
	mov	r1,r3
	.loc 1 15 44
	mov.l	.L5,r2
	.loc 1 15 61
	mov	r14,r1
	add	#-56,r1
	mov.l	@(56,r1),r1
	mov.b	@r1,r1
	.loc 1 15 45
	extu.b	r1,r1
	.loc 1 15 44
	shll2	r1
	add	r2,r1
	mov.l	@r1,r1
	mov	r1,r2
	.loc 1 15 9
	mov	r14,r1
	add	#-56,r1
	add	r3,r2
	mov.l	r2,@(60,r1)
	.loc 1 16 4
	mov	r14,r1
	add	#-56,r1
	mov	r14,r2
	add	#-56,r2
	mov.l	@(56,r2),r2
	add	#1,r2
	mov.l	r2,@(56,r1)
.L2:
	.loc 1 14 9
	mov	r14,r1
	add	#-56,r1
	mov.l	@(56,r1),r1
	mov.b	@r1,r1
	.loc 1 14 12
	tst	r1,r1
	bf	.L3
	.loc 1 19 12
	mov	r14,r1
	add	#-56,r1
	mov.l	@(60,r1),r1
	.loc 1 20 1
	mov	r1,r0
	add	#8,r14
	.cfi_def_cfa_offset 4
	mov	r14,r15
	.cfi_def_cfa_register 15
	mov.l	@r15+,r14
	.cfi_restore 14
	.cfi_def_cfa_offset 0
	rts	
	nop
.L6:
	.align 2
.L5:
	.long	s_digits-192
	.cfi_endproc
.LFE0:
	.size	parse_decimal, .-parse_decimal
	.section	.rodata
	.align 2
.LC0:
	.string	"0"
	.align 2
.LC1:
	.string	"123"
	.align 2
.LC2:
	.string	"65535"
	.align 2
.LC3:
	.string	"All tests passed."
	.text
	.align 1
	.global	main
	.type	main, @function
main:
.LFB1:
	.loc 1 22 16
	.cfi_startproc
	mov.l	r14,@-r15
	.cfi_def_cfa_offset 4
	.cfi_offset 14, -4
	sts.l	pr,@-r15
	.cfi_def_cfa_offset 8
	.cfi_offset 17, -8
	mov	r15,r14
	.cfi_def_cfa_register 14
	.loc 1 23 9
	mov.l	.L12,r1
	mov	r1,r4
	mov.l	.L17,r1
	jsr	@r1
	nop
.LVL0:
	mov	r0,r1
	.loc 1 23 8
	tst	r1,r1
	bt	.L8
	.loc 1 24 16
	mov	#1,r1
	bra	.L9
	nop
	.align 1
.L8:
	.loc 1 26 9
	mov.l	.L14,r1
	mov	r1,r4
	mov.l	.L17,r1
	jsr	@r1
	nop
.LVL1:
	mov	r0,r1
	.loc 1 26 8
	mov	#123,r2
	cmp/eq	r2,r1
	bt	.L10
	.loc 1 27 16
	mov	#2,r1
	bra	.L9
	nop
	.align 1
.L10:
	.loc 1 29 9
	mov.l	.L16,r1
	mov	r1,r4
	mov.l	.L17,r1
	jsr	@r1
	nop
.LVL2:
	mov	r0,r1
	.loc 1 29 8
	mov.l	.L18,r2
	cmp/eq	r2,r1
	bt	.L11
	.loc 1 30 16
	mov	#3,r1
	bra	.L9
	nop
	.align 1
.L11:
	.loc 1 33 5
	mov.l	.L19,r1
	mov	r1,r4
	mov.l	.L20,r1
	jsr	@r1
	nop
.LVL3:
	.loc 1 34 12
	mov	#0,r1
.L9:
	.loc 1 35 1
	mov	r1,r0
	mov	r14,r15
	.cfi_def_cfa_register 15
	lds.l	@r15+,pr
	.cfi_restore 17
	.cfi_def_cfa_offset 4
	mov.l	@r15+,r14
	.cfi_restore 14
	.cfi_def_cfa_offset 0
	rts	
	nop
.L21:
	.align 2
.L12:
	.long	.LC0
.L17:
	.long	parse_decimal
.L14:
	.long	.LC1
.L16:
	.long	.LC2
.L18:
	.long	65535
.L19:
	.long	.LC3
.L20:
	.long	puts
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/sh4-linux-gnu/include/stdio.h"
	.file 3 "<built-in>"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.ualong	0x155
	.uaword	0x4
	.ualong	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.ualong	.LASF14
	.byte	0xc
	.ualong	.LASF15
	.ualong	.LASF16
	.ualong	.Ltext0
	.ualong	.Letext0-.Ltext0
	.ualong	.Ldebug_line0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.ualong	.LASF0
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.ualong	.LASF1
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.ualong	.LASF2
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.ualong	.LASF3
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.ualong	.LASF4
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.ualong	.LASF5
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x4
	.ualong	0x4f
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.ualong	.LASF6
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.ualong	.LASF7
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.ualong	.LASF8
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.ualong	.LASF9
	.uleb128 0x4
	.ualong	0x70
	.uleb128 0x5
	.ualong	0x56
	.ualong	0x8c
	.uleb128 0x6
	.ualong	0x25
	.byte	0x9
	.byte	0
	.uleb128 0x4
	.ualong	0x7c
	.uleb128 0x7
	.ualong	.LASF10
	.byte	0x1
	.byte	0x8
	.byte	0x12
	.ualong	0x8c
	.uleb128 0x8
	.ualong	.LASF11
	.byte	0x1
	.byte	0x9
	.byte	0x13
	.ualong	0xb5
	.uleb128 0x5
	.byte	0x3
	.ualong	s_ascii_digit_bias
	.uleb128 0x9
	.byte	0x4
	.ualong	0x56
	.uleb128 0x4
	.ualong	0xaf
	.uleb128 0xa
	.ualong	.LASF17
	.byte	0x2
	.uaword	0x295
	.byte	0xc
	.ualong	0x4f
	.ualong	0xd1
	.uleb128 0xb
	.ualong	0xd1
	.byte	0
	.uleb128 0x9
	.byte	0x4
	.ualong	0x77
	.uleb128 0xc
	.ualong	.LASF12
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.ualong	0x4f
	.ualong	.LFB1
	.ualong	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.ualong	0x116
	.uleb128 0xd
	.ualong	.LVL0
	.ualong	0x116
	.uleb128 0xd
	.ualong	.LVL1
	.ualong	0x116
	.uleb128 0xd
	.ualong	.LVL2
	.ualong	0x116
	.uleb128 0xd
	.ualong	.LVL3
	.ualong	0x14d
	.byte	0
	.uleb128 0xc
	.ualong	.LASF13
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.ualong	0x25
	.ualong	.LFB0
	.ualong	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.ualong	0x14d
	.uleb128 0xe
	.string	"s"
	.byte	0x1
	.byte	0xb
	.byte	0x28
	.ualong	0xd1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.uleb128 0xf
	.ualong	.LASF18
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.ualong	0x25
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x10
	.ualong	.LASF17
	.ualong	.LASF19
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
	.ualong	0x1c
	.uaword	0x2
	.ualong	.Ldebug_info0
	.byte	0x4
	.byte	0
	.uaword	0
	.uaword	0
	.ualong	.Ltext0
	.ualong	.Letext0-.Ltext0
	.ualong	0
	.ualong	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF6:
	.string	"long long int"
.LASF16:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing"
.LASF0:
	.string	"unsigned int"
.LASF13:
	.string	"parse_decimal"
.LASF17:
	.string	"puts"
.LASF19:
	.string	"__builtin_puts"
.LASF3:
	.string	"long unsigned int"
.LASF7:
	.string	"long long unsigned int"
.LASF15:
	.string	"src/main.c"
.LASF11:
	.string	"s_ascii_digit_bias"
.LASF14:
	.string	"GNU C17 12.2.0 -gdwarf-4 -gctf"
.LASF1:
	.string	"unsigned char"
.LASF12:
	.string	"main"
.LASF20:
	.string	"void"
.LASF8:
	.string	"long int"
.LASF21:
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
