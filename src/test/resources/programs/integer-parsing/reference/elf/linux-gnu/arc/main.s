	.file	"main.c"
	.cpu HS
	.arc_attribute Tag_ARC_PCS_config, 3
	.arc_attribute Tag_ARC_ABI_rf16, 0
	.arc_attribute Tag_ARC_ABI_pic, 0
	.arc_attribute Tag_ARC_ABI_tls, 1
	.arc_attribute Tag_ARC_ABI_sda, 0
	.arc_attribute Tag_ARC_ABI_exceptions, 0
	.arc_attribute Tag_ARC_CPU_variation, 2
	.section	.ctf,"",@progbits
.Lctf0:
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
	.4byte	0xf
	.4byte	0x11
	.4byte	0x12
	.4byte	0x15
	.4byte	0x14
	.4byte	0x8e
	.4byte	0x97
	.4byte	0xaa
	.4byte	0xb4
	.4byte	0xaf
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
	.4byte	0x2000008
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
	.section	.text
.Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "src/main.c"
	.global	s_ascii_digit_bias
	.section	.rodata
	.align 4
	.type	s_ascii_digit_bias, @object
	.size	s_ascii_digit_bias, 4
s_ascii_digit_bias:
	.word	@s_digits-192
	.section	.text
	.align 4
	.global	parse_decimal
	.type	parse_decimal, @function
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 4
	.cfi_offset 27, -4
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,8 ;4
	st	r0,[fp,-8]	;26
	.loc 1 12 18
	st	0,[fp,-4]	;37
	.loc 1 14 8
	b_s @.L2
	.align 4
.L3:
	.loc 1 15 18
	ld	r2,[fp,-4]	;23
	mpy	r2,r2,10
	.loc 1 15 44
	mov_s	r12,@s_digits-192	;13
	.loc 1 15 61
	ld	r3,[fp,-8]	;23
	ldb_s	r3,[r3]
	.loc 1 15 44
	asl_s	r3,r3,2
	add_s r3,r12,r3 ;1
	ld_s	r3,[r3]		;15
	.loc 1 15 9
	add_s r2,r2,r3 ;1
	st	r2,[fp,-4]	;26
	.loc 1 16 4
	ld	r2,[fp,-8]	;23
	add_s r2,r2,1 ;1
	st	r2,[fp,-8]	;26
	.align 2
.L2:
	.loc 1 14 9
	ld	r2,[fp,-8]	;23
	ldb_s	r2,[r2]
	.loc 1 14 12
	tst_s r2,r2
	bne_s @.L3
	.loc 1 19 12
	ld	r2,[fp,-4]	;23
	.loc 1 20 1
	mov_s	r0,r2	;4
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	j_s	[blink]
	.cfi_endproc
.LFE0:
	.size	parse_decimal, .-parse_decimal
	.section	.rodata
	.align 4
.LC0:
	.string	"0"
	.align 4
.LC1:
	.string	"123"
	.align 4
.LC2:
	.string	"65535"
	.align 4
.LC3:
	.string	"All tests passed."
	.section	.text
	.align 4
	.global	main
	.type	main, @function
main:
.LFB1:
	.loc 1 22 16
	.cfi_startproc
	push_s	blink
	.cfi_def_cfa_offset 4
	.cfi_offset 31, -4
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 8
	.cfi_offset 27, -8
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	.loc 1 23 9
	mov_s	r0,@.LC0	;13
	bl @parse_decimal;1
	mov_s	r2,r0	;4
	.loc 1 23 8
	tst_s r2,r2
	beq_s @.L6
	.loc 1 24 16
	mov_s	r2,1	;3
	b_s @.L7
	.align 4
.L6:
	.loc 1 26 9
	mov_s	r0,@.LC1	;13
	bl @parse_decimal;1
	mov_s	r2,r0	;4
	.loc 1 26 8
	cmp_s r2,123
	beq_s @.L8
	.loc 1 27 16
	mov_s	r2,2	;3
	b_s @.L7
	.align 4
.L8:
	.loc 1 29 9
	mov_s	r0,@.LC2	;13
	bl @parse_decimal;1
	mov_s	r2,r0	;4
	.loc 1 29 8
	cmp_s r2,65535
	beq_s @.L9
	.loc 1 30 16
	mov_s	r2,3	;3
	b_s @.L7
	.align 4
.L9:
	.loc 1 33 5
	mov_s	r0,@.LC3	;13
	bl @puts;1
	.loc 1 34 12
	mov_s	r2,0	;3
	.align 2
.L7:
	.loc 1 35 1
	mov_s	r0,r2	;4
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	.cfi_def_cfa 28, 4
	pop_s	blink
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	j_s	[blink]
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/arc-linux-gnu/include/stdio.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x11d
	.2byte	0x4
	.4byte	@.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	@.LASF12
	.byte	0xc
	.4byte	@.LASF13
	.4byte	@.LASF14
	.4byte	@.Ltext0
	.4byte	@.Letext0-@.Ltext0
	.4byte	@.Ldebug_line0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	@.LASF0
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	@.LASF1
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.4byte	@.LASF2
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	@.LASF3
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	@.LASF4
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.4byte	@.LASF5
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x4
	.4byte	0x4f
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	@.LASF6
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	@.LASF7
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.4byte	@.LASF8
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	@.LASF9
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
	.4byte	@.LASF10
	.byte	0x1
	.byte	0x8
	.byte	0x12
	.4byte	0x8c
	.uleb128 0x8
	.4byte	@.LASF11
	.byte	0x1
	.byte	0x9
	.byte	0x13
	.4byte	0xb5
	.uleb128 0x5
	.byte	0x3
	.4byte	@s_ascii_digit_bias
	.uleb128 0x9
	.byte	0x4
	.4byte	0x56
	.uleb128 0x4
	.4byte	0xaf
	.uleb128 0xa
	.4byte	@.LASF15
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
	.4byte	@.LASF16
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.4byte	0x4f
	.4byte	@.LFB1
	.4byte	@.LFE1-@.LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.4byte	@.LASF17
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.4byte	0x25
	.4byte	@.LFB0
	.4byte	@.LFE0-@.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xe
	.string	"s"
	.byte	0x1
	.byte	0xb
	.byte	0x28
	.4byte	0xd1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.uleb128 0xf
	.4byte	@.LASF18
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.4byte	0x25
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
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
	.4byte	0x1c
	.2byte	0x2
	.4byte	@.Ldebug_info0
	.byte	0x4
	.byte	0
	.2byte	0
	.2byte	0
	.4byte	@.Ltext0
	.4byte	@.Letext0-@.Ltext0
	.4byte	0
	.4byte	0
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
.LASF3:
	.string	"long unsigned int"
.LASF7:
	.string	"long long unsigned int"
.LASF13:
	.string	"src/main.c"
.LASF11:
	.string	"s_ascii_digit_bias"
.LASF12:
	.string	"GNU C17 12.2.0 -gdwarf-4 -gctf"
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
