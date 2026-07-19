	.arch armv7-a
	.fpu vfpv3-d16
	.eabi_attribute 28, 1
	.eabi_attribute 20, 1
	.eabi_attribute 21, 1
	.eabi_attribute 23, 3
	.eabi_attribute 24, 1
	.eabi_attribute 25, 1
	.eabi_attribute 26, 2
	.eabi_attribute 30, 6
	.eabi_attribute 34, 1
	.eabi_attribute 18, 4
	.file	"main.c"
	.section	.ctf,"",%progbits
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
	.ascii	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delin"
	.ascii	"ker-extension/src/test/resources/programs/integer-p"
	.ascii	"arsing/src/main.c\000"
	.text
.Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "src/main.c"
	.global	s_ascii_digit_bias
	.section	.data.rel.ro,"aw"
	.align	2
	.type	s_ascii_digit_bias, %object
	.size	s_ascii_digit_bias, 4
s_ascii_digit_bias:
	.word	s_digits-192
	.text
	.align	1
	.global	parse_decimal
	.syntax unified
	.thumb
	.thumb_func
	.type	parse_decimal, %function
parse_decimal:
.LFB0:
	.loc 1 11 43
	.cfi_startproc
	@ args = 0, pretend = 0, frame = 16
	@ frame_needed = 1, uses_anonymous_args = 0
	@ link register save eliminated.
	push	{r7}
	.cfi_def_cfa_offset 4
	.cfi_offset 7, -4
	sub	sp, sp, #20
	.cfi_def_cfa_offset 24
	add	r7, sp, #0
	.cfi_def_cfa_register 7
	str	r0, [r7, #4]
	ldr	r2, .L5
.LPIC0:
	add	r2, pc
	.loc 1 12 18
	movs	r3, #0
	str	r3, [r7, #12]
	.loc 1 14 8
	b	.L2
.L3:
	.loc 1 15 18
	ldr	r3, [r7, #12]
	movs	r1, #10
	mul	r3, r1, r3
	.loc 1 15 44
	ldr	r1, .L5+4
	ldr	r1, [r2, r1]
	sub	r0, r1, #192
	.loc 1 15 61
	ldr	r1, [r7, #4]
	ldrb	r1, [r1]	@ zero_extendqisi2
	.loc 1 15 44
	lsls	r1, r1, #2
	add	r1, r1, r0
	ldr	r1, [r1]
	.loc 1 15 9
	add	r3, r3, r1
	str	r3, [r7, #12]
	.loc 1 16 4
	ldr	r3, [r7, #4]
	adds	r3, r3, #1
	str	r3, [r7, #4]
.L2:
	.loc 1 14 9
	ldr	r3, [r7, #4]
	ldrb	r3, [r3]	@ zero_extendqisi2
	.loc 1 14 12
	cmp	r3, #0
	bne	.L3
	.loc 1 19 12
	ldr	r3, [r7, #12]
	.loc 1 20 1
	mov	r0, r3
	adds	r7, r7, #20
	.cfi_def_cfa_offset 4
	mov	sp, r7
	.cfi_def_cfa_register 13
	@ sp needed
	ldr	r7, [sp], #4
	.cfi_restore 7
	.cfi_def_cfa_offset 0
	bx	lr
.L6:
	.align	2
.L5:
	.word	_GLOBAL_OFFSET_TABLE_-(.LPIC0+4)
	.word	s_digits(GOT)
	.cfi_endproc
.LFE0:
	.size	parse_decimal, .-parse_decimal
	.section	.rodata
	.align	2
.LC0:
	.ascii	"0\000"
	.align	2
.LC1:
	.ascii	"123\000"
	.align	2
.LC2:
	.ascii	"65535\000"
	.align	2
.LC3:
	.ascii	"All tests passed.\000"
	.text
	.align	1
	.global	main
	.syntax unified
	.thumb
	.thumb_func
	.type	main, %function
main:
.LFB1:
	.loc 1 22 16
	.cfi_startproc
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 1, uses_anonymous_args = 0
	push	{r7, lr}
	.cfi_def_cfa_offset 8
	.cfi_offset 7, -8
	.cfi_offset 14, -4
	add	r7, sp, #0
	.cfi_def_cfa_register 7
	.loc 1 23 9
	ldr	r3, .L12
.LPIC1:
	add	r3, pc
	mov	r0, r3
	bl	parse_decimal(PLT)
	mov	r3, r0
	.loc 1 23 8
	cmp	r3, #0
	beq	.L8
	.loc 1 24 16
	movs	r3, #1
	b	.L9
.L8:
	.loc 1 26 9
	ldr	r3, .L12+4
.LPIC2:
	add	r3, pc
	mov	r0, r3
	bl	parse_decimal(PLT)
	mov	r3, r0
	.loc 1 26 8
	cmp	r3, #123
	beq	.L10
	.loc 1 27 16
	movs	r3, #2
	b	.L9
.L10:
	.loc 1 29 9
	ldr	r3, .L12+8
.LPIC3:
	add	r3, pc
	mov	r0, r3
	bl	parse_decimal(PLT)
	mov	r3, r0
	.loc 1 29 8
	movw	r2, #65535
	cmp	r3, r2
	beq	.L11
	.loc 1 30 16
	movs	r3, #3
	b	.L9
.L11:
	.loc 1 33 5
	ldr	r3, .L12+12
.LPIC4:
	add	r3, pc
	mov	r0, r3
	bl	puts(PLT)
	.loc 1 34 12
	movs	r3, #0
.L9:
	.loc 1 35 1
	mov	r0, r3
	pop	{r7, pc}
.L13:
	.align	2
.L12:
	.word	.LC0-(.LPIC1+4)
	.word	.LC1-(.LPIC2+4)
	.word	.LC2-(.LPIC3+4)
	.word	.LC3-(.LPIC4+4)
	.cfi_endproc
.LFE1:
	.size	main, .-main
.Letext0:
	.file 2 "/usr/arm-linux-gnueabihf/include/stdio.h"
	.section	.debug_info,"",%progbits
.Ldebug_info0:
	.4byte	0x11d
	.2byte	0x4
	.4byte	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	.LASF12
	.byte	0xc
	.4byte	.LASF13
	.4byte	.LASF14
	.4byte	.Ltext0
	.4byte	.Letext0-.Ltext0
	.4byte	.Ldebug_line0
	.uleb128 0x2
	.byte	0x4
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
	.4byte	0x4f
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	.LASF6
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	.LASF7
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.4byte	.LASF8
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	.LASF9
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
	.4byte	.LASF10
	.byte	0x1
	.byte	0x8
	.byte	0x12
	.4byte	0x8c
	.uleb128 0x8
	.4byte	.LASF11
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
	.4byte	.LASF15
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
	.4byte	.LASF16
	.byte	0x1
	.byte	0x16
	.byte	0x5
	.4byte	0x4f
	.4byte	.LFB1
	.4byte	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.4byte	.LASF17
	.byte	0x1
	.byte	0xb
	.byte	0xe
	.4byte	0x25
	.4byte	.LFB0
	.4byte	.LFE0-.LFB0
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
	.sleb128 -20
	.uleb128 0xf
	.4byte	.LASF18
	.byte	0x1
	.byte	0xc
	.byte	0x12
	.4byte	0x25
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.byte	0
	.byte	0
	.section	.debug_abbrev,"",%progbits
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
	.section	.debug_aranges,"",%progbits
	.4byte	0x1c
	.2byte	0x2
	.4byte	.Ldebug_info0
	.byte	0x4
	.byte	0
	.2byte	0
	.2byte	0
	.4byte	.Ltext0
	.4byte	.Letext0-.Ltext0
	.4byte	0
	.4byte	0
	.section	.debug_line,"",%progbits
.Ldebug_line0:
	.section	.debug_str,"MS",%progbits,1
.LASF6:
	.ascii	"long long int\000"
.LASF14:
	.ascii	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delin"
	.ascii	"ker-extension/src/test/resources/programs/integer-p"
	.ascii	"arsing\000"
.LASF0:
	.ascii	"unsigned int\000"
.LASF17:
	.ascii	"parse_decimal\000"
.LASF15:
	.ascii	"puts\000"
.LASF3:
	.ascii	"long unsigned int\000"
.LASF12:
	.ascii	"GNU C17 12.2.0 -mfloat-abi=hard -mtls-dialect=gnu -"
	.ascii	"mthumb -march=armv7-a+fp -gdwarf-4 -gctf\000"
.LASF7:
	.ascii	"long long unsigned int\000"
.LASF13:
	.ascii	"src/main.c\000"
.LASF11:
	.ascii	"s_ascii_digit_bias\000"
.LASF1:
	.ascii	"unsigned char\000"
.LASF16:
	.ascii	"main\000"
.LASF19:
	.ascii	"void\000"
.LASF8:
	.ascii	"long int\000"
.LASF20:
	.ascii	"unknown\000"
.LASF2:
	.ascii	"short unsigned int\000"
.LASF4:
	.ascii	"signed char\000"
.LASF18:
	.ascii	"value\000"
.LASF5:
	.ascii	"short int\000"
.LASF10:
	.ascii	"s_digits\000"
.LASF9:
	.ascii	"char\000"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",%progbits
