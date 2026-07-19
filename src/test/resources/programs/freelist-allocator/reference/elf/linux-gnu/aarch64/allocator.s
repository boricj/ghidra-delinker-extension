	.arch armv8-a
	.file	"allocator.c"
	.section	.ctf,"",@progbits
.Lctf0:
	.2byte	0xdff2
	.byte	0x4
	.byte	0x2
	.4byte	0
	.4byte	0
	.4byte	0x144
	.4byte	0
	.4byte	0
	.4byte	0
	.4byte	0x30
	.4byte	0x30
	.4byte	0x60
	.4byte	0x60
	.4byte	0x284
	.4byte	0x1c4
	.4byte	0x13
	.4byte	0x12
	.4byte	0x14
	.4byte	0x1a
	.4byte	0x1b
	.4byte	0x19
	.4byte	0x1c
	.4byte	0x16
	.4byte	0x1f
	.4byte	0x11
	.4byte	0x1e
	.4byte	0x15
	.4byte	0xb0
	.4byte	0xa2
	.4byte	0xbf
	.4byte	0x105
	.4byte	0x111
	.4byte	0xf7
	.4byte	0x120
	.4byte	0xd9
	.4byte	0x13b
	.4byte	0x9b
	.4byte	0x12e
	.4byte	0xcd
	.4byte	0x1
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x1000040
	.4byte	0xa
	.4byte	0x2a000000
	.4byte	0x1
	.4byte	0x14
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x40
	.4byte	0x26
	.4byte	0x2a000000
	.4byte	0x3
	.4byte	0x2d
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x20
	.4byte	0x3a
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x1000040
	.4byte	0x48
	.4byte	0xa000000
	.4byte	0x10
	.4byte	0x6000080
	.4byte	0x54
	.4byte	0x1a000002
	.4byte	0x10
	.4byte	0x6e
	.4byte	0
	.4byte	0xa
	.4byte	0x73
	.4byte	0x40
	.4byte	0x2
	.4byte	0x61
	.4byte	0x2a000000
	.4byte	0x8
	.4byte	0
	.4byte	0xe000000
	.4byte	0x9
	.4byte	0
	.4byte	0x32000000
	.4byte	0x9
	.4byte	0x7a
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x10
	.4byte	0x8d
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x1000020
	.4byte	0x91
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0x96
	.4byte	0x6000000
	.4byte	0
	.4byte	0x1000000
	.4byte	0
	.4byte	0xe000000
	.4byte	0xf
	.4byte	0x9b
	.4byte	0x16000003
	.4byte	0x10
	.4byte	0x10
	.4byte	0xd
	.4byte	0x4
	.4byte	0
	.4byte	0xa2
	.4byte	0x16000002
	.4byte	0xf
	.4byte	0x10
	.4byte	0x10
	.4byte	0xb0
	.4byte	0x16000002
	.4byte	0x10
	.4byte	0x10
	.4byte	0x4
	.4byte	0xbf
	.4byte	0x16000002
	.4byte	0xf
	.4byte	0x10
	.4byte	0x4
	.4byte	0xcd
	.4byte	0x16000002
	.4byte	0xf
	.4byte	0xa
	.4byte	0x4
	.4byte	0xd9
	.4byte	0x16000001
	.4byte	0xa
	.4byte	0x10
	.4byte	0
	.4byte	0xe9
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0
	.4byte	0xe000000
	.4byte	0x17
	.4byte	0xf7
	.4byte	0x16000001
	.4byte	0x18
	.4byte	0xa
	.4byte	0
	.4byte	0x105
	.4byte	0x16000004
	.4byte	0xf
	.4byte	0xa
	.4byte	0xa
	.4byte	0x4
	.4byte	0xd
	.4byte	0x111
	.4byte	0x16000002
	.4byte	0xf
	.4byte	0xa
	.4byte	0xd
	.4byte	0x120
	.4byte	0x16000001
	.4byte	0xd
	.4byte	0x1d
	.4byte	0
	.4byte	0
	.4byte	0xe000000
	.4byte	0xb
	.4byte	0x12e
	.4byte	0x16000001
	.4byte	0x4
	.4byte	0x1d
	.4byte	0
	.4byte	0x13b
	.4byte	0x16000001
	.4byte	0x4
	.4byte	0x4
	.4byte	0
	.string	""
	.string	"long int"
	.string	"ptrdiff_t"
	.string	"long unsigned int"
	.string	"size_t"
	.string	"unsigned int"
	.string	"long long int"
	.string	"long double"
	.string	"chunk_header"
	.string	"chunk_header"
	.string	"next"
	.string	"length"
	.string	"short unsigned int"
	.string	"int"
	.string	"char"
	.string	"void"
	.string	"memset"
	.string	"freelist_free"
	.string	"freelist_alloc"
	.string	"freelist_init"
	.string	"chunk_split"
	.string	"chunk_from_data"
	.string	"unsigned char"
	.string	"chunk_to_data"
	.string	"chunk_write"
	.string	"chunk_set_used"
	.string	"chunk_is_used"
	.string	"chunk_length"
	.string	"align_up"
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/src/allocator.c"
	.text
.Ltext0:
	.file 1 "src/allocator.c"
	.align	2
	.type	align_up, %function
align_up:
.LFB0:
	.loc 1 5 38
	.cfi_startproc
	sub	sp, sp, #32
	.cfi_def_cfa_offset 32
	str	x0, [sp, 8]
	.loc 1 6 12
	mov	x0, 7
	str	x0, [sp, 24]
	.loc 1 7 19
	ldr	x1, [sp, 8]
	ldr	x0, [sp, 24]
	add	x1, x1, x0
	.loc 1 7 26
	ldr	x0, [sp, 24]
	mvn	x0, x0
	.loc 1 7 24
	and	x0, x1, x0
	.loc 1 8 1
	add	sp, sp, 32
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE0:
	.size	align_up, .-align_up
	.align	2
	.type	chunk_length, %function
chunk_length:
.LFB1:
	.loc 1 10 55
	.cfi_startproc
	sub	sp, sp, #16
	.cfi_def_cfa_offset 16
	str	x0, [sp, 8]
	.loc 1 11 47
	ldr	x0, [sp, 8]
	ldr	x0, [x0, 8]
	.loc 1 11 12
	cmp	x0, 0
	csneg	x0, x0, x0, ge
	.loc 1 12 1
	add	sp, sp, 16
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE1:
	.size	chunk_length, .-chunk_length
	.align	2
	.type	chunk_is_used, %function
chunk_is_used:
.LFB2:
	.loc 1 14 53
	.cfi_startproc
	sub	sp, sp, #16
	.cfi_def_cfa_offset 16
	str	x0, [sp, 8]
	.loc 1 15 17
	ldr	x0, [sp, 8]
	ldr	x0, [x0, 8]
	.loc 1 15 26
	lsr	x0, x0, 63
	and	w0, w0, 255
	.loc 1 16 1
	add	sp, sp, 16
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE2:
	.size	chunk_is_used, .-chunk_is_used
	.align	2
	.type	chunk_set_used, %function
chunk_set_used:
.LFB3:
	.loc 1 18 59
	.cfi_startproc
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	mov	x29, sp
	str	x0, [sp, 24]
	str	w1, [sp, 20]
	.loc 1 19 9
	ldr	x0, [sp, 24]
	bl	chunk_is_used
	mov	w1, w0
	.loc 1 19 8
	ldr	w0, [sp, 20]
	cmp	w0, w1
	beq	.L10
	.loc 1 23 27
	ldr	x0, [sp, 24]
	ldr	x0, [x0, 8]
	.loc 1 23 21
	neg	x1, x0
	.loc 1 23 19
	ldr	x0, [sp, 24]
	str	x1, [x0, 8]
	b	.L7
.L10:
	.loc 1 20 9
	nop
.L7:
	.loc 1 24 1
	ldp	x29, x30, [sp], 32
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE3:
	.size	chunk_set_used, .-chunk_set_used
	.align	2
	.type	chunk_write, %function
chunk_write:
.LFB4:
	.loc 1 26 91
	.cfi_startproc
	sub	sp, sp, #32
	.cfi_def_cfa_offset 32
	str	x0, [sp, 24]
	str	x1, [sp, 16]
	str	x2, [sp, 8]
	str	w3, [sp, 4]
	.loc 1 27 17
	ldr	x0, [sp, 24]
	ldr	x1, [sp, 16]
	str	x1, [x0]
	.loc 1 28 50
	ldr	w0, [sp, 4]
	cmp	w0, 0
	beq	.L12
	.loc 1 28 30 discriminator 1
	ldr	x0, [sp, 8]
	.loc 1 28 50 discriminator 1
	neg	x0, x0
	b	.L13
.L12:
	.loc 1 28 50 is_stmt 0 discriminator 2
	ldr	x0, [sp, 8]
.L13:
	.loc 1 28 19 is_stmt 1 discriminator 4
	ldr	x1, [sp, 24]
	str	x0, [x1, 8]
	.loc 1 29 1 discriminator 4
	nop
	add	sp, sp, 32
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE4:
	.size	chunk_write, .-chunk_write
	.align	2
	.type	chunk_to_data, %function
chunk_to_data:
.LFB5:
	.loc 1 31 58
	.cfi_startproc
	sub	sp, sp, #16
	.cfi_def_cfa_offset 16
	str	x0, [sp, 8]
	.loc 1 32 38
	ldr	x0, [sp, 8]
	add	x0, x0, 16
	.loc 1 33 1
	add	sp, sp, 16
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE5:
	.size	chunk_to_data, .-chunk_to_data
	.align	2
	.type	chunk_from_data, %function
chunk_from_data:
.LFB6:
	.loc 1 35 49
	.cfi_startproc
	sub	sp, sp, #16
	.cfi_def_cfa_offset 16
	str	x0, [sp, 8]
	.loc 1 36 12
	ldr	x0, [sp, 8]
	sub	x0, x0, #16
	.loc 1 37 1
	add	sp, sp, 16
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE6:
	.size	chunk_from_data, .-chunk_from_data
	.align	2
	.type	chunk_split, %function
chunk_split:
.LFB7:
	.loc 1 39 64
	.cfi_startproc
	stp	x29, x30, [sp, -48]!
	.cfi_def_cfa_offset 48
	.cfi_offset 29, -48
	.cfi_offset 30, -40
	mov	x29, sp
	str	x0, [sp, 24]
	str	x1, [sp, 16]
	.loc 1 40 19
	ldr	x1, [sp, 24]
	ldr	x0, [sp, 16]
	add	x0, x1, x0
	str	x0, [sp, 40]
	.loc 1 41 19
	ldr	x0, [sp, 24]
	bl	chunk_length
	mov	x1, x0
	.loc 1 41 9
	ldr	x0, [sp, 16]
	sub	x0, x1, x0
	str	x0, [sp, 32]
	.loc 1 44 5
	ldr	x0, [sp, 32]
	cmp	x0, 31
	bls	.L21
	.loc 1 48 5
	ldr	x0, [sp, 24]
	ldr	x0, [x0]
	mov	w3, 0
	ldr	x2, [sp, 32]
	mov	x1, x0
	ldr	x0, [sp, 40]
	bl	chunk_write
	.loc 1 49 5
	ldr	x0, [sp, 24]
	bl	chunk_is_used
	mov	w3, w0
	ldr	x2, [sp, 16]
	ldr	x1, [sp, 40]
	ldr	x0, [sp, 24]
	bl	chunk_write
	b	.L18
.L21:
	.loc 1 45 3
	nop
.L18:
	.loc 1 50 1
	ldp	x29, x30, [sp], 48
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE7:
	.size	chunk_split, .-chunk_split
	.align	2
	.global	freelist_init
	.type	freelist_init, %function
freelist_init:
.LFB8:
	.loc 1 52 50
	.cfi_startproc
	stp	x29, x30, [sp, -32]!
	.cfi_def_cfa_offset 32
	.cfi_offset 29, -32
	.cfi_offset 30, -24
	mov	x29, sp
	str	x0, [sp, 24]
	str	x1, [sp, 16]
	.loc 1 53 5
	mov	w3, 0
	ldr	x2, [sp, 16]
	mov	x1, 0
	ldr	x0, [sp, 24]
	bl	chunk_write
	.loc 1 54 1
	nop
	ldp	x29, x30, [sp], 32
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE8:
	.size	freelist_init, .-freelist_init
	.align	2
	.global	freelist_alloc
	.type	freelist_alloc, %function
freelist_alloc:
.LFB9:
	.loc 1 56 47
	.cfi_startproc
	stp	x29, x30, [sp, -48]!
	.cfi_def_cfa_offset 48
	.cfi_offset 29, -48
	.cfi_offset 30, -40
	mov	x29, sp
	str	x0, [sp, 24]
	str	x1, [sp, 16]
	.loc 1 57 47
	ldr	x0, [sp, 16]
	bl	align_up
	.loc 1 57 12
	add	x0, x0, 16
	str	x0, [sp, 40]
	.loc 1 60 8
	ldr	x0, [sp, 16]
	cmp	x0, 0
	bne	.L24
	.loc 1 61 16
	mov	x0, 0
	b	.L25
.L24:
	.loc 1 65 5
	ldr	x0, [sp, 40]
	cmp	x0, 31
	bhi	.L26
	.loc 1 66 13
	mov	x0, 32
	str	x0, [sp, 40]
.L26:
	.loc 1 70 14
	ldr	x0, [sp, 24]
	str	x0, [sp, 32]
	.loc 1 70 5
	b	.L27
.L29:
	.loc 1 71 14
	ldr	x0, [sp, 32]
	bl	chunk_is_used
	.loc 1 71 12
	cmp	w0, 0
	bne	.L28
	.loc 1 71 36 discriminator 1
	ldr	x0, [sp, 32]
	bl	chunk_length
	mov	x1, x0
	.loc 1 71 33 discriminator 1
	ldr	x0, [sp, 40]
	cmp	x0, x1
	bhi	.L28
	.loc 1 72 13
	ldr	x1, [sp, 40]
	ldr	x0, [sp, 32]
	bl	chunk_split
	.loc 1 73 13
	mov	w1, 1
	ldr	x0, [sp, 32]
	bl	chunk_set_used
	.loc 1 75 20
	ldr	x0, [sp, 32]
	bl	chunk_to_data
	b	.L25
.L28:
	.loc 1 70 56 discriminator 2
	ldr	x0, [sp, 32]
	ldr	x0, [x0]
	str	x0, [sp, 32]
.L27:
	.loc 1 70 43 discriminator 1
	ldr	x0, [sp, 32]
	cmp	x0, 0
	bne	.L29
	.loc 1 79 12
	mov	x0, 0
.L25:
	.loc 1 80 1
	ldp	x29, x30, [sp], 48
	.cfi_restore 30
	.cfi_restore 29
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE9:
	.size	freelist_alloc, .-freelist_alloc
	.align	2
	.global	freelist_free
	.type	freelist_free, %function
freelist_free:
.LFB10:
	.loc 1 82 43
	.cfi_startproc
	stp	x29, x30, [sp, -64]!
	.cfi_def_cfa_offset 64
	.cfi_offset 29, -64
	.cfi_offset 30, -56
	mov	x29, sp
	stp	x19, x20, [sp, 16]
	.cfi_offset 19, -48
	.cfi_offset 20, -40
	str	x0, [sp, 40]
	str	x1, [sp, 32]
	.loc 1 85 8
	ldr	x0, [sp, 32]
	cmp	x0, 0
	beq	.L36
	.loc 1 90 13
	ldr	x0, [sp, 32]
	bl	chunk_from_data
	str	x0, [sp, 56]
	.loc 1 91 5
	mov	w1, 0
	ldr	x0, [sp, 56]
	bl	chunk_set_used
	.loc 1 92 20
	ldr	x0, [sp, 56]
	bl	chunk_length
	.loc 1 92 5
	sub	x0, x0, #16
	mov	x2, x0
	mov	w1, 0
	ldr	x0, [sp, 32]
	bl	memset
	.loc 1 95 11
	ldr	x0, [sp, 40]
	str	x0, [sp, 56]
	.loc 1 96 11
	b	.L33
.L35:
	.loc 1 97 14
	ldr	x0, [sp, 56]
	bl	chunk_is_used
	.loc 1 97 12
	cmp	w0, 0
	bne	.L34
	.loc 1 97 58 discriminator 1
	ldr	x0, [sp, 56]
	ldr	x0, [x0]
	.loc 1 97 39 discriminator 1
	bl	chunk_is_used
	.loc 1 97 35 discriminator 1
	cmp	w0, 0
	bne	.L34
.LBB2:
	.loc 1 98 19
	ldr	x0, [sp, 56]
	ldr	x0, [x0]
	str	x0, [sp, 48]
	.loc 1 100 37
	ldr	x0, [sp, 56]
	ldr	x0, [x0]
	.loc 1 100 13
	ldr	x19, [x0]
	.loc 1 100 51
	ldr	x0, [sp, 56]
	bl	chunk_length
	mov	x20, x0
	.loc 1 100 91
	ldr	x0, [sp, 56]
	ldr	x0, [x0]
	.loc 1 100 73
	bl	chunk_length
	.loc 1 100 13
	add	x0, x20, x0
	mov	w3, 0
	mov	x2, x0
	mov	x1, x19
	ldr	x0, [sp, 56]
	bl	chunk_write
	.loc 1 101 13
	mov	x2, 16
	mov	w1, 0
	ldr	x0, [sp, 48]
	bl	memset
.LBE2:
	.loc 1 97 67
	b	.L33
.L34:
	.loc 1 103 19
	ldr	x0, [sp, 56]
	ldr	x0, [x0]
	str	x0, [sp, 56]
.L33:
	.loc 1 96 26
	ldr	x0, [sp, 56]
	cmp	x0, 0
	beq	.L30
	.loc 1 96 34 discriminator 1
	ldr	x0, [sp, 56]
	ldr	x0, [x0]
	.loc 1 96 26 discriminator 1
	cmp	x0, 0
	bne	.L35
	b	.L30
.L36:
	.loc 1 86 9
	nop
.L30:
	.loc 1 106 1
	ldp	x19, x20, [sp, 16]
	ldp	x29, x30, [sp], 64
	.cfi_restore 30
	.cfi_restore 29
	.cfi_restore 19
	.cfi_restore 20
	.cfi_def_cfa_offset 0
	ret
	.cfi_endproc
.LFE10:
	.size	freelist_free, .-freelist_free
.Letext0:
	.file 2 "/usr/lib/gcc-cross/aarch64-linux-gnu/12/include/stddef.h"
	.file 3 "/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/include/allocator.h"
	.file 4 "/usr/aarch64-linux-gnu/include/string.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x3ed
	.2byte	0x4
	.4byte	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.4byte	.LASF33
	.byte	0xc
	.4byte	.LASF34
	.4byte	.LASF35
	.8byte	.Ltext0
	.8byte	.Letext0-.Ltext0
	.4byte	.Ldebug_line0
	.uleb128 0x2
	.4byte	.LASF0
	.byte	0x2
	.byte	0x91
	.byte	0x1a
	.4byte	0x39
	.uleb128 0x3
	.byte	0x8
	.byte	0x5
	.4byte	.LASF2
	.uleb128 0x2
	.4byte	.LASF1
	.byte	0x2
	.byte	0xd6
	.byte	0x17
	.4byte	0x4c
	.uleb128 0x3
	.byte	0x8
	.byte	0x7
	.4byte	.LASF3
	.uleb128 0x3
	.byte	0x4
	.byte	0x7
	.4byte	.LASF4
	.uleb128 0x3
	.byte	0x8
	.byte	0x5
	.4byte	.LASF5
	.uleb128 0x3
	.byte	0x10
	.byte	0x4
	.4byte	.LASF6
	.uleb128 0x2
	.4byte	.LASF7
	.byte	0x3
	.byte	0x9
	.byte	0x1d
	.4byte	0x79
	.uleb128 0x4
	.4byte	0x68
	.uleb128 0x5
	.4byte	.LASF7
	.byte	0x10
	.byte	0x3
	.byte	0xb
	.byte	0x8
	.4byte	0xa1
	.uleb128 0x6
	.4byte	.LASF8
	.byte	0x3
	.byte	0xc
	.byte	0x13
	.4byte	0xa1
	.byte	0
	.uleb128 0x6
	.4byte	.LASF9
	.byte	0x3
	.byte	0xd
	.byte	0xf
	.4byte	0x2d
	.byte	0x8
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.4byte	0x68
	.uleb128 0x3
	.byte	0x2
	.byte	0x7
	.4byte	.LASF10
	.uleb128 0x8
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x3
	.byte	0x1
	.byte	0x8
	.4byte	.LASF11
	.uleb128 0x9
	.4byte	.LASF36
	.byte	0x4
	.byte	0x3d
	.byte	0xe
	.4byte	0xdc
	.4byte	0xdc
	.uleb128 0xa
	.4byte	0xdc
	.uleb128 0xa
	.4byte	0xae
	.uleb128 0xa
	.4byte	0x40
	.byte	0
	.uleb128 0xb
	.byte	0x8
	.uleb128 0xc
	.4byte	.LASF17
	.byte	0x1
	.byte	0x52
	.byte	0x6
	.8byte	.LFB10
	.8byte	.LFE10-.LFB10
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x14b
	.uleb128 0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x52
	.byte	0x1a
	.4byte	0xdc
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x52
	.byte	0x26
	.4byte	0xdc
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0xf
	.4byte	.LASF13
	.byte	0x1
	.byte	0x53
	.byte	0x13
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.uleb128 0x10
	.8byte	.LBB2
	.8byte	.LBE2-.LBB2
	.uleb128 0xf
	.4byte	.LASF14
	.byte	0x1
	.byte	0x62
	.byte	0x13
	.4byte	0xdc
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.byte	0
	.uleb128 0x11
	.4byte	.LASF37
	.byte	0x1
	.byte	0x38
	.byte	0x7
	.4byte	0xdc
	.8byte	.LFB9
	.8byte	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x1aa
	.uleb128 0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x38
	.byte	0x1c
	.4byte	0xdc
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xd
	.4byte	.LASF15
	.byte	0x1
	.byte	0x38
	.byte	0x29
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0xf
	.4byte	.LASF16
	.byte	0x1
	.byte	0x39
	.byte	0xc
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.uleb128 0x12
	.string	"cur"
	.byte	0x1
	.byte	0x3a
	.byte	0x13
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0xc
	.4byte	.LASF18
	.byte	0x1
	.byte	0x34
	.byte	0x6
	.8byte	.LFB8
	.8byte	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x1e7
	.uleb128 0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x34
	.byte	0x1a
	.4byte	0xdc
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.uleb128 0xd
	.4byte	.LASF19
	.byte	0x1
	.byte	0x34
	.byte	0x27
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0x13
	.4byte	.LASF25
	.byte	0x1
	.byte	0x27
	.byte	0xd
	.8byte	.LFB7
	.8byte	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x242
	.uleb128 0xd
	.4byte	.LASF13
	.byte	0x1
	.byte	0x27
	.byte	0x27
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xd
	.4byte	.LASF16
	.byte	0x1
	.byte	0x27
	.byte	0x35
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0xf
	.4byte	.LASF20
	.byte	0x1
	.byte	0x28
	.byte	0x13
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.uleb128 0xf
	.4byte	.LASF21
	.byte	0x1
	.byte	0x29
	.byte	0x9
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0x14
	.4byte	.LASF22
	.byte	0x1
	.byte	0x23
	.byte	0x16
	.4byte	0xa1
	.8byte	.LFB6
	.8byte	.LFE6-.LFB6
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x274
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x23
	.byte	0x2c
	.4byte	0xdc
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x14
	.4byte	.LASF23
	.byte	0x1
	.byte	0x1f
	.byte	0x17
	.4byte	0x2a6
	.8byte	.LFB5
	.8byte	.LFE5-.LFB5
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x2a6
	.uleb128 0xd
	.4byte	.LASF13
	.byte	0x1
	.byte	0x1f
	.byte	0x33
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.4byte	0x2ac
	.uleb128 0x3
	.byte	0x1
	.byte	0x8
	.4byte	.LASF24
	.uleb128 0x15
	.4byte	.LASF26
	.byte	0x1
	.byte	0x1a
	.byte	0xd
	.8byte	.LFB4
	.8byte	.LFE4-.LFB4
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x30e
	.uleb128 0xd
	.4byte	.LASF13
	.byte	0x1
	.byte	0x1a
	.byte	0x27
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.uleb128 0xd
	.4byte	.LASF8
	.byte	0x1
	.byte	0x1a
	.byte	0x3c
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0xd
	.4byte	.LASF9
	.byte	0x1
	.byte	0x1a
	.byte	0x49
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xd
	.4byte	.LASF27
	.byte	0x1
	.byte	0x1a
	.byte	0x55
	.4byte	0xae
	.uleb128 0x2
	.byte	0x91
	.sleb128 -28
	.byte	0
	.uleb128 0x13
	.4byte	.LASF28
	.byte	0x1
	.byte	0x12
	.byte	0xd
	.8byte	.LFB3
	.8byte	.LFE3-.LFB3
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x34b
	.uleb128 0xd
	.4byte	.LASF13
	.byte	0x1
	.byte	0x12
	.byte	0x2a
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.uleb128 0xd
	.4byte	.LASF27
	.byte	0x1
	.byte	0x12
	.byte	0x35
	.4byte	0xae
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.byte	0
	.uleb128 0x14
	.4byte	.LASF29
	.byte	0x1
	.byte	0xe
	.byte	0xc
	.4byte	0xae
	.8byte	.LFB2
	.8byte	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x37d
	.uleb128 0xd
	.4byte	.LASF13
	.byte	0x1
	.byte	0xe
	.byte	0x2e
	.4byte	0x37d
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x7
	.byte	0x8
	.4byte	0x74
	.uleb128 0x14
	.4byte	.LASF30
	.byte	0x1
	.byte	0xa
	.byte	0xf
	.4byte	0x40
	.8byte	.LFB1
	.8byte	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x3b5
	.uleb128 0xd
	.4byte	.LASF13
	.byte	0x1
	.byte	0xa
	.byte	0x30
	.4byte	0x37d
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x16
	.4byte	.LASF31
	.byte	0x1
	.byte	0x5
	.byte	0xf
	.4byte	0x40
	.8byte	.LFB0
	.8byte	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.4byte	.LASF32
	.byte	0x1
	.byte	0x5
	.byte	0x1f
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0x12
	.string	"m"
	.byte	0x1
	.byte	0x6
	.byte	0xc
	.4byte	0x40
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
	.uleb128 0x7
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x16
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
	.uleb128 0xe
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
	.uleb128 0x13
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0xd
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
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
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
	.uleb128 0x9
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
	.uleb128 0x3c
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
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
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2116
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x5
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
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.byte	0
	.byte	0
	.uleb128 0x11
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
	.uleb128 0x2116
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x12
	.uleb128 0x34
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
	.uleb128 0x13
	.uleb128 0x2e
	.byte	0x1
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
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2116
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x14
	.uleb128 0x2e
	.byte	0x1
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
	.uleb128 0x15
	.uleb128 0x2e
	.byte	0x1
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
	.uleb128 0x16
	.uleb128 0x2e
	.byte	0x1
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
.LASF19:
	.string	"heap_size"
.LASF1:
	.string	"size_t"
.LASF8:
	.string	"next"
.LASF32:
	.string	"value"
.LASF16:
	.string	"requested"
.LASF37:
	.string	"freelist_alloc"
.LASF17:
	.string	"freelist_free"
.LASF23:
	.string	"chunk_to_data"
.LASF28:
	.string	"chunk_set_used"
.LASF15:
	.string	"size"
.LASF3:
	.string	"long unsigned int"
.LASF30:
	.string	"chunk_length"
.LASF10:
	.string	"short unsigned int"
.LASF33:
	.string	"GNU C17 12.2.0 -mlittle-endian -mabi=lp64 -gdwarf-4 -gctf -fasynchronous-unwind-tables"
.LASF20:
	.string	"new_chunk"
.LASF14:
	.string	"old_next"
.LASF7:
	.string	"chunk_header"
.LASF36:
	.string	"memset"
.LASF29:
	.string	"chunk_is_used"
.LASF0:
	.string	"ptrdiff_t"
.LASF21:
	.string	"new_len"
.LASF13:
	.string	"chunk"
.LASF24:
	.string	"unsigned char"
.LASF4:
	.string	"unsigned int"
.LASF11:
	.string	"char"
.LASF12:
	.string	"heap"
.LASF38:
	.string	"void"
.LASF5:
	.string	"long long int"
.LASF35:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator"
.LASF18:
	.string	"freelist_init"
.LASF39:
	.string	"unknown"
.LASF22:
	.string	"chunk_from_data"
.LASF27:
	.string	"used"
.LASF25:
	.string	"chunk_split"
.LASF34:
	.string	"src/allocator.c"
.LASF26:
	.string	"chunk_write"
.LASF2:
	.string	"long int"
.LASF31:
	.string	"align_up"
.LASF6:
	.string	"long double"
.LASF9:
	.string	"length"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
