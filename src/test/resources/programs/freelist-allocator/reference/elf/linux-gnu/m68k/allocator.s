#NO_APP
	.file	"allocator.c"
	.section	.ctf,"",@progbits
.Lctf0:
	.word	0xdff2
	.byte	0x4
	.byte	0x2
	.long	0
	.long	0
	.long	0x132
	.long	0
	.long	0
	.long	0
	.long	0x30
	.long	0x30
	.long	0x60
	.long	0x60
	.long	0x274
	.long	0x1b2
	.long	0x1a
	.long	0x14
	.long	0x1b
	.long	0x13
	.long	0x10
	.long	0x12
	.long	0x11
	.long	0x15
	.long	0x18
	.long	0x1e
	.long	0x19
	.long	0x1d
	.long	0xff
	.long	0xbb
	.long	0x10e
	.long	0xad
	.long	0x89
	.long	0x9e
	.long	0x90
	.long	0xc7
	.long	0xe5
	.long	0x129
	.long	0xf3
	.long	0x11c
	.long	0x1
	.long	0x6000000
	.long	0x4
	.long	0x1000020
	.long	0x5
	.long	0x2a000000
	.long	0x1
	.long	0xf
	.long	0x6000000
	.long	0x4
	.long	0x20
	.long	0x1c
	.long	0x2a000000
	.long	0x3
	.long	0x23
	.long	0x6000000
	.long	0x4
	.long	0x1000020
	.long	0x2c
	.long	0x6000000
	.long	0x8
	.long	0x1000040
	.long	0x3a
	.long	0xa000000
	.long	0x10
	.long	0x6000060
	.long	0x46
	.long	0x1a000002
	.long	0x8
	.long	0x60
	.long	0
	.long	0xa
	.long	0x65
	.long	0x20
	.long	0x2
	.long	0x53
	.long	0x2a000000
	.long	0x8
	.long	0
	.long	0xe000000
	.long	0x9
	.long	0
	.long	0x32000000
	.long	0x9
	.long	0x6c
	.long	0x6000000
	.long	0x2
	.long	0x10
	.long	0x7f
	.long	0x6000000
	.long	0x1
	.long	0x3000008
	.long	0x84
	.long	0x6000000
	.long	0
	.long	0x1000000
	.long	0
	.long	0xe000000
	.long	0xe
	.long	0x89
	.long	0x16000003
	.long	0xf
	.long	0xf
	.long	0x1
	.long	0x4
	.long	0
	.long	0x90
	.long	0x16000002
	.long	0xe
	.long	0xf
	.long	0xf
	.long	0x9e
	.long	0x16000002
	.long	0xf
	.long	0xf
	.long	0x4
	.long	0xad
	.long	0x16000002
	.long	0xe
	.long	0xf
	.long	0x4
	.long	0xbb
	.long	0x16000002
	.long	0xe
	.long	0xa
	.long	0x4
	.long	0xc7
	.long	0x16000001
	.long	0xa
	.long	0xf
	.long	0
	.long	0xd7
	.long	0x6000000
	.long	0x1
	.long	0x2000008
	.long	0
	.long	0xe000000
	.long	0x16
	.long	0xe5
	.long	0x16000001
	.long	0x17
	.long	0xa
	.long	0
	.long	0xf3
	.long	0x16000004
	.long	0xe
	.long	0xa
	.long	0xa
	.long	0x4
	.long	0x1
	.long	0xff
	.long	0x16000002
	.long	0xe
	.long	0xa
	.long	0x1
	.long	0x10e
	.long	0x16000001
	.long	0x1
	.long	0x1c
	.long	0
	.long	0
	.long	0xe000000
	.long	0xb
	.long	0x11c
	.long	0x16000001
	.long	0x4
	.long	0x1c
	.long	0
	.long	0x129
	.long	0x16000001
	.long	0x4
	.long	0x4
	.long	0
	.string	""
	.string	"int"
	.string	"ptrdiff_t"
	.string	"unsigned int"
	.string	"size_t"
	.string	"long int"
	.string	"long long int"
	.string	"long double"
	.string	"chunk_header"
	.string	"chunk_header"
	.string	"next"
	.string	"length"
	.string	"short unsigned int"
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
	.cfi_sections	.debug_frame
	.file 1 "src/allocator.c"
	.align	2
	.type	align_up, @function
align_up:
.LFB0:
	.loc 1 5 38
	.cfi_startproc
	link.w %fp,#-4
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 6 12
	moveq #3,%d0
	move.l %d0,-4(%fp)
	.loc 1 7 19
	move.l 8(%fp),%d0
	add.l -4(%fp),%d0
	.loc 1 7 26
	move.l -4(%fp),%d1
	not.l %d1
	.loc 1 7 24
	and.l %d1,%d0
	.loc 1 8 1
	unlk %fp
	rts
	.cfi_endproc
.LFE0:
	.size	align_up, .-align_up
	.align	2
	.type	chunk_length, @function
chunk_length:
.LFB1:
	.loc 1 10 55
	.cfi_startproc
	link.w %fp,#0
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 11 47
	move.l 8(%fp),%a0
	move.l 4(%a0),%d0
	.loc 1 11 12
	jpl .L4
	neg.l %d0
.L4:
	.loc 1 12 1
	unlk %fp
	rts
	.cfi_endproc
.LFE1:
	.size	chunk_length, .-chunk_length
	.align	2
	.type	chunk_is_used, @function
chunk_is_used:
.LFB2:
	.loc 1 14 53
	.cfi_startproc
	link.w %fp,#0
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 15 17
	move.l 8(%fp),%a0
	move.l 4(%a0),%d0
	.loc 1 15 26
	add.l %d0,%d0
	subx.l %d0,%d0
	neg.l %d0
	move.b %d0,%d0
	move.b %d0,%d0
	and.l #255,%d0
	.loc 1 16 1
	unlk %fp
	rts
	.cfi_endproc
.LFE2:
	.size	chunk_is_used, .-chunk_is_used
	.align	2
	.type	chunk_set_used, @function
chunk_set_used:
.LFB3:
	.loc 1 18 59
	.cfi_startproc
	link.w %fp,#0
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 19 9
	move.l 8(%fp),-(%sp)
	jsr chunk_is_used
	addq.l #4,%sp
	.loc 1 19 8
	cmp.l 12(%fp),%d0
	jeq .L11
	.loc 1 23 27
	move.l 8(%fp),%a0
	move.l 4(%a0),%d0
	.loc 1 23 21
	neg.l %d0
	.loc 1 23 19
	move.l 8(%fp),%a0
	move.l %d0,4(%a0)
	jra .L8
.L11:
	.loc 1 20 9
	nop
.L8:
	.loc 1 24 1
	unlk %fp
	rts
	.cfi_endproc
.LFE3:
	.size	chunk_set_used, .-chunk_set_used
	.align	2
	.type	chunk_write, @function
chunk_write:
.LFB4:
	.loc 1 26 91
	.cfi_startproc
	link.w %fp,#0
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 27 17
	move.l 8(%fp),%a0
	move.l 12(%fp),(%a0)
	.loc 1 28 50
	tst.l 20(%fp)
	jeq .L13
	.loc 1 28 30 discriminator 1
	move.l 16(%fp),%d0
	.loc 1 28 50 discriminator 1
	neg.l %d0
	jra .L14
.L13:
	.loc 1 28 50 is_stmt 0 discriminator 2
	move.l 16(%fp),%d0
.L14:
	.loc 1 28 19 is_stmt 1 discriminator 4
	move.l 8(%fp),%a0
	move.l %d0,4(%a0)
	.loc 1 29 1 discriminator 4
	nop
	unlk %fp
	rts
	.cfi_endproc
.LFE4:
	.size	chunk_write, .-chunk_write
	.align	2
	.type	chunk_to_data, @function
chunk_to_data:
.LFB5:
	.loc 1 31 58
	.cfi_startproc
	link.w %fp,#0
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 32 38
	move.l 8(%fp),%d0
	addq.l #8,%d0
	move.l %d0,%d1
	.loc 1 33 1
	move.l %d1,%a0
	unlk %fp
	rts
	.cfi_endproc
.LFE5:
	.size	chunk_to_data, .-chunk_to_data
	.align	2
	.type	chunk_from_data, @function
chunk_from_data:
.LFB6:
	.loc 1 35 49
	.cfi_startproc
	link.w %fp,#0
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 36 12
	move.l 8(%fp),%d0
	subq.l #8,%d0
	move.l %d0,%d1
	.loc 1 37 1
	move.l %d1,%a0
	unlk %fp
	rts
	.cfi_endproc
.LFE6:
	.size	chunk_from_data, .-chunk_from_data
	.align	2
	.type	chunk_split, @function
chunk_split:
.LFB7:
	.loc 1 39 64
	.cfi_startproc
	link.w %fp,#-8
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 40 19
	move.l 8(%fp),%d0
	add.l 12(%fp),%d0
	move.l %d0,-4(%fp)
	.loc 1 41 19
	move.l 8(%fp),-(%sp)
	jsr chunk_length
	addq.l #4,%sp
	.loc 1 41 9
	move.l %d0,%d1
	sub.l 12(%fp),%d1
	move.l %d1,-8(%fp)
	.loc 1 44 5
	moveq #15,%d0
	cmp.l -8(%fp),%d0
	jcc .L22
	.loc 1 48 5
	move.l 8(%fp),%a0
	move.l (%a0),%d0
	clr.l -(%sp)
	move.l -8(%fp),-(%sp)
	move.l %d0,-(%sp)
	move.l -4(%fp),-(%sp)
	jsr chunk_write
	lea (16,%sp),%sp
	.loc 1 49 5
	move.l 8(%fp),-(%sp)
	jsr chunk_is_used
	addq.l #4,%sp
	move.l %d0,-(%sp)
	move.l 12(%fp),-(%sp)
	move.l -4(%fp),-(%sp)
	move.l 8(%fp),-(%sp)
	jsr chunk_write
	lea (16,%sp),%sp
	jra .L19
.L22:
	.loc 1 45 3
	nop
.L19:
	.loc 1 50 1
	unlk %fp
	rts
	.cfi_endproc
.LFE7:
	.size	chunk_split, .-chunk_split
	.align	2
	.globl	freelist_init
	.type	freelist_init, @function
freelist_init:
.LFB8:
	.loc 1 52 50
	.cfi_startproc
	link.w %fp,#0
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 53 5
	clr.l -(%sp)
	move.l 12(%fp),-(%sp)
	clr.l -(%sp)
	move.l 8(%fp),-(%sp)
	jsr chunk_write
	lea (16,%sp),%sp
	.loc 1 54 1
	nop
	unlk %fp
	rts
	.cfi_endproc
.LFE8:
	.size	freelist_init, .-freelist_init
	.align	2
	.globl	freelist_alloc
	.type	freelist_alloc, @function
freelist_alloc:
.LFB9:
	.loc 1 56 47
	.cfi_startproc
	link.w %fp,#-8
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	.loc 1 57 47
	move.l 12(%fp),-(%sp)
	jsr align_up
	addq.l #4,%sp
	.loc 1 57 12
	move.l %d0,%d1
	addq.l #8,%d1
	move.l %d1,-4(%fp)
	.loc 1 60 8
	tst.l 12(%fp)
	jne .L25
	.loc 1 61 16
	clr.l %d0
	jra .L26
.L25:
	.loc 1 65 5
	moveq #15,%d0
	cmp.l -4(%fp),%d0
	jcs .L27
	.loc 1 66 13
	moveq #16,%d1
	move.l %d1,-4(%fp)
.L27:
	.loc 1 70 14
	move.l 8(%fp),-8(%fp)
	.loc 1 70 5
	jra .L28
.L30:
	.loc 1 71 14
	move.l -8(%fp),-(%sp)
	jsr chunk_is_used
	addq.l #4,%sp
	.loc 1 71 12
	tst.l %d0
	jne .L29
	.loc 1 71 36 discriminator 1
	move.l -8(%fp),-(%sp)
	jsr chunk_length
	addq.l #4,%sp
	.loc 1 71 33 discriminator 1
	cmp.l -4(%fp),%d0
	jcs .L29
	.loc 1 72 13
	move.l -4(%fp),-(%sp)
	move.l -8(%fp),-(%sp)
	jsr chunk_split
	addq.l #8,%sp
	.loc 1 73 13
	pea 1.w
	move.l -8(%fp),-(%sp)
	jsr chunk_set_used
	addq.l #8,%sp
	.loc 1 75 20
	move.l -8(%fp),-(%sp)
	jsr chunk_to_data
	addq.l #4,%sp
	move.l %a0,%d0
	jra .L26
.L29:
	.loc 1 70 56 discriminator 2
	move.l -8(%fp),%a0
	move.l (%a0),-8(%fp)
.L28:
	.loc 1 70 43 discriminator 1
	tst.l -8(%fp)
	jne .L30
	.loc 1 79 12
	clr.l %d0
.L26:
	.loc 1 80 1
	move.l %d0,%d1
	move.l %d1,%a0
	unlk %fp
	rts
	.cfi_endproc
.LFE9:
	.size	freelist_alloc, .-freelist_alloc
	.align	2
	.globl	freelist_free
	.type	freelist_free, @function
freelist_free:
.LFB10:
	.loc 1 82 43
	.cfi_startproc
	link.w %fp,#-8
	.cfi_offset 14, -8
	.cfi_def_cfa 14, 8
	move.l %d2,-(%sp)
	.cfi_offset 2, -20
	.loc 1 85 8
	tst.l 12(%fp)
	jeq .L37
	.loc 1 90 13
	move.l 12(%fp),-(%sp)
	jsr chunk_from_data
	addq.l #4,%sp
	move.l %a0,-4(%fp)
	.loc 1 91 5
	clr.l -(%sp)
	move.l -4(%fp),-(%sp)
	jsr chunk_set_used
	addq.l #8,%sp
	.loc 1 92 20
	move.l -4(%fp),-(%sp)
	jsr chunk_length
	addq.l #4,%sp
	.loc 1 92 5
	subq.l #8,%d0
	move.l %d0,-(%sp)
	clr.l -(%sp)
	move.l 12(%fp),-(%sp)
	jsr memset
	lea (12,%sp),%sp
	.loc 1 95 11
	move.l 8(%fp),-4(%fp)
	.loc 1 96 11
	jra .L34
.L36:
	.loc 1 97 14
	move.l -4(%fp),-(%sp)
	jsr chunk_is_used
	addq.l #4,%sp
	.loc 1 97 12
	tst.l %d0
	jne .L35
	.loc 1 97 58 discriminator 1
	move.l -4(%fp),%a0
	move.l (%a0),%d0
	.loc 1 97 39 discriminator 1
	move.l %d0,-(%sp)
	jsr chunk_is_used
	addq.l #4,%sp
	.loc 1 97 35 discriminator 1
	tst.l %d0
	jne .L35
.LBB2:
	.loc 1 98 19
	move.l -4(%fp),%a0
	move.l (%a0),-8(%fp)
	.loc 1 100 51
	move.l -4(%fp),-(%sp)
	jsr chunk_length
	addq.l #4,%sp
	move.l %d0,%d2
	.loc 1 100 91
	move.l -4(%fp),%a0
	move.l (%a0),%d0
	.loc 1 100 73
	move.l %d0,-(%sp)
	jsr chunk_length
	addq.l #4,%sp
	.loc 1 100 13
	move.l %d2,%d1
	add.l %d0,%d1
	.loc 1 100 37
	move.l -4(%fp),%a0
	move.l (%a0),%a0
	.loc 1 100 13
	move.l (%a0),%d0
	clr.l -(%sp)
	move.l %d1,-(%sp)
	move.l %d0,-(%sp)
	move.l -4(%fp),-(%sp)
	jsr chunk_write
	lea (16,%sp),%sp
	.loc 1 101 13
	pea 8.w
	clr.l -(%sp)
	move.l -8(%fp),-(%sp)
	jsr memset
	lea (12,%sp),%sp
.LBE2:
	.loc 1 97 67
	jra .L34
.L35:
	.loc 1 103 19
	move.l -4(%fp),%a0
	move.l (%a0),-4(%fp)
.L34:
	.loc 1 96 26
	tst.l -4(%fp)
	jeq .L31
	.loc 1 96 34 discriminator 1
	move.l -4(%fp),%a0
	move.l (%a0),%d0
	.loc 1 96 26 discriminator 1
	jne .L36
	jra .L31
.L37:
	.loc 1 86 9
	nop
.L31:
	.loc 1 106 1
	move.l -12(%fp),%d2
	unlk %fp
	rts
	.cfi_endproc
.LFE10:
	.size	freelist_free, .-freelist_free
.Letext0:
	.file 2 "/usr/lib/gcc-cross/m68k-linux-gnu/12/include/stddef.h"
	.file 3 "/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/include/allocator.h"
	.file 4 "/usr/m68k-linux-gnu/include/string.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x37e
	.word	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF32
	.byte	0xc
	.long	.LASF33
	.long	.LASF34
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.long	.LASF0
	.byte	0x2
	.byte	0x91
	.byte	0x1a
	.long	0x31
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x2
	.long	.LASF1
	.byte	0x2
	.byte	0xd6
	.byte	0x17
	.long	0x44
	.uleb128 0x4
	.byte	0x4
	.byte	0x7
	.long	.LASF2
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.long	.LASF3
	.uleb128 0x4
	.byte	0x8
	.byte	0x5
	.long	.LASF4
	.uleb128 0x4
	.byte	0xc
	.byte	0x4
	.long	.LASF5
	.uleb128 0x2
	.long	.LASF6
	.byte	0x3
	.byte	0x9
	.byte	0x1d
	.long	0x71
	.uleb128 0x5
	.long	0x60
	.uleb128 0x6
	.long	.LASF6
	.byte	0x8
	.byte	0x3
	.byte	0xb
	.byte	0x8
	.long	0x99
	.uleb128 0x7
	.long	.LASF7
	.byte	0x3
	.byte	0xc
	.byte	0x13
	.long	0x99
	.byte	0
	.uleb128 0x7
	.long	.LASF8
	.byte	0x3
	.byte	0xd
	.byte	0xf
	.long	0x25
	.byte	0x4
	.byte	0
	.uleb128 0x8
	.byte	0x4
	.long	0x60
	.uleb128 0x4
	.byte	0x2
	.byte	0x7
	.long	.LASF9
	.uleb128 0x4
	.byte	0x1
	.byte	0x6
	.long	.LASF10
	.uleb128 0x9
	.long	.LASF35
	.byte	0x4
	.byte	0x3d
	.byte	0xe
	.long	0xcd
	.long	0xcd
	.uleb128 0xa
	.long	0xcd
	.uleb128 0xa
	.long	0x31
	.uleb128 0xa
	.long	0x38
	.byte	0
	.uleb128 0xb
	.byte	0x4
	.uleb128 0xc
	.long	.LASF16
	.byte	0x1
	.byte	0x52
	.byte	0x6
	.long	.LFB10
	.long	.LFE10-.LFB10
	.uleb128 0x1
	.byte	0x9c
	.long	0x12c
	.uleb128 0xd
	.long	.LASF11
	.byte	0x1
	.byte	0x52
	.byte	0x1a
	.long	0xcd
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x52
	.byte	0x26
	.long	0xcd
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0xf
	.long	.LASF12
	.byte	0x1
	.byte	0x53
	.byte	0x13
	.long	0x99
	.uleb128 0x2
	.byte	0x7e
	.sleb128 -4
	.uleb128 0x10
	.long	.LBB2
	.long	.LBE2-.LBB2
	.uleb128 0xf
	.long	.LASF13
	.byte	0x1
	.byte	0x62
	.byte	0x13
	.long	0xcd
	.uleb128 0x2
	.byte	0x7e
	.sleb128 -8
	.byte	0
	.byte	0
	.uleb128 0x11
	.long	.LASF36
	.byte	0x1
	.byte	0x38
	.byte	0x7
	.long	0xcd
	.long	.LFB9
	.long	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.long	0x183
	.uleb128 0xd
	.long	.LASF11
	.byte	0x1
	.byte	0x38
	.byte	0x1c
	.long	0xcd
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF14
	.byte	0x1
	.byte	0x38
	.byte	0x29
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0xf
	.long	.LASF15
	.byte	0x1
	.byte	0x39
	.byte	0xc
	.long	0x38
	.uleb128 0x2
	.byte	0x7e
	.sleb128 -4
	.uleb128 0x12
	.string	"cur"
	.byte	0x1
	.byte	0x3a
	.byte	0x13
	.long	0x99
	.uleb128 0x2
	.byte	0x7e
	.sleb128 -8
	.byte	0
	.uleb128 0xc
	.long	.LASF17
	.byte	0x1
	.byte	0x34
	.byte	0x6
	.long	.LFB8
	.long	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.long	0x1b8
	.uleb128 0xd
	.long	.LASF11
	.byte	0x1
	.byte	0x34
	.byte	0x1a
	.long	0xcd
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF18
	.byte	0x1
	.byte	0x34
	.byte	0x27
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.byte	0
	.uleb128 0x13
	.long	.LASF24
	.byte	0x1
	.byte	0x27
	.byte	0xd
	.long	.LFB7
	.long	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.long	0x20b
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x27
	.byte	0x27
	.long	0x99
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF15
	.byte	0x1
	.byte	0x27
	.byte	0x35
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0xf
	.long	.LASF19
	.byte	0x1
	.byte	0x28
	.byte	0x13
	.long	0x99
	.uleb128 0x2
	.byte	0x7e
	.sleb128 -4
	.uleb128 0xf
	.long	.LASF20
	.byte	0x1
	.byte	0x29
	.byte	0x9
	.long	0x38
	.uleb128 0x2
	.byte	0x7e
	.sleb128 -8
	.byte	0
	.uleb128 0x14
	.long	.LASF21
	.byte	0x1
	.byte	0x23
	.byte	0x16
	.long	0x99
	.long	.LFB6
	.long	.LFE6-.LFB6
	.uleb128 0x1
	.byte	0x9c
	.long	0x235
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x23
	.byte	0x2c
	.long	0xcd
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0x14
	.long	.LASF22
	.byte	0x1
	.byte	0x1f
	.byte	0x17
	.long	0x25f
	.long	.LFB5
	.long	.LFE5-.LFB5
	.uleb128 0x1
	.byte	0x9c
	.long	0x25f
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x1f
	.byte	0x33
	.long	0x99
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0x8
	.byte	0x4
	.long	0x265
	.uleb128 0x4
	.byte	0x1
	.byte	0x8
	.long	.LASF23
	.uleb128 0x15
	.long	.LASF25
	.byte	0x1
	.byte	0x1a
	.byte	0xd
	.long	.LFB4
	.long	.LFE4-.LFB4
	.uleb128 0x1
	.byte	0x9c
	.long	0x2bf
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x1a
	.byte	0x27
	.long	0x99
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF7
	.byte	0x1
	.byte	0x1a
	.byte	0x3c
	.long	0x99
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.uleb128 0xd
	.long	.LASF8
	.byte	0x1
	.byte	0x1a
	.byte	0x49
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 8
	.uleb128 0xd
	.long	.LASF26
	.byte	0x1
	.byte	0x1a
	.byte	0x55
	.long	0x31
	.uleb128 0x2
	.byte	0x91
	.sleb128 12
	.byte	0
	.uleb128 0x13
	.long	.LASF27
	.byte	0x1
	.byte	0x12
	.byte	0xd
	.long	.LFB3
	.long	.LFE3-.LFB3
	.uleb128 0x1
	.byte	0x9c
	.long	0x2f4
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0x12
	.byte	0x2a
	.long	0x99
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0xd
	.long	.LASF26
	.byte	0x1
	.byte	0x12
	.byte	0x35
	.long	0x31
	.uleb128 0x2
	.byte	0x91
	.sleb128 4
	.byte	0
	.uleb128 0x14
	.long	.LASF28
	.byte	0x1
	.byte	0xe
	.byte	0xc
	.long	0x31
	.long	.LFB2
	.long	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.long	0x31e
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0xe
	.byte	0x2e
	.long	0x31e
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0x8
	.byte	0x4
	.long	0x6c
	.uleb128 0x14
	.long	.LASF29
	.byte	0x1
	.byte	0xa
	.byte	0xf
	.long	0x38
	.long	.LFB1
	.long	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.long	0x34e
	.uleb128 0xd
	.long	.LASF12
	.byte	0x1
	.byte	0xa
	.byte	0x30
	.long	0x31e
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.byte	0
	.uleb128 0x16
	.long	.LASF30
	.byte	0x1
	.byte	0x5
	.byte	0xf
	.long	0x38
	.long	.LFB0
	.long	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.long	.LASF31
	.byte	0x1
	.byte	0x5
	.byte	0x1f
	.long	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 0
	.uleb128 0x12
	.string	"m"
	.byte	0x1
	.byte	0x6
	.byte	0xc
	.long	0x38
	.uleb128 0x2
	.byte	0x7e
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
	.uleb128 0x6
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
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0x4
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
	.uleb128 0x5
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
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
	.uleb128 0x7
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
	.uleb128 0x8
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
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
	.uleb128 0x6
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
	.uleb128 0x6
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
	.uleb128 0x6
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
	.uleb128 0x6
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
	.uleb128 0x6
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
	.uleb128 0x6
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
	.uleb128 0x6
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.long	0x1c
	.word	0x2
	.long	.Ldebug_info0
	.byte	0x4
	.byte	0
	.word	0
	.word	0
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF18:
	.string	"heap_size"
.LASF1:
	.string	"size_t"
.LASF7:
	.string	"next"
.LASF31:
	.string	"value"
.LASF15:
	.string	"requested"
.LASF36:
	.string	"freelist_alloc"
.LASF16:
	.string	"freelist_free"
.LASF22:
	.string	"chunk_to_data"
.LASF27:
	.string	"chunk_set_used"
.LASF14:
	.string	"size"
.LASF6:
	.string	"chunk_header"
.LASF37:
	.string	"void"
.LASF29:
	.string	"chunk_length"
.LASF9:
	.string	"short unsigned int"
.LASF19:
	.string	"new_chunk"
.LASF13:
	.string	"old_next"
.LASF32:
	.string	"GNU C17 12.2.0 -mcpu=68020 -gdwarf-4 -gctf"
.LASF35:
	.string	"memset"
.LASF28:
	.string	"chunk_is_used"
.LASF0:
	.string	"ptrdiff_t"
.LASF20:
	.string	"new_len"
.LASF12:
	.string	"chunk"
.LASF23:
	.string	"unsigned char"
.LASF2:
	.string	"unsigned int"
.LASF10:
	.string	"char"
.LASF11:
	.string	"heap"
.LASF4:
	.string	"long long int"
.LASF34:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator"
.LASF17:
	.string	"freelist_init"
.LASF38:
	.string	"unknown"
.LASF21:
	.string	"chunk_from_data"
.LASF26:
	.string	"used"
.LASF24:
	.string	"chunk_split"
.LASF33:
	.string	"src/allocator.c"
.LASF25:
	.string	"chunk_write"
.LASF3:
	.string	"long int"
.LASF30:
	.string	"align_up"
.LASF5:
	.string	"long double"
.LASF8:
	.string	"length"
	.ident	"GCC: (Debian 12.2.0-13) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
