	.file	"allocator.c"
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
	.4byte	0x129
	.4byte	0
	.4byte	0
	.4byte	0
	.4byte	0x30
	.4byte	0x30
	.4byte	0x60
	.4byte	0x60
	.4byte	0x264
	.4byte	0x1a9
	.4byte	0x14
	.4byte	0x13
	.4byte	0x12
	.4byte	0x18
	.4byte	0x1a
	.4byte	0xf
	.4byte	0x1d
	.4byte	0x19
	.4byte	0x10
	.4byte	0x17
	.4byte	0x11
	.4byte	0x1c
	.4byte	0xbe
	.4byte	0xb2
	.4byte	0xa4
	.4byte	0xea
	.4byte	0x105
	.4byte	0x80
	.4byte	0x120
	.4byte	0xf6
	.4byte	0x87
	.4byte	0xdc
	.4byte	0x95
	.4byte	0x113
	.4byte	0x1
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x1000020
	.4byte	0x5
	.4byte	0x2a000000
	.4byte	0x1
	.4byte	0xf
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x20
	.4byte	0x1c
	.4byte	0x2a000000
	.4byte	0x3
	.4byte	0x23
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x1000040
	.4byte	0x31
	.4byte	0xa000000
	.4byte	0x8
	.4byte	0x2000040
	.4byte	0x3d
	.4byte	0x1a000002
	.4byte	0x8
	.4byte	0x57
	.4byte	0
	.4byte	0x9
	.4byte	0x5c
	.4byte	0x20
	.4byte	0x2
	.4byte	0x4a
	.4byte	0x2a000000
	.4byte	0x7
	.4byte	0
	.4byte	0xe000000
	.4byte	0x8
	.4byte	0
	.4byte	0x32000000
	.4byte	0x8
	.4byte	0x63
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x10
	.4byte	0x76
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0x7b
	.4byte	0x6000000
	.4byte	0
	.4byte	0x1000000
	.4byte	0
	.4byte	0xe000000
	.4byte	0xd
	.4byte	0x80
	.4byte	0x16000003
	.4byte	0xe
	.4byte	0xe
	.4byte	0x1
	.4byte	0x4
	.4byte	0
	.4byte	0x87
	.4byte	0x16000002
	.4byte	0xd
	.4byte	0xe
	.4byte	0xe
	.4byte	0x95
	.4byte	0x16000002
	.4byte	0xe
	.4byte	0xe
	.4byte	0x4
	.4byte	0xa4
	.4byte	0x16000002
	.4byte	0xd
	.4byte	0xe
	.4byte	0x4
	.4byte	0xb2
	.4byte	0x16000002
	.4byte	0xd
	.4byte	0x9
	.4byte	0x4
	.4byte	0xbe
	.4byte	0x16000001
	.4byte	0x9
	.4byte	0xe
	.4byte	0
	.4byte	0xce
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0
	.4byte	0xe000000
	.4byte	0x15
	.4byte	0xdc
	.4byte	0x16000001
	.4byte	0x16
	.4byte	0x9
	.4byte	0
	.4byte	0xea
	.4byte	0x16000004
	.4byte	0xd
	.4byte	0x9
	.4byte	0x9
	.4byte	0x4
	.4byte	0x1
	.4byte	0xf6
	.4byte	0x16000002
	.4byte	0xd
	.4byte	0x9
	.4byte	0x1
	.4byte	0x105
	.4byte	0x16000001
	.4byte	0x1
	.4byte	0x1b
	.4byte	0
	.4byte	0
	.4byte	0xe000000
	.4byte	0xa
	.4byte	0x113
	.4byte	0x16000001
	.4byte	0x4
	.4byte	0x1b
	.4byte	0
	.4byte	0x120
	.4byte	0x16000001
	.4byte	0x4
	.4byte	0x4
	.4byte	0
	.string	""
	.string	"int"
	.string	"ptrdiff_t"
	.string	"unsigned int"
	.string	"size_t"
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
	.section	.text
.Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "src/allocator.c"
	.align 4
	.type	align_up, @function
align_up:
.LFB0:
	.loc 1 5 38
	.cfi_startproc
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 4
	.cfi_offset 27, -4
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,8 ;4
	st	r0,[fp,-8]	;26
	.loc 1 6 12
	st	3,[fp,-4]	;37
	.loc 1 7 19
	ld	r3,[fp,-8]	;23
	ld	r2,[fp,-4]	;23
	add_s r3,r3,r2 ;1
	.loc 1 7 26
	ld	r2,[fp,-4]	;23
	not_s r2,r2
	.loc 1 7 24
	and_s r2,r2,r3
	.loc 1 8 1
	mov_s	r0,r2	;4
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	j_s	[blink]
	.cfi_endproc
.LFE0:
	.size	align_up, .-align_up
	.align 4
	.type	chunk_length, @function
chunk_length:
.LFB1:
	.loc 1 10 55
	.cfi_startproc
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 4
	.cfi_offset 27, -4
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,4 ;4
	st	r0,[fp,-4]	;26
	.loc 1 11 47
	ld	r2,[fp,-4]	;23
	ld_s	r2,[r2,4]		;15
	.loc 1 11 12
	abs_s r2,r2
	.loc 1 12 1
	mov_s	r0,r2	;4
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	j_s	[blink]
	.cfi_endproc
.LFE1:
	.size	chunk_length, .-chunk_length
	.align 4
	.type	chunk_is_used, @function
chunk_is_used:
.LFB2:
	.loc 1 14 53
	.cfi_startproc
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 4
	.cfi_offset 27, -4
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,4 ;4
	st	r0,[fp,-4]	;26
	.loc 1 15 17
	ld	r2,[fp,-4]	;23
	ld_s	r2,[r2,4]		;15
	.loc 1 15 26
	lsr_s r2,r2,31
	extb_s	r2,r2
	.loc 1 16 1
	mov_s	r0,r2	;4
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	j_s	[blink]
	.cfi_endproc
.LFE2:
	.size	chunk_is_used, .-chunk_is_used
	.align 4
	.type	chunk_set_used, @function
chunk_set_used:
.LFB3:
	.loc 1 18 59
	.cfi_startproc
	push_s	blink
	.cfi_def_cfa_offset 4
	.cfi_offset 31, -4
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 8
	.cfi_offset 27, -8
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,8 ;4
	st	r0,[fp,-4]	;26
	st	r1,[fp,-8]	;26
	.loc 1 19 9
	ld	r0,[fp,-4]	;23
	bl @chunk_is_used;1
	mov_s	r2,r0	;4
	.loc 1 19 8
	ld	r3,[fp,-8]	;23
	cmp_s r3,r2
	beq_s @.L10
	.loc 1 23 27
	ld	r2,[fp,-4]	;23
	ld_s	r2,[r2,4]		;15
	.loc 1 23 21
	neg_s r3,r2
	.loc 1 23 19
	ld	r2,[fp,-4]	;23
	st_s	r3,[r2,4]		;16
	b_s @.L7
	.align 4
.L10:
	.loc 1 20 9
	nop_s
	.align 2
.L7:
	.loc 1 24 1
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	.cfi_def_cfa_offset 4
	pop_s	blink
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	j_s	[blink]
	.cfi_endproc
.LFE3:
	.size	chunk_set_used, .-chunk_set_used
	.align 4
	.type	chunk_write, @function
chunk_write:
.LFB4:
	.loc 1 26 91
	.cfi_startproc
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 4
	.cfi_offset 27, -4
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,16 ;4
	st	r0,[fp,-4]	;26
	st	r1,[fp,-8]	;26
	st	r2,[fp,-12]	;26
	st	r3,[fp,-16]	;26
	.loc 1 27 17
	ld	r2,[fp,-4]	;23
	ld	r3,[fp,-8]	;23
	st_s	r3,[r2]		;16
	.loc 1 28 50
	ld	r2,[fp,-16]	;23
	tst_s r2,r2
	beq_s @.L12
	.loc 1 28 30 discriminator 1
	ld	r2,[fp,-12]	;23
	.loc 1 28 50 discriminator 1
	neg_s r2,r2
	b_s @.L13
	.align 4
.L12:
	.loc 1 28 50 is_stmt 0 discriminator 2
	ld	r2,[fp,-12]	;23
	.align 2
.L13:
	.loc 1 28 19 is_stmt 1 discriminator 4
	ld	r3,[fp,-4]	;23
	st_s	r2,[r3,4]		;16
	.loc 1 29 1 discriminator 4
	nop_s
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	j_s	[blink]
	.cfi_endproc
.LFE4:
	.size	chunk_write, .-chunk_write
	.align 4
	.type	chunk_to_data, @function
chunk_to_data:
.LFB5:
	.loc 1 31 58
	.cfi_startproc
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 4
	.cfi_offset 27, -4
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,4 ;4
	st	r0,[fp,-4]	;26
	.loc 1 32 38
	ld	r2,[fp,-4]	;23
	add_s r2,r2,8 ;1
	.loc 1 33 1
	mov_s	r0,r2	;4
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	j_s	[blink]
	.cfi_endproc
.LFE5:
	.size	chunk_to_data, .-chunk_to_data
	.align 4
	.type	chunk_from_data, @function
chunk_from_data:
.LFB6:
	.loc 1 35 49
	.cfi_startproc
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 4
	.cfi_offset 27, -4
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,4 ;4
	st	r0,[fp,-4]	;26
	.loc 1 36 12
	ld	r2,[fp,-4]	;23
	sub r2,r2,8
	.loc 1 37 1
	mov_s	r0,r2	;4
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	j_s	[blink]
	.cfi_endproc
.LFE6:
	.size	chunk_from_data, .-chunk_from_data
	.align 4
	.type	chunk_split, @function
chunk_split:
.LFB7:
	.loc 1 39 64
	.cfi_startproc
	push_s	blink
	.cfi_def_cfa_offset 4
	.cfi_offset 31, -4
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 8
	.cfi_offset 27, -8
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,16 ;4
	st	r0,[fp,-12]	;26
	st	r1,[fp,-16]	;26
	.loc 1 40 19
	ld	r3,[fp,-12]	;23
	ld	r2,[fp,-16]	;23
	add_s r2,r3,r2 ;1
	st	r2,[fp,-4]	;26
	.loc 1 41 19
	ld	r0,[fp,-12]	;23
	bl @chunk_length;1
	mov_s	r2,r0	;4
	.loc 1 41 9
	ld	r3,[fp,-16]	;23
	sub_s r2,r2,r3
	st	r2,[fp,-8]	;26
	.loc 1 44 5
	ld	r2,[fp,-8]	;23
	cmp_s r2,15
	bls_s @.L21
	.loc 1 48 5
	ld	r2,[fp,-12]	;23
	ld_s	r12,[r2]		;15
	mov_s	r3,0	;3
	ld	r2,[fp,-8]	;23
	mov_s	r1,r12	;4
	ld	r0,[fp,-4]	;23
	bl @chunk_write
	.loc 1 49 5
	ld	r0,[fp,-12]	;23
	bl @chunk_is_used;1
	mov_s	r2,r0	;4
	mov_s	r3,r2	;4
	ld	r2,[fp,-16]	;23
	ld	r1,[fp,-4]	;23
	ld	r0,[fp,-12]	;23
	bl @chunk_write
	b_s @.L18
	.align 4
.L21:
	.loc 1 45 3
	nop_s
	.align 2
.L18:
	.loc 1 50 1
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	.cfi_def_cfa_offset 4
	pop_s	blink
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	j_s	[blink]
	.cfi_endproc
.LFE7:
	.size	chunk_split, .-chunk_split
	.align 4
	.global	freelist_init
	.type	freelist_init, @function
freelist_init:
.LFB8:
	.loc 1 52 50
	.cfi_startproc
	push_s	blink
	.cfi_def_cfa_offset 4
	.cfi_offset 31, -4
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 8
	.cfi_offset 27, -8
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,8 ;4
	st	r0,[fp,-4]	;26
	st	r1,[fp,-8]	;26
	.loc 1 53 5
	mov_s	r3,0	;3
	ld	r2,[fp,-8]	;23
	mov_s	r1,0	;3
	ld	r0,[fp,-4]	;23
	bl @chunk_write
	.loc 1 54 1
	nop_s
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	.cfi_def_cfa_offset 4
	pop_s	blink
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	j_s	[blink]
	.cfi_endproc
.LFE8:
	.size	freelist_init, .-freelist_init
	.align 4
	.global	freelist_alloc
	.type	freelist_alloc, @function
freelist_alloc:
.LFB9:
	.loc 1 56 47
	.cfi_startproc
	push_s	blink
	.cfi_def_cfa_offset 4
	.cfi_offset 31, -4
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 8
	.cfi_offset 27, -8
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,16 ;4
	st	r0,[fp,-12]	;26
	st	r1,[fp,-16]	;26
	.loc 1 57 47
	ld	r0,[fp,-16]	;23
	bl @align_up;1
	mov_s	r2,r0	;4
	.loc 1 57 12
	add_s r2,r2,8 ;1
	st	r2,[fp,-4]	;26
	.loc 1 60 8
	ld	r2,[fp,-16]	;23
	tst_s r2,r2
	bne_s @.L24
	.loc 1 61 16
	mov_s	r2,0	;3
	b_s @.L25
	.align 4
.L24:
	.loc 1 65 5
	ld	r2,[fp,-4]	;23
	cmp_s r2,15
	bhi_s @.L26
	.loc 1 66 13
	st	16,[fp,-4]	;37
	.align 2
.L26:
	.loc 1 70 14
	ld	r2,[fp,-12]	;23
	st	r2,[fp,-8]	;26
	.loc 1 70 5
	b_s @.L27
	.align 4
.L29:
	.loc 1 71 14
	ld	r0,[fp,-8]	;23
	bl @chunk_is_used;1
	mov_s	r2,r0	;4
	.loc 1 71 12
	tst_s r2,r2
	bne_s @.L28
	.loc 1 71 36 discriminator 1
	ld	r0,[fp,-8]	;23
	bl @chunk_length;1
	mov_s	r2,r0	;4
	.loc 1 71 33 discriminator 1
	ld	r3,[fp,-4]	;23
	cmp_s r3,r2
	bhi_s @.L28
	.loc 1 72 13
	ld	r1,[fp,-4]	;23
	ld	r0,[fp,-8]	;23
	bl @chunk_split
	.loc 1 73 13
	mov_s	r1,1	;3
	ld	r0,[fp,-8]	;23
	bl @chunk_set_used
	.loc 1 75 20
	ld	r0,[fp,-8]	;23
	bl @chunk_to_data;1
	mov_s	r2,r0	;4
	b_s @.L25
	.align 4
.L28:
	.loc 1 70 56 discriminator 2
	ld	r2,[fp,-8]	;23
	ld_s	r2,[r2]		;15
	st	r2,[fp,-8]	;26
	.align 2
.L27:
	.loc 1 70 43 discriminator 1
	ld	r2,[fp,-8]	;23
	tst_s r2,r2
	bne_s @.L29
	.loc 1 79 12
	mov_s	r2,0	;3
	.align 2
.L25:
	.loc 1 80 1
	mov_s	r0,r2	;4
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	.cfi_def_cfa_offset 4
	pop_s	blink
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	j_s	[blink]
	.cfi_endproc
.LFE9:
	.size	freelist_alloc, .-freelist_alloc
	.align 4
	.global	freelist_free
	.type	freelist_free, @function
freelist_free:
.LFB10:
	.loc 1 82 43
	.cfi_startproc
	push_s	blink
	.cfi_def_cfa_offset 4
	.cfi_offset 31, -4
	push_s	r14
	.cfi_def_cfa_offset 8
	.cfi_offset 14, -8
	push_s	r13
	.cfi_def_cfa_offset 12
	.cfi_offset 13, -12
	st.a	fp,[sp,-4]	;26
	.cfi_def_cfa_offset 16
	.cfi_offset 27, -16
	mov_s	fp,sp	;4
	.cfi_def_cfa_register 27
	sub_s sp,sp,16 ;4
	st	r0,[fp,-12]	;26
	st	r1,[fp,-16]	;26
	.loc 1 85 8
	ld	r2,[fp,-16]	;23
	tst_s r2,r2
	beq_s @.L36
	.loc 1 90 13
	ld	r0,[fp,-16]	;23
	bl @chunk_from_data;1
	st	r0,[fp,-4]	;26
	.loc 1 91 5
	mov_s	r1,0	;3
	ld	r0,[fp,-4]	;23
	bl @chunk_set_used
	.loc 1 92 20
	ld	r0,[fp,-4]	;23
	bl @chunk_length;1
	mov_s	r2,r0	;4
	.loc 1 92 5
	sub r2,r2,8
	mov_s	r1,0	;3
	ld	r0,[fp,-16]	;23
	bl @memset;1
	.loc 1 95 11
	ld	r2,[fp,-12]	;23
	st	r2,[fp,-4]	;26
	.loc 1 96 11
	b_s @.L33
	.align 4
.L35:
	.loc 1 97 14
	ld	r0,[fp,-4]	;23
	bl @chunk_is_used;1
	mov_s	r2,r0	;4
	.loc 1 97 12
	tst_s r2,r2
	bne_s @.L34
	.loc 1 97 58 discriminator 1
	ld	r2,[fp,-4]	;23
	ld_s	r2,[r2]		;15
	.loc 1 97 39 discriminator 1
	mov_s	r0,r2	;4
	bl @chunk_is_used;1
	mov_s	r2,r0	;4
	.loc 1 97 35 discriminator 1
	tst_s r2,r2
	bne_s @.L34
.LBB2:
	.loc 1 98 19
	ld	r2,[fp,-4]	;23
	ld_s	r2,[r2]		;15
	st	r2,[fp,-8]	;26
	.loc 1 100 37
	ld	r2,[fp,-4]	;23
	ld_s	r2,[r2]		;15
	.loc 1 100 13
	ld_s	r14,[r2]		;15
	.loc 1 100 51
	ld	r0,[fp,-4]	;23
	bl @chunk_length;1
	mov_s	r13,r0	;4
	.loc 1 100 91
	ld	r2,[fp,-4]	;23
	ld_s	r2,[r2]		;15
	.loc 1 100 73
	mov_s	r0,r2	;4
	bl @chunk_length;1
	mov_s	r2,r0	;4
	.loc 1 100 13
	add_s r2,r13,r2 ;1
	mov_s	r3,0	;3
	mov_s	r1,r14	;4
	ld	r0,[fp,-4]	;23
	bl @chunk_write
	.loc 1 101 13
	mov_s	r2,8	;3
	mov_s	r1,0	;3
	ld	r0,[fp,-8]	;23
	bl @memset;1
.LBE2:
	.loc 1 97 67
	b_s @.L33
	.align 4
.L34:
	.loc 1 103 19
	ld	r2,[fp,-4]	;23
	ld_s	r2,[r2]		;15
	st	r2,[fp,-4]	;26
	.align 2
.L33:
	.loc 1 96 26
	ld	r2,[fp,-4]	;23
	tst_s r2,r2
	beq_s @.L30
	.loc 1 96 34 discriminator 1
	ld	r2,[fp,-4]	;23
	ld_s	r2,[r2]		;15
	.loc 1 96 26 discriminator 1
	tst_s r2,r2
	bne_s @.L35
	b_s @.L30
	.align 4
.L36:
	.loc 1 86 9
	nop_s
	.align 2
.L30:
	.loc 1 106 1
	mov_s	sp,fp	;4
	.cfi_def_cfa_register 28
	ld.ab	fp,[sp,4]	;23
	.cfi_restore 27
	.cfi_def_cfa_offset 4
	ld	blink,[sp,8]	;23
	.cfi_restore 31
	pop_s	r13
	.cfi_restore 13
	.cfi_def_cfa_offset 0
	ld.ab	r14,[sp,8]	;23
	.cfi_restore 14
	.cfi_def_cfa_offset -8
	j_s	[blink]
	.cfi_endproc
.LFE10:
	.size	freelist_free, .-freelist_free
.Letext0:
	.file 2 "/usr/lib/gcc-cross/arc-linux-gnu/12/include/stddef.h"
	.file 3 "/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/include/allocator.h"
	.file 4 "/usr/arc-linux-gnu/include/string.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x377
	.2byte	0x4
	.4byte	@.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	@.LASF31
	.byte	0xc
	.4byte	@.LASF32
	.4byte	@.LASF33
	.4byte	@.Ltext0
	.4byte	@.Letext0-@.Ltext0
	.4byte	@.Ldebug_line0
	.uleb128 0x2
	.4byte	@.LASF0
	.byte	0x2
	.byte	0x91
	.byte	0x1a
	.4byte	0x31
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x2
	.4byte	@.LASF1
	.byte	0x2
	.byte	0xd6
	.byte	0x17
	.4byte	0x44
	.uleb128 0x4
	.byte	0x4
	.byte	0x7
	.4byte	@.LASF2
	.uleb128 0x4
	.byte	0x8
	.byte	0x5
	.4byte	@.LASF3
	.uleb128 0x4
	.byte	0x8
	.byte	0x4
	.4byte	@.LASF4
	.uleb128 0x2
	.4byte	@.LASF5
	.byte	0x3
	.byte	0x9
	.byte	0x1d
	.4byte	0x6a
	.uleb128 0x5
	.4byte	0x59
	.uleb128 0x6
	.4byte	@.LASF5
	.byte	0x8
	.byte	0x3
	.byte	0xb
	.byte	0x8
	.4byte	0x92
	.uleb128 0x7
	.4byte	@.LASF6
	.byte	0x3
	.byte	0xc
	.byte	0x13
	.4byte	0x92
	.byte	0
	.uleb128 0x7
	.4byte	@.LASF7
	.byte	0x3
	.byte	0xd
	.byte	0xf
	.4byte	0x25
	.byte	0x4
	.byte	0
	.uleb128 0x8
	.byte	0x4
	.4byte	0x59
	.uleb128 0x4
	.byte	0x2
	.byte	0x7
	.4byte	@.LASF8
	.uleb128 0x4
	.byte	0x1
	.byte	0x8
	.4byte	@.LASF9
	.uleb128 0x9
	.4byte	@.LASF34
	.byte	0x4
	.byte	0x3d
	.byte	0xe
	.4byte	0xc6
	.4byte	0xc6
	.uleb128 0xa
	.4byte	0xc6
	.uleb128 0xa
	.4byte	0x31
	.uleb128 0xa
	.4byte	0x38
	.byte	0
	.uleb128 0xb
	.byte	0x4
	.uleb128 0xc
	.4byte	@.LASF15
	.byte	0x1
	.byte	0x52
	.byte	0x6
	.4byte	@.LFB10
	.4byte	@.LFE10-@.LFB10
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x125
	.uleb128 0xd
	.4byte	@.LASF10
	.byte	0x1
	.byte	0x52
	.byte	0x1a
	.4byte	0xc6
	.uleb128 0x2
	.byte	0x91
	.sleb128 -28
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x52
	.byte	0x26
	.4byte	0xc6
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0xf
	.4byte	@.LASF11
	.byte	0x1
	.byte	0x53
	.byte	0x13
	.4byte	0x92
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0x10
	.4byte	@.LBB2
	.4byte	@.LBE2-@.LBB2
	.uleb128 0xf
	.4byte	@.LASF12
	.byte	0x1
	.byte	0x62
	.byte	0x13
	.4byte	0xc6
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.byte	0
	.uleb128 0x11
	.4byte	@.LASF35
	.byte	0x1
	.byte	0x38
	.byte	0x7
	.4byte	0xc6
	.4byte	@.LFB9
	.4byte	@.LFE9-@.LFB9
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x17c
	.uleb128 0xd
	.4byte	@.LASF10
	.byte	0x1
	.byte	0x38
	.byte	0x1c
	.4byte	0xc6
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0xd
	.4byte	@.LASF13
	.byte	0x1
	.byte	0x38
	.byte	0x29
	.4byte	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xf
	.4byte	@.LASF14
	.byte	0x1
	.byte	0x39
	.byte	0xc
	.4byte	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.uleb128 0x12
	.string	"cur"
	.byte	0x1
	.byte	0x3a
	.byte	0x13
	.4byte	0x92
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0xc
	.4byte	@.LASF16
	.byte	0x1
	.byte	0x34
	.byte	0x6
	.4byte	@.LFB8
	.4byte	@.LFE8-@.LFB8
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x1b1
	.uleb128 0xd
	.4byte	@.LASF10
	.byte	0x1
	.byte	0x34
	.byte	0x1a
	.4byte	0xc6
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.uleb128 0xd
	.4byte	@.LASF17
	.byte	0x1
	.byte	0x34
	.byte	0x27
	.4byte	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0x13
	.4byte	@.LASF23
	.byte	0x1
	.byte	0x27
	.byte	0xd
	.4byte	@.LFB7
	.4byte	@.LFE7-@.LFB7
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x204
	.uleb128 0xd
	.4byte	@.LASF11
	.byte	0x1
	.byte	0x27
	.byte	0x27
	.4byte	0x92
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.uleb128 0xd
	.4byte	@.LASF14
	.byte	0x1
	.byte	0x27
	.byte	0x35
	.4byte	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xf
	.4byte	@.LASF18
	.byte	0x1
	.byte	0x28
	.byte	0x13
	.4byte	0x92
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.uleb128 0xf
	.4byte	@.LASF19
	.byte	0x1
	.byte	0x29
	.byte	0x9
	.4byte	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0x14
	.4byte	@.LASF20
	.byte	0x1
	.byte	0x23
	.byte	0x16
	.4byte	0x92
	.4byte	@.LFB6
	.4byte	@.LFE6-@.LFB6
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x22e
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x23
	.byte	0x2c
	.4byte	0xc6
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x14
	.4byte	@.LASF21
	.byte	0x1
	.byte	0x1f
	.byte	0x17
	.4byte	0x258
	.4byte	@.LFB5
	.4byte	@.LFE5-@.LFB5
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x258
	.uleb128 0xd
	.4byte	@.LASF11
	.byte	0x1
	.byte	0x1f
	.byte	0x33
	.4byte	0x92
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x8
	.byte	0x4
	.4byte	0x25e
	.uleb128 0x4
	.byte	0x1
	.byte	0x8
	.4byte	@.LASF22
	.uleb128 0x15
	.4byte	@.LASF24
	.byte	0x1
	.byte	0x1a
	.byte	0xd
	.4byte	@.LFB4
	.4byte	@.LFE4-@.LFB4
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x2b8
	.uleb128 0xd
	.4byte	@.LASF11
	.byte	0x1
	.byte	0x1a
	.byte	0x27
	.4byte	0x92
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.uleb128 0xd
	.4byte	@.LASF6
	.byte	0x1
	.byte	0x1a
	.byte	0x3c
	.4byte	0x92
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.uleb128 0xd
	.4byte	@.LASF7
	.byte	0x1
	.byte	0x1a
	.byte	0x49
	.4byte	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0xd
	.4byte	@.LASF25
	.byte	0x1
	.byte	0x1a
	.byte	0x55
	.4byte	0x31
	.uleb128 0x2
	.byte	0x91
	.sleb128 -20
	.byte	0
	.uleb128 0x13
	.4byte	@.LASF26
	.byte	0x1
	.byte	0x12
	.byte	0xd
	.4byte	@.LFB3
	.4byte	@.LFE3-@.LFB3
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x2ed
	.uleb128 0xd
	.4byte	@.LASF11
	.byte	0x1
	.byte	0x12
	.byte	0x2a
	.4byte	0x92
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.uleb128 0xd
	.4byte	@.LASF25
	.byte	0x1
	.byte	0x12
	.byte	0x35
	.4byte	0x31
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0x14
	.4byte	@.LASF27
	.byte	0x1
	.byte	0xe
	.byte	0xc
	.4byte	0x31
	.4byte	@.LFB2
	.4byte	@.LFE2-@.LFB2
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x317
	.uleb128 0xd
	.4byte	@.LASF11
	.byte	0x1
	.byte	0xe
	.byte	0x2e
	.4byte	0x317
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x8
	.byte	0x4
	.4byte	0x65
	.uleb128 0x14
	.4byte	@.LASF28
	.byte	0x1
	.byte	0xa
	.byte	0xf
	.4byte	0x38
	.4byte	@.LFB1
	.4byte	@.LFE1-@.LFB1
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x347
	.uleb128 0xd
	.4byte	@.LASF11
	.byte	0x1
	.byte	0xa
	.byte	0x30
	.4byte	0x317
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x16
	.4byte	@.LASF29
	.byte	0x1
	.byte	0x5
	.byte	0xf
	.4byte	0x38
	.4byte	@.LFB0
	.4byte	@.LFE0-@.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.4byte	@.LASF30
	.byte	0x1
	.byte	0x5
	.byte	0x1f
	.4byte	0x38
	.uleb128 0x2
	.byte	0x91
	.sleb128 -12
	.uleb128 0x12
	.string	"m"
	.byte	0x1
	.byte	0x6
	.byte	0xc
	.4byte	0x38
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
.LASF17:
	.string	"heap_size"
.LASF1:
	.string	"size_t"
.LASF6:
	.string	"next"
.LASF30:
	.string	"value"
.LASF14:
	.string	"requested"
.LASF35:
	.string	"freelist_alloc"
.LASF15:
	.string	"freelist_free"
.LASF21:
	.string	"chunk_to_data"
.LASF31:
	.string	"GNU C17 12.2.0 -gdwarf-4 -gctf"
.LASF13:
	.string	"size"
.LASF29:
	.string	"align_up"
.LASF36:
	.string	"void"
.LASF28:
	.string	"chunk_length"
.LASF8:
	.string	"short unsigned int"
.LASF18:
	.string	"new_chunk"
.LASF12:
	.string	"old_next"
.LASF5:
	.string	"chunk_header"
.LASF34:
	.string	"memset"
.LASF27:
	.string	"chunk_is_used"
.LASF0:
	.string	"ptrdiff_t"
.LASF19:
	.string	"new_len"
.LASF11:
	.string	"chunk"
.LASF22:
	.string	"unsigned char"
.LASF2:
	.string	"unsigned int"
.LASF9:
	.string	"char"
.LASF10:
	.string	"heap"
.LASF3:
	.string	"long long int"
.LASF33:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator"
.LASF16:
	.string	"freelist_init"
.LASF37:
	.string	"unknown"
.LASF20:
	.string	"chunk_from_data"
.LASF25:
	.string	"used"
.LASF23:
	.string	"chunk_split"
.LASF32:
	.string	"src/allocator.c"
.LASF24:
	.string	"chunk_write"
.LASF26:
	.string	"chunk_set_used"
.LASF4:
	.string	"long double"
.LASF7:
	.string	"length"
	.ident	"GCC: (Debian 12.2.0-13) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
