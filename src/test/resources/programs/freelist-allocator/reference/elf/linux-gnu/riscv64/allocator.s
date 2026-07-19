	.file	"allocator.c"
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
	.4byte	0x137
	.4byte	0
	.4byte	0
	.4byte	0
	.4byte	0x30
	.4byte	0x30
	.4byte	0x60
	.4byte	0x60
	.4byte	0x274
	.4byte	0x1b7
	.4byte	0x1b
	.4byte	0x1d
	.4byte	0x1a
	.4byte	0x1e
	.4byte	0x11
	.4byte	0x19
	.4byte	0x18
	.4byte	0x14
	.4byte	0x13
	.4byte	0x12
	.4byte	0x15
	.4byte	0x10
	.4byte	0x113
	.4byte	0x121
	.4byte	0x104
	.4byte	0x12e
	.4byte	0x95
	.4byte	0xf8
	.4byte	0xea
	.4byte	0xc0
	.4byte	0xb2
	.4byte	0xa3
	.4byte	0xcc
	.4byte	0x8e
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
	.4byte	0x1000020
	.4byte	0x31
	.4byte	0x6000000
	.4byte	0x8
	.4byte	0x1000040
	.4byte	0x3f
	.4byte	0xa000000
	.4byte	0x10
	.4byte	0x6000080
	.4byte	0x4b
	.4byte	0x1a000002
	.4byte	0x10
	.4byte	0x65
	.4byte	0
	.4byte	0xa
	.4byte	0x6a
	.4byte	0x40
	.4byte	0x2
	.4byte	0x58
	.4byte	0x2a000000
	.4byte	0x8
	.4byte	0
	.4byte	0xe000000
	.4byte	0x9
	.4byte	0
	.4byte	0x32000000
	.4byte	0x9
	.4byte	0x71
	.4byte	0x6000000
	.4byte	0x2
	.4byte	0x10
	.4byte	0x84
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0x89
	.4byte	0x6000000
	.4byte	0
	.4byte	0x1000000
	.4byte	0
	.4byte	0xe000000
	.4byte	0xe
	.4byte	0x8e
	.4byte	0x16000003
	.4byte	0xf
	.4byte	0xf
	.4byte	0x5
	.4byte	0x4
	.4byte	0
	.4byte	0x95
	.4byte	0x16000002
	.4byte	0xe
	.4byte	0xf
	.4byte	0xf
	.4byte	0xa3
	.4byte	0x16000002
	.4byte	0xf
	.4byte	0xf
	.4byte	0x4
	.4byte	0xb2
	.4byte	0x16000002
	.4byte	0xe
	.4byte	0xf
	.4byte	0x4
	.4byte	0xc0
	.4byte	0x16000002
	.4byte	0xe
	.4byte	0xa
	.4byte	0x4
	.4byte	0xcc
	.4byte	0x16000001
	.4byte	0xa
	.4byte	0xf
	.4byte	0
	.4byte	0xdc
	.4byte	0x6000000
	.4byte	0x1
	.4byte	0x2000008
	.4byte	0
	.4byte	0xe000000
	.4byte	0x16
	.4byte	0xea
	.4byte	0x16000001
	.4byte	0x17
	.4byte	0xa
	.4byte	0
	.4byte	0xf8
	.4byte	0x16000004
	.4byte	0xe
	.4byte	0xa
	.4byte	0xa
	.4byte	0x4
	.4byte	0x5
	.4byte	0x104
	.4byte	0x16000002
	.4byte	0xe
	.4byte	0xa
	.4byte	0x5
	.4byte	0x113
	.4byte	0x16000001
	.4byte	0x5
	.4byte	0x1c
	.4byte	0
	.4byte	0
	.4byte	0xe000000
	.4byte	0xb
	.4byte	0x121
	.4byte	0x16000001
	.4byte	0x4
	.4byte	0x1c
	.4byte	0
	.4byte	0x12e
	.4byte	0x16000001
	.4byte	0x4
	.4byte	0x4
	.4byte	0
	.string	""
	.string	"long int"
	.string	"ptrdiff_t"
	.string	"long unsigned int"
	.string	"size_t"
	.string	"int"
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
	.align	1
	.type	align_up, @function
align_up:
.LFB0:
	.loc 1 5 38
	.cfi_startproc
	addi	sp,sp,-48
	.cfi_def_cfa_offset 48
	sd	s0,40(sp)
	.cfi_offset 8, -8
	addi	s0,sp,48
	.cfi_def_cfa 8, 0
	sd	a0,-40(s0)
	.loc 1 6 12
	li	a5,7
	sd	a5,-24(s0)
	.loc 1 7 19
	ld	a4,-40(s0)
	ld	a5,-24(s0)
	add	a4,a4,a5
	.loc 1 7 26
	ld	a5,-24(s0)
	not	a5,a5
	.loc 1 7 24
	and	a5,a4,a5
	.loc 1 8 1
	mv	a0,a5
	ld	s0,40(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 48
	addi	sp,sp,48
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE0:
	.size	align_up, .-align_up
	.align	1
	.type	chunk_length, @function
chunk_length:
.LFB1:
	.loc 1 10 55
	.cfi_startproc
	addi	sp,sp,-32
	.cfi_def_cfa_offset 32
	sd	s0,24(sp)
	.cfi_offset 8, -8
	addi	s0,sp,32
	.cfi_def_cfa 8, 0
	sd	a0,-24(s0)
	.loc 1 11 47
	ld	a5,-24(s0)
	ld	a5,8(a5)
	.loc 1 11 12
	srai	a4,a5,63
	xor	a5,a4,a5
	sub	a5,a5,a4
	.loc 1 12 1
	mv	a0,a5
	ld	s0,24(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 32
	addi	sp,sp,32
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE1:
	.size	chunk_length, .-chunk_length
	.align	1
	.type	chunk_is_used, @function
chunk_is_used:
.LFB2:
	.loc 1 14 53
	.cfi_startproc
	addi	sp,sp,-32
	.cfi_def_cfa_offset 32
	sd	s0,24(sp)
	.cfi_offset 8, -8
	addi	s0,sp,32
	.cfi_def_cfa 8, 0
	sd	a0,-24(s0)
	.loc 1 15 17
	ld	a5,-24(s0)
	ld	a5,8(a5)
	.loc 1 15 26
	srli	a5,a5,63
	andi	a5,a5,0xff
	sext.w	a5,a5
	.loc 1 16 1
	mv	a0,a5
	ld	s0,24(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 32
	addi	sp,sp,32
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE2:
	.size	chunk_is_used, .-chunk_is_used
	.align	1
	.type	chunk_set_used, @function
chunk_set_used:
.LFB3:
	.loc 1 18 59
	.cfi_startproc
	addi	sp,sp,-32
	.cfi_def_cfa_offset 32
	sd	ra,24(sp)
	sd	s0,16(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	addi	s0,sp,32
	.cfi_def_cfa 8, 0
	sd	a0,-24(s0)
	mv	a5,a1
	sw	a5,-28(s0)
	.loc 1 19 9
	ld	a0,-24(s0)
	call	chunk_is_used
	mv	a5,a0
	mv	a4,a5
	.loc 1 19 8
	lw	a5,-28(s0)
	sext.w	a5,a5
	beq	a5,a4,.L10
	.loc 1 23 27
	ld	a5,-24(s0)
	ld	a5,8(a5)
	.loc 1 23 21
	neg	a4,a5
	.loc 1 23 19
	ld	a5,-24(s0)
	sd	a4,8(a5)
	j	.L7
.L10:
	.loc 1 20 9
	nop
.L7:
	.loc 1 24 1
	ld	ra,24(sp)
	.cfi_restore 1
	ld	s0,16(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 32
	addi	sp,sp,32
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE3:
	.size	chunk_set_used, .-chunk_set_used
	.align	1
	.type	chunk_write, @function
chunk_write:
.LFB4:
	.loc 1 26 91
	.cfi_startproc
	addi	sp,sp,-48
	.cfi_def_cfa_offset 48
	sd	s0,40(sp)
	.cfi_offset 8, -8
	addi	s0,sp,48
	.cfi_def_cfa 8, 0
	sd	a0,-24(s0)
	sd	a1,-32(s0)
	sd	a2,-40(s0)
	mv	a5,a3
	sw	a5,-44(s0)
	.loc 1 27 17
	ld	a5,-24(s0)
	ld	a4,-32(s0)
	sd	a4,0(a5)
	.loc 1 28 50
	lw	a5,-44(s0)
	sext.w	a5,a5
	beq	a5,zero,.L12
	.loc 1 28 30 discriminator 1
	ld	a5,-40(s0)
	.loc 1 28 50 discriminator 1
	neg	a5,a5
	j	.L13
.L12:
	.loc 1 28 50 is_stmt 0 discriminator 2
	ld	a5,-40(s0)
.L13:
	.loc 1 28 19 is_stmt 1 discriminator 4
	ld	a4,-24(s0)
	sd	a5,8(a4)
	.loc 1 29 1 discriminator 4
	nop
	ld	s0,40(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 48
	addi	sp,sp,48
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE4:
	.size	chunk_write, .-chunk_write
	.align	1
	.type	chunk_to_data, @function
chunk_to_data:
.LFB5:
	.loc 1 31 58
	.cfi_startproc
	addi	sp,sp,-32
	.cfi_def_cfa_offset 32
	sd	s0,24(sp)
	.cfi_offset 8, -8
	addi	s0,sp,32
	.cfi_def_cfa 8, 0
	sd	a0,-24(s0)
	.loc 1 32 38
	ld	a5,-24(s0)
	addi	a5,a5,16
	.loc 1 33 1
	mv	a0,a5
	ld	s0,24(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 32
	addi	sp,sp,32
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE5:
	.size	chunk_to_data, .-chunk_to_data
	.align	1
	.type	chunk_from_data, @function
chunk_from_data:
.LFB6:
	.loc 1 35 49
	.cfi_startproc
	addi	sp,sp,-32
	.cfi_def_cfa_offset 32
	sd	s0,24(sp)
	.cfi_offset 8, -8
	addi	s0,sp,32
	.cfi_def_cfa 8, 0
	sd	a0,-24(s0)
	.loc 1 36 12
	ld	a5,-24(s0)
	addi	a5,a5,-16
	.loc 1 37 1
	mv	a0,a5
	ld	s0,24(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 32
	addi	sp,sp,32
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE6:
	.size	chunk_from_data, .-chunk_from_data
	.align	1
	.type	chunk_split, @function
chunk_split:
.LFB7:
	.loc 1 39 64
	.cfi_startproc
	addi	sp,sp,-48
	.cfi_def_cfa_offset 48
	sd	ra,40(sp)
	sd	s0,32(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	addi	s0,sp,48
	.cfi_def_cfa 8, 0
	sd	a0,-40(s0)
	sd	a1,-48(s0)
	.loc 1 40 19
	ld	a4,-40(s0)
	ld	a5,-48(s0)
	add	a5,a4,a5
	sd	a5,-24(s0)
	.loc 1 41 19
	ld	a0,-40(s0)
	call	chunk_length
	mv	a4,a0
	.loc 1 41 9
	ld	a5,-48(s0)
	sub	a5,a4,a5
	sd	a5,-32(s0)
	.loc 1 44 5
	ld	a4,-32(s0)
	li	a5,31
	bleu	a4,a5,.L21
	.loc 1 48 5
	ld	a5,-40(s0)
	ld	a5,0(a5)
	li	a3,0
	ld	a2,-32(s0)
	mv	a1,a5
	ld	a0,-24(s0)
	call	chunk_write
	.loc 1 49 5
	ld	a0,-40(s0)
	call	chunk_is_used
	mv	a5,a0
	mv	a3,a5
	ld	a2,-48(s0)
	ld	a1,-24(s0)
	ld	a0,-40(s0)
	call	chunk_write
	j	.L18
.L21:
	.loc 1 45 3
	nop
.L18:
	.loc 1 50 1
	ld	ra,40(sp)
	.cfi_restore 1
	ld	s0,32(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 48
	addi	sp,sp,48
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE7:
	.size	chunk_split, .-chunk_split
	.align	1
	.globl	freelist_init
	.type	freelist_init, @function
freelist_init:
.LFB8:
	.loc 1 52 50
	.cfi_startproc
	addi	sp,sp,-32
	.cfi_def_cfa_offset 32
	sd	ra,24(sp)
	sd	s0,16(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	addi	s0,sp,32
	.cfi_def_cfa 8, 0
	sd	a0,-24(s0)
	sd	a1,-32(s0)
	.loc 1 53 5
	li	a3,0
	ld	a2,-32(s0)
	li	a1,0
	ld	a0,-24(s0)
	call	chunk_write
	.loc 1 54 1
	nop
	ld	ra,24(sp)
	.cfi_restore 1
	ld	s0,16(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 32
	addi	sp,sp,32
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE8:
	.size	freelist_init, .-freelist_init
	.align	1
	.globl	freelist_alloc
	.type	freelist_alloc, @function
freelist_alloc:
.LFB9:
	.loc 1 56 47
	.cfi_startproc
	addi	sp,sp,-48
	.cfi_def_cfa_offset 48
	sd	ra,40(sp)
	sd	s0,32(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	addi	s0,sp,48
	.cfi_def_cfa 8, 0
	sd	a0,-40(s0)
	sd	a1,-48(s0)
	.loc 1 57 47
	ld	a0,-48(s0)
	call	align_up
	mv	a5,a0
	.loc 1 57 12
	addi	a5,a5,16
	sd	a5,-24(s0)
	.loc 1 60 8
	ld	a5,-48(s0)
	bne	a5,zero,.L24
	.loc 1 61 16
	li	a5,0
	j	.L25
.L24:
	.loc 1 65 5
	ld	a4,-24(s0)
	li	a5,31
	bgtu	a4,a5,.L26
	.loc 1 66 13
	li	a5,32
	sd	a5,-24(s0)
.L26:
	.loc 1 70 14
	ld	a5,-40(s0)
	sd	a5,-32(s0)
	.loc 1 70 5
	j	.L27
.L29:
	.loc 1 71 14
	ld	a0,-32(s0)
	call	chunk_is_used
	mv	a5,a0
	.loc 1 71 12
	bne	a5,zero,.L28
	.loc 1 71 36 discriminator 1
	ld	a0,-32(s0)
	call	chunk_length
	mv	a4,a0
	.loc 1 71 33 discriminator 1
	ld	a5,-24(s0)
	bgtu	a5,a4,.L28
	.loc 1 72 13
	ld	a1,-24(s0)
	ld	a0,-32(s0)
	call	chunk_split
	.loc 1 73 13
	li	a1,1
	ld	a0,-32(s0)
	call	chunk_set_used
	.loc 1 75 20
	ld	a0,-32(s0)
	call	chunk_to_data
	mv	a5,a0
	j	.L25
.L28:
	.loc 1 70 56 discriminator 2
	ld	a5,-32(s0)
	ld	a5,0(a5)
	sd	a5,-32(s0)
.L27:
	.loc 1 70 43 discriminator 1
	ld	a5,-32(s0)
	bne	a5,zero,.L29
	.loc 1 79 12
	li	a5,0
.L25:
	.loc 1 80 1
	mv	a0,a5
	ld	ra,40(sp)
	.cfi_restore 1
	ld	s0,32(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 48
	addi	sp,sp,48
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE9:
	.size	freelist_alloc, .-freelist_alloc
	.align	1
	.globl	freelist_free
	.type	freelist_free, @function
freelist_free:
.LFB10:
	.loc 1 82 43
	.cfi_startproc
	addi	sp,sp,-64
	.cfi_def_cfa_offset 64
	sd	ra,56(sp)
	sd	s0,48(sp)
	sd	s1,40(sp)
	sd	s2,32(sp)
	.cfi_offset 1, -8
	.cfi_offset 8, -16
	.cfi_offset 9, -24
	.cfi_offset 18, -32
	addi	s0,sp,64
	.cfi_def_cfa 8, 0
	sd	a0,-56(s0)
	sd	a1,-64(s0)
	.loc 1 85 8
	ld	a5,-64(s0)
	beq	a5,zero,.L36
	.loc 1 90 13
	ld	a0,-64(s0)
	call	chunk_from_data
	sd	a0,-40(s0)
	.loc 1 91 5
	li	a1,0
	ld	a0,-40(s0)
	call	chunk_set_used
	.loc 1 92 20
	ld	a0,-40(s0)
	call	chunk_length
	mv	a5,a0
	.loc 1 92 5
	addi	a5,a5,-16
	mv	a2,a5
	li	a1,0
	ld	a0,-64(s0)
	call	memset@plt
	.loc 1 95 11
	ld	a5,-56(s0)
	sd	a5,-40(s0)
	.loc 1 96 11
	j	.L33
.L35:
	.loc 1 97 14
	ld	a0,-40(s0)
	call	chunk_is_used
	mv	a5,a0
	.loc 1 97 12
	bne	a5,zero,.L34
	.loc 1 97 58 discriminator 1
	ld	a5,-40(s0)
	ld	a5,0(a5)
	.loc 1 97 39 discriminator 1
	mv	a0,a5
	call	chunk_is_used
	mv	a5,a0
	.loc 1 97 35 discriminator 1
	bne	a5,zero,.L34
.LBB2:
	.loc 1 98 19
	ld	a5,-40(s0)
	ld	a5,0(a5)
	sd	a5,-48(s0)
	.loc 1 100 37
	ld	a5,-40(s0)
	ld	a5,0(a5)
	.loc 1 100 13
	ld	s1,0(a5)
	.loc 1 100 51
	ld	a0,-40(s0)
	call	chunk_length
	mv	s2,a0
	.loc 1 100 91
	ld	a5,-40(s0)
	ld	a5,0(a5)
	.loc 1 100 73
	mv	a0,a5
	call	chunk_length
	mv	a5,a0
	.loc 1 100 13
	add	a5,s2,a5
	li	a3,0
	mv	a2,a5
	mv	a1,s1
	ld	a0,-40(s0)
	call	chunk_write
	.loc 1 101 13
	li	a2,16
	li	a1,0
	ld	a0,-48(s0)
	call	memset@plt
.LBE2:
	.loc 1 97 67
	j	.L33
.L34:
	.loc 1 103 19
	ld	a5,-40(s0)
	ld	a5,0(a5)
	sd	a5,-40(s0)
.L33:
	.loc 1 96 26
	ld	a5,-40(s0)
	beq	a5,zero,.L30
	.loc 1 96 34 discriminator 1
	ld	a5,-40(s0)
	ld	a5,0(a5)
	.loc 1 96 26 discriminator 1
	bne	a5,zero,.L35
	j	.L30
.L36:
	.loc 1 86 9
	nop
.L30:
	.loc 1 106 1
	ld	ra,56(sp)
	.cfi_restore 1
	ld	s0,48(sp)
	.cfi_restore 8
	.cfi_def_cfa 2, 64
	ld	s1,40(sp)
	.cfi_restore 9
	ld	s2,32(sp)
	.cfi_restore 18
	addi	sp,sp,64
	.cfi_def_cfa_offset 0
	jr	ra
	.cfi_endproc
.LFE10:
	.size	freelist_free, .-freelist_free
.Letext0:
	.file 2 "/usr/lib/gcc-cross/riscv64-linux-gnu/12/include/stddef.h"
	.file 3 "/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/include/allocator.h"
	.file 4 "/usr/riscv64-linux-gnu/include/string.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x3e6
	.2byte	0x4
	.4byte	.Ldebug_abbrev0
	.byte	0x8
	.byte	0x1
	.4byte	.LASF32
	.byte	0xc
	.4byte	.LASF33
	.4byte	.LASF34
	.8byte	.Ltext0
	.8byte	.Letext0-.Ltext0
	.4byte	.Ldebug_line0
	.byte	0x2
	.4byte	.LASF0
	.byte	0x2
	.byte	0x91
	.byte	0x1a
	.4byte	0x39
	.byte	0x3
	.byte	0x8
	.byte	0x5
	.4byte	.LASF2
	.byte	0x2
	.4byte	.LASF1
	.byte	0x2
	.byte	0xd6
	.byte	0x17
	.4byte	0x4c
	.byte	0x3
	.byte	0x8
	.byte	0x7
	.4byte	.LASF3
	.byte	0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.byte	0x3
	.byte	0x8
	.byte	0x5
	.4byte	.LASF4
	.byte	0x3
	.byte	0x10
	.byte	0x4
	.4byte	.LASF5
	.byte	0x2
	.4byte	.LASF6
	.byte	0x3
	.byte	0x9
	.byte	0x1d
	.4byte	0x79
	.byte	0x5
	.4byte	0x68
	.byte	0x6
	.4byte	.LASF6
	.byte	0x10
	.byte	0x3
	.byte	0xb
	.byte	0x8
	.4byte	0xa1
	.byte	0x7
	.4byte	.LASF7
	.byte	0x3
	.byte	0xc
	.byte	0x13
	.4byte	0xa1
	.byte	0
	.byte	0x7
	.4byte	.LASF8
	.byte	0x3
	.byte	0xd
	.byte	0xf
	.4byte	0x2d
	.byte	0x8
	.byte	0
	.byte	0x8
	.byte	0x8
	.4byte	0x68
	.byte	0x3
	.byte	0x2
	.byte	0x7
	.4byte	.LASF9
	.byte	0x3
	.byte	0x1
	.byte	0x8
	.4byte	.LASF10
	.byte	0x9
	.4byte	.LASF35
	.byte	0x4
	.byte	0x3d
	.byte	0xe
	.4byte	0xd5
	.4byte	0xd5
	.byte	0xa
	.4byte	0xd5
	.byte	0xa
	.4byte	0x53
	.byte	0xa
	.4byte	0x40
	.byte	0
	.byte	0xb
	.byte	0x8
	.byte	0xc
	.4byte	.LASF16
	.byte	0x1
	.byte	0x52
	.byte	0x6
	.8byte	.LFB10
	.8byte	.LFE10-.LFB10
	.byte	0x1
	.byte	0x9c
	.4byte	0x144
	.byte	0xd
	.4byte	.LASF11
	.byte	0x1
	.byte	0x52
	.byte	0x1a
	.4byte	0xd5
	.byte	0x2
	.byte	0x91
	.byte	0x48
	.byte	0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x52
	.byte	0x26
	.4byte	0xd5
	.byte	0x2
	.byte	0x91
	.byte	0x40
	.byte	0xf
	.4byte	.LASF12
	.byte	0x1
	.byte	0x53
	.byte	0x13
	.4byte	0xa1
	.byte	0x2
	.byte	0x91
	.byte	0x58
	.byte	0x10
	.8byte	.LBB2
	.8byte	.LBE2-.LBB2
	.byte	0xf
	.4byte	.LASF13
	.byte	0x1
	.byte	0x62
	.byte	0x13
	.4byte	0xd5
	.byte	0x2
	.byte	0x91
	.byte	0x50
	.byte	0
	.byte	0
	.byte	0x11
	.4byte	.LASF36
	.byte	0x1
	.byte	0x38
	.byte	0x7
	.4byte	0xd5
	.8byte	.LFB9
	.8byte	.LFE9-.LFB9
	.byte	0x1
	.byte	0x9c
	.4byte	0x1a3
	.byte	0xd
	.4byte	.LASF11
	.byte	0x1
	.byte	0x38
	.byte	0x1c
	.4byte	0xd5
	.byte	0x2
	.byte	0x91
	.byte	0x58
	.byte	0xd
	.4byte	.LASF14
	.byte	0x1
	.byte	0x38
	.byte	0x29
	.4byte	0x40
	.byte	0x2
	.byte	0x91
	.byte	0x50
	.byte	0xf
	.4byte	.LASF15
	.byte	0x1
	.byte	0x39
	.byte	0xc
	.4byte	0x40
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0x12
	.string	"cur"
	.byte	0x1
	.byte	0x3a
	.byte	0x13
	.4byte	0xa1
	.byte	0x2
	.byte	0x91
	.byte	0x60
	.byte	0
	.byte	0xc
	.4byte	.LASF17
	.byte	0x1
	.byte	0x34
	.byte	0x6
	.8byte	.LFB8
	.8byte	.LFE8-.LFB8
	.byte	0x1
	.byte	0x9c
	.4byte	0x1e0
	.byte	0xd
	.4byte	.LASF11
	.byte	0x1
	.byte	0x34
	.byte	0x1a
	.4byte	0xd5
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0xd
	.4byte	.LASF18
	.byte	0x1
	.byte	0x34
	.byte	0x27
	.4byte	0x40
	.byte	0x2
	.byte	0x91
	.byte	0x60
	.byte	0
	.byte	0x13
	.4byte	.LASF24
	.byte	0x1
	.byte	0x27
	.byte	0xd
	.8byte	.LFB7
	.8byte	.LFE7-.LFB7
	.byte	0x1
	.byte	0x9c
	.4byte	0x23b
	.byte	0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x27
	.byte	0x27
	.4byte	0xa1
	.byte	0x2
	.byte	0x91
	.byte	0x58
	.byte	0xd
	.4byte	.LASF15
	.byte	0x1
	.byte	0x27
	.byte	0x35
	.4byte	0x40
	.byte	0x2
	.byte	0x91
	.byte	0x50
	.byte	0xf
	.4byte	.LASF19
	.byte	0x1
	.byte	0x28
	.byte	0x13
	.4byte	0xa1
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0xf
	.4byte	.LASF20
	.byte	0x1
	.byte	0x29
	.byte	0x9
	.4byte	0x40
	.byte	0x2
	.byte	0x91
	.byte	0x60
	.byte	0
	.byte	0x14
	.4byte	.LASF21
	.byte	0x1
	.byte	0x23
	.byte	0x16
	.4byte	0xa1
	.8byte	.LFB6
	.8byte	.LFE6-.LFB6
	.byte	0x1
	.byte	0x9c
	.4byte	0x26d
	.byte	0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x23
	.byte	0x2c
	.4byte	0xd5
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0
	.byte	0x14
	.4byte	.LASF22
	.byte	0x1
	.byte	0x1f
	.byte	0x17
	.4byte	0x29f
	.8byte	.LFB5
	.8byte	.LFE5-.LFB5
	.byte	0x1
	.byte	0x9c
	.4byte	0x29f
	.byte	0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x1f
	.byte	0x33
	.4byte	0xa1
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0
	.byte	0x8
	.byte	0x8
	.4byte	0x2a5
	.byte	0x3
	.byte	0x1
	.byte	0x8
	.4byte	.LASF23
	.byte	0x15
	.4byte	.LASF25
	.byte	0x1
	.byte	0x1a
	.byte	0xd
	.8byte	.LFB4
	.8byte	.LFE4-.LFB4
	.byte	0x1
	.byte	0x9c
	.4byte	0x307
	.byte	0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x1a
	.byte	0x27
	.4byte	0xa1
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0xd
	.4byte	.LASF7
	.byte	0x1
	.byte	0x1a
	.byte	0x3c
	.4byte	0xa1
	.byte	0x2
	.byte	0x91
	.byte	0x60
	.byte	0xd
	.4byte	.LASF8
	.byte	0x1
	.byte	0x1a
	.byte	0x49
	.4byte	0x40
	.byte	0x2
	.byte	0x91
	.byte	0x58
	.byte	0xd
	.4byte	.LASF26
	.byte	0x1
	.byte	0x1a
	.byte	0x55
	.4byte	0x53
	.byte	0x2
	.byte	0x91
	.byte	0x54
	.byte	0
	.byte	0x13
	.4byte	.LASF27
	.byte	0x1
	.byte	0x12
	.byte	0xd
	.8byte	.LFB3
	.8byte	.LFE3-.LFB3
	.byte	0x1
	.byte	0x9c
	.4byte	0x344
	.byte	0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x12
	.byte	0x2a
	.4byte	0xa1
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0xd
	.4byte	.LASF26
	.byte	0x1
	.byte	0x12
	.byte	0x35
	.4byte	0x53
	.byte	0x2
	.byte	0x91
	.byte	0x64
	.byte	0
	.byte	0x14
	.4byte	.LASF28
	.byte	0x1
	.byte	0xe
	.byte	0xc
	.4byte	0x53
	.8byte	.LFB2
	.8byte	.LFE2-.LFB2
	.byte	0x1
	.byte	0x9c
	.4byte	0x376
	.byte	0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0xe
	.byte	0x2e
	.4byte	0x376
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0
	.byte	0x8
	.byte	0x8
	.4byte	0x74
	.byte	0x14
	.4byte	.LASF29
	.byte	0x1
	.byte	0xa
	.byte	0xf
	.4byte	0x40
	.8byte	.LFB1
	.8byte	.LFE1-.LFB1
	.byte	0x1
	.byte	0x9c
	.4byte	0x3ae
	.byte	0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0xa
	.byte	0x30
	.4byte	0x376
	.byte	0x2
	.byte	0x91
	.byte	0x68
	.byte	0
	.byte	0x16
	.4byte	.LASF30
	.byte	0x1
	.byte	0x5
	.byte	0xf
	.4byte	0x40
	.8byte	.LFB0
	.8byte	.LFE0-.LFB0
	.byte	0x1
	.byte	0x9c
	.byte	0xd
	.4byte	.LASF31
	.byte	0x1
	.byte	0x5
	.byte	0x1f
	.4byte	0x40
	.byte	0x2
	.byte	0x91
	.byte	0x58
	.byte	0x12
	.string	"m"
	.byte	0x1
	.byte	0x6
	.byte	0xc
	.4byte	0x40
	.byte	0x2
	.byte	0x91
	.byte	0x68
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
	.byte	0x16
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
	.byte	0xe
	.byte	0
	.byte	0
	.byte	0x4
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
	.byte	0x5
	.byte	0x26
	.byte	0
	.byte	0x49
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x6
	.byte	0x13
	.byte	0x1
	.byte	0x3
	.byte	0xe
	.byte	0xb
	.byte	0xb
	.byte	0x3a
	.byte	0xb
	.byte	0x3b
	.byte	0xb
	.byte	0x39
	.byte	0xb
	.byte	0x1
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x7
	.byte	0xd
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
	.byte	0x38
	.byte	0xb
	.byte	0
	.byte	0
	.byte	0x8
	.byte	0xf
	.byte	0
	.byte	0xb
	.byte	0xb
	.byte	0x49
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x9
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
	.byte	0x3c
	.byte	0x19
	.byte	0x1
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0xa
	.byte	0x5
	.byte	0
	.byte	0x49
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0xb
	.byte	0xf
	.byte	0
	.byte	0xb
	.byte	0xb
	.byte	0
	.byte	0
	.byte	0xc
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
	.byte	0x11
	.byte	0x1
	.byte	0x12
	.byte	0x7
	.byte	0x40
	.byte	0x18
	.byte	0x96,0x42
	.byte	0x19
	.byte	0x1
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0xd
	.byte	0x5
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
	.byte	0x10
	.byte	0xb
	.byte	0x1
	.byte	0x11
	.byte	0x1
	.byte	0x12
	.byte	0x7
	.byte	0
	.byte	0
	.byte	0x11
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
	.byte	0x96,0x42
	.byte	0x19
	.byte	0x1
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x12
	.byte	0x34
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
	.byte	0x13
	.byte	0x2e
	.byte	0x1
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
	.byte	0x11
	.byte	0x1
	.byte	0x12
	.byte	0x7
	.byte	0x40
	.byte	0x18
	.byte	0x96,0x42
	.byte	0x19
	.byte	0x1
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x14
	.byte	0x2e
	.byte	0x1
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
	.byte	0x1
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x15
	.byte	0x2e
	.byte	0x1
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
	.byte	0x11
	.byte	0x1
	.byte	0x12
	.byte	0x7
	.byte	0x40
	.byte	0x18
	.byte	0x97,0x42
	.byte	0x19
	.byte	0x1
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x16
	.byte	0x2e
	.byte	0x1
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
.LASF3:
	.string	"long unsigned int"
.LASF29:
	.string	"chunk_length"
.LASF9:
	.string	"short unsigned int"
.LASF32:
	.string	"GNU C17 12.2.0 -mabi=lp64d -misa-spec=20191213 -march=rv64imafdc_zicsr_zifencei -gdwarf-4 -gctf"
.LASF19:
	.string	"new_chunk"
.LASF13:
	.string	"old_next"
.LASF6:
	.string	"chunk_header"
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
.LASF10:
	.string	"char"
.LASF11:
	.string	"heap"
.LASF37:
	.string	"void"
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
.LASF2:
	.string	"long int"
.LASF30:
	.string	"align_up"
.LASF5:
	.string	"long double"
.LASF8:
	.string	"length"
	.ident	"GCC: (Debian 12.2.0-13) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
