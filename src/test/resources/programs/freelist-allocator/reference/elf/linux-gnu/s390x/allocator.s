	.file	"allocator.c"
	.machinemode zarch
	.machine "z196"
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
	.4byte	0x12
	.4byte	0x10
	.4byte	0x1a
	.4byte	0x1e
	.4byte	0x15
	.4byte	0x11
	.4byte	0x13
	.4byte	0x18
	.4byte	0x1d
	.4byte	0x14
	.4byte	0x19
	.4byte	0x113
	.4byte	0xa3
	.4byte	0x8e
	.4byte	0x104
	.4byte	0x12e
	.4byte	0xcc
	.4byte	0x95
	.4byte	0xb2
	.4byte	0xea
	.4byte	0x121
	.4byte	0xc0
	.4byte	0xf8
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
	.file 1 "src/allocator.c"
	.align	8
	.type	align_up, @function
align_up:
.LFB0:
	.loc 1 5 38
	.cfi_startproc
	ldgr	%f2,%r11
	.cfi_register 11, 17
	ldgr	%f0,%r15
	.cfi_register 15, 16
	lay	%r15,-176(%r15)
	.cfi_def_cfa_offset 336
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,160(%r11)
	.loc 1 6 12
	mvghi	168(%r11),7
	.loc 1 7 19
	lg	%r1,160(%r11)
	ag	%r1,168(%r11)
	.loc 1 7 26
	lg	%r2,168(%r11)
	lghi	%r3,-1
	xgr	%r2,%r3
	.loc 1 7 24
	ngr	%r1,%r2
	.loc 1 8 1
	lgr	%r2,%r1
	lgdr	%r15,%f0
	.cfi_restore 15
	.cfi_def_cfa 15, 160
	lgdr	%r11,%f2
	.cfi_restore 11
	br	%r14
	.cfi_endproc
.LFE0:
	.size	align_up, .-align_up
	.align	8
	.type	chunk_length, @function
chunk_length:
.LFB1:
	.loc 1 10 55
	.cfi_startproc
	ldgr	%f2,%r11
	.cfi_register 11, 17
	ldgr	%f0,%r15
	.cfi_register 15, 16
	lay	%r15,-168(%r15)
	.cfi_def_cfa_offset 328
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,160(%r11)
	.loc 1 11 47
	lg	%r1,160(%r11)
	lg	%r1,8(%r1)
	.loc 1 11 12
	lpgr	%r1,%r1
	.loc 1 12 1
	lgr	%r2,%r1
	lgdr	%r15,%f0
	.cfi_restore 15
	.cfi_def_cfa 15, 160
	lgdr	%r11,%f2
	.cfi_restore 11
	br	%r14
	.cfi_endproc
.LFE1:
	.size	chunk_length, .-chunk_length
	.align	8
	.type	chunk_is_used, @function
chunk_is_used:
.LFB2:
	.loc 1 14 53
	.cfi_startproc
	ldgr	%f2,%r11
	.cfi_register 11, 17
	ldgr	%f0,%r15
	.cfi_register 15, 16
	lay	%r15,-168(%r15)
	.cfi_def_cfa_offset 328
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,160(%r11)
	.loc 1 15 17
	lg	%r1,160(%r11)
	lg	%r1,8(%r1)
	.loc 1 15 26
	srlg	%r1,%r1,63
	llcr	%r1,%r1
	lgfr	%r1,%r1
	.loc 1 16 1
	lgr	%r2,%r1
	lgdr	%r15,%f0
	.cfi_restore 15
	.cfi_def_cfa 15, 160
	lgdr	%r11,%f2
	.cfi_restore 11
	br	%r14
	.cfi_endproc
.LFE2:
	.size	chunk_is_used, .-chunk_is_used
	.align	8
	.type	chunk_set_used, @function
chunk_set_used:
.LFB3:
	.loc 1 18 59
	.cfi_startproc
	stmg	%r11,%r15,88(%r15)
	.cfi_offset 11, -72
	.cfi_offset 12, -64
	.cfi_offset 13, -56
	.cfi_offset 14, -48
	.cfi_offset 15, -40
	lay	%r15,-176(%r15)
	.cfi_def_cfa_offset 336
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,168(%r11)
	lgr	%r1,%r3
	st	%r1,164(%r11)
	.loc 1 19 9
	lg	%r2,168(%r11)
	brasl	%r14,chunk_is_used@PLT
	lgr	%r1,%r2
	lr	%r2,%r1
	.loc 1 19 8
	l	%r1,164(%r11)
	cr	%r1,%r2
	je	.L13
	.loc 1 23 27
	lg	%r1,168(%r11)
	lg	%r1,8(%r1)
	.loc 1 23 21
	lcgr	%r2,%r1
	.loc 1 23 19
	lg	%r1,168(%r11)
	stg	%r2,8(%r1)
	j	.L10
.L13:
	.loc 1 20 9
	nopr	%r0
.L10:
	.loc 1 24 1
	lmg	%r11,%r15,264(%r11)
	.cfi_restore 15
	.cfi_restore 14
	.cfi_restore 13
	.cfi_restore 12
	.cfi_restore 11
	.cfi_def_cfa 15, 160
	br	%r14
	.cfi_endproc
.LFE3:
	.size	chunk_set_used, .-chunk_set_used
	.align	8
	.type	chunk_write, @function
chunk_write:
.LFB4:
	.loc 1 26 91
	.cfi_startproc
	ldgr	%f2,%r11
	.cfi_register 11, 17
	ldgr	%f0,%r15
	.cfi_register 15, 16
	lay	%r15,-192(%r15)
	.cfi_def_cfa_offset 352
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,184(%r11)
	stg	%r3,176(%r11)
	stg	%r4,168(%r11)
	lgr	%r1,%r5
	st	%r1,164(%r11)
	.loc 1 27 17
	lg	%r1,184(%r11)
	lg	%r2,176(%r11)
	stg	%r2,0(%r1)
	.loc 1 28 50
	l	%r1,164(%r11)
	ltr	%r1,%r1
	je	.L16
	.loc 1 28 30 discriminator 1
	lg	%r1,168(%r11)
	.loc 1 28 50 discriminator 1
	lcgr	%r1,%r1
	j	.L17
.L16:
	.loc 1 28 50 is_stmt 0 discriminator 2
	lg	%r1,168(%r11)
.L17:
	.loc 1 28 19 is_stmt 1 discriminator 4
	lg	%r2,184(%r11)
	stg	%r1,8(%r2)
	.loc 1 29 1 discriminator 4
	nopr	%r0
	lgdr	%r15,%f0
	.cfi_restore 15
	.cfi_def_cfa 15, 160
	lgdr	%r11,%f2
	.cfi_restore 11
	br	%r14
	.cfi_endproc
.LFE4:
	.size	chunk_write, .-chunk_write
	.align	8
	.type	chunk_to_data, @function
chunk_to_data:
.LFB5:
	.loc 1 31 58
	.cfi_startproc
	ldgr	%f2,%r11
	.cfi_register 11, 17
	ldgr	%f0,%r15
	.cfi_register 15, 16
	lay	%r15,-168(%r15)
	.cfi_def_cfa_offset 328
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,160(%r11)
	.loc 1 32 38
	lg	%r1,160(%r11)
	aghi	%r1,16
	.loc 1 33 1
	lgr	%r2,%r1
	lgdr	%r15,%f0
	.cfi_restore 15
	.cfi_def_cfa 15, 160
	lgdr	%r11,%f2
	.cfi_restore 11
	br	%r14
	.cfi_endproc
.LFE5:
	.size	chunk_to_data, .-chunk_to_data
	.align	8
	.type	chunk_from_data, @function
chunk_from_data:
.LFB6:
	.loc 1 35 49
	.cfi_startproc
	ldgr	%f2,%r11
	.cfi_register 11, 17
	ldgr	%f0,%r15
	.cfi_register 15, 16
	lay	%r15,-168(%r15)
	.cfi_def_cfa_offset 328
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,160(%r11)
	.loc 1 36 12
	lg	%r1,160(%r11)
	aghi	%r1,-16
	.loc 1 37 1
	lgr	%r2,%r1
	lgdr	%r15,%f0
	.cfi_restore 15
	.cfi_def_cfa 15, 160
	lgdr	%r11,%f2
	.cfi_restore 11
	br	%r14
	.cfi_endproc
.LFE6:
	.size	chunk_from_data, .-chunk_from_data
	.align	8
	.type	chunk_split, @function
chunk_split:
.LFB7:
	.loc 1 39 64
	.cfi_startproc
	stmg	%r11,%r15,88(%r15)
	.cfi_offset 11, -72
	.cfi_offset 12, -64
	.cfi_offset 13, -56
	.cfi_offset 14, -48
	.cfi_offset 15, -40
	lay	%r15,-192(%r15)
	.cfi_def_cfa_offset 352
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,168(%r11)
	stg	%r3,160(%r11)
	.loc 1 40 19
	lg	%r1,168(%r11)
	ag	%r1,160(%r11)
	stg	%r1,184(%r11)
	.loc 1 41 19
	lg	%r2,168(%r11)
	brasl	%r14,chunk_length@PLT
	lgr	%r1,%r2
	.loc 1 41 9
	sg	%r1,160(%r11)
	stg	%r1,176(%r11)
	.loc 1 44 5
	lg	%r1,176(%r11)
	clgfi	%r1,31
	jle	.L28
	.loc 1 48 5
	lg	%r1,168(%r11)
	lg	%r1,0(%r1)
	lghi	%r5,0
	lg	%r4,176(%r11)
	lgr	%r3,%r1
	lg	%r2,184(%r11)
	brasl	%r14,chunk_write@PLT
	.loc 1 49 5
	lg	%r2,168(%r11)
	brasl	%r14,chunk_is_used@PLT
	lgr	%r1,%r2
	lgfr	%r1,%r1
	lgr	%r5,%r1
	lg	%r4,160(%r11)
	lg	%r3,184(%r11)
	lg	%r2,168(%r11)
	brasl	%r14,chunk_write@PLT
	j	.L25
.L28:
	.loc 1 45 3
	nopr	%r0
.L25:
	.loc 1 50 1
	lmg	%r11,%r15,280(%r11)
	.cfi_restore 15
	.cfi_restore 14
	.cfi_restore 13
	.cfi_restore 12
	.cfi_restore 11
	.cfi_def_cfa 15, 160
	br	%r14
	.cfi_endproc
.LFE7:
	.size	chunk_split, .-chunk_split
	.align	8
.globl freelist_init
	.type	freelist_init, @function
freelist_init:
.LFB8:
	.loc 1 52 50
	.cfi_startproc
	stmg	%r11,%r15,88(%r15)
	.cfi_offset 11, -72
	.cfi_offset 12, -64
	.cfi_offset 13, -56
	.cfi_offset 14, -48
	.cfi_offset 15, -40
	lay	%r15,-176(%r15)
	.cfi_def_cfa_offset 336
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,168(%r11)
	stg	%r3,160(%r11)
	.loc 1 53 5
	lghi	%r5,0
	lg	%r4,160(%r11)
	lghi	%r3,0
	lg	%r2,168(%r11)
	brasl	%r14,chunk_write@PLT
	.loc 1 54 1
	nopr	%r0
	lmg	%r11,%r15,264(%r11)
	.cfi_restore 15
	.cfi_restore 14
	.cfi_restore 13
	.cfi_restore 12
	.cfi_restore 11
	.cfi_def_cfa 15, 160
	br	%r14
	.cfi_endproc
.LFE8:
	.size	freelist_init, .-freelist_init
	.align	8
.globl freelist_alloc
	.type	freelist_alloc, @function
freelist_alloc:
.LFB9:
	.loc 1 56 47
	.cfi_startproc
	stmg	%r11,%r15,88(%r15)
	.cfi_offset 11, -72
	.cfi_offset 12, -64
	.cfi_offset 13, -56
	.cfi_offset 14, -48
	.cfi_offset 15, -40
	lay	%r15,-192(%r15)
	.cfi_def_cfa_offset 352
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,168(%r11)
	stg	%r3,160(%r11)
	.loc 1 57 47
	lg	%r2,160(%r11)
	brasl	%r14,align_up@PLT
	lgr	%r1,%r2
	.loc 1 57 12
	aghi	%r1,16
	stg	%r1,184(%r11)
	.loc 1 60 8
	lg	%r1,160(%r11)
	ltgr	%r1,%r1
	jne	.L33
	.loc 1 61 16
	lghi	%r1,0
	j	.L34
.L33:
	.loc 1 65 5
	lg	%r1,184(%r11)
	clgfi	%r1,31
	jh	.L35
	.loc 1 66 13
	mvghi	184(%r11),32
.L35:
	.loc 1 70 14
	lg	%r1,168(%r11)
	stg	%r1,176(%r11)
	.loc 1 70 5
	j	.L36
.L38:
	.loc 1 71 14
	lg	%r2,176(%r11)
	brasl	%r14,chunk_is_used@PLT
	lgr	%r1,%r2
	.loc 1 71 12
	ltr	%r1,%r1
	jne	.L37
	.loc 1 71 36 discriminator 1
	lg	%r2,176(%r11)
	brasl	%r14,chunk_length@PLT
	.loc 1 71 33 discriminator 1
	lg	%r1,184(%r11)
	clgr	%r1,%r2
	jh	.L37
	.loc 1 72 13
	lg	%r3,184(%r11)
	lg	%r2,176(%r11)
	brasl	%r14,chunk_split@PLT
	.loc 1 73 13
	lghi	%r3,1
	lg	%r2,176(%r11)
	brasl	%r14,chunk_set_used@PLT
	.loc 1 75 20
	lg	%r2,176(%r11)
	brasl	%r14,chunk_to_data@PLT
	lgr	%r1,%r2
	j	.L34
.L37:
	.loc 1 70 56 discriminator 2
	lg	%r1,176(%r11)
	lg	%r1,0(%r1)
	stg	%r1,176(%r11)
.L36:
	.loc 1 70 43 discriminator 1
	lg	%r1,176(%r11)
	ltgr	%r1,%r1
	jne	.L38
	.loc 1 79 12
	lghi	%r1,0
.L34:
	.loc 1 80 1
	lgr	%r2,%r1
	lmg	%r11,%r15,280(%r11)
	.cfi_restore 15
	.cfi_restore 14
	.cfi_restore 13
	.cfi_restore 12
	.cfi_restore 11
	.cfi_def_cfa 15, 160
	br	%r14
	.cfi_endproc
.LFE9:
	.size	freelist_alloc, .-freelist_alloc
	.align	8
.globl freelist_free
	.type	freelist_free, @function
freelist_free:
.LFB10:
	.loc 1 82 43
	.cfi_startproc
	stmg	%r9,%r15,72(%r15)
	.cfi_offset 9, -88
	.cfi_offset 10, -80
	.cfi_offset 11, -72
	.cfi_offset 12, -64
	.cfi_offset 13, -56
	.cfi_offset 14, -48
	.cfi_offset 15, -40
	lay	%r15,-192(%r15)
	.cfi_def_cfa_offset 352
	lgr	%r11,%r15
	.cfi_def_cfa_register 11
	stg	%r2,168(%r11)
	stg	%r3,160(%r11)
	.loc 1 85 8
	lg	%r1,160(%r11)
	ltgr	%r1,%r1
	je	.L46
	.loc 1 90 13
	lg	%r2,160(%r11)
	brasl	%r14,chunk_from_data@PLT
	stg	%r2,184(%r11)
	.loc 1 91 5
	lghi	%r3,0
	lg	%r2,184(%r11)
	brasl	%r14,chunk_set_used@PLT
	.loc 1 92 20
	lg	%r2,184(%r11)
	brasl	%r14,chunk_length@PLT
	lgr	%r1,%r2
	.loc 1 92 5
	aghi	%r1,-16
	lgr	%r4,%r1
	lghi	%r3,0
	lg	%r2,160(%r11)
	brasl	%r14,memset@PLT
	.loc 1 95 11
	lg	%r1,168(%r11)
	stg	%r1,184(%r11)
	.loc 1 96 11
	j	.L43
.L45:
	.loc 1 97 14
	lg	%r2,184(%r11)
	brasl	%r14,chunk_is_used@PLT
	lgr	%r1,%r2
	.loc 1 97 12
	ltr	%r1,%r1
	jne	.L44
	.loc 1 97 58 discriminator 1
	lg	%r1,184(%r11)
	lg	%r1,0(%r1)
	.loc 1 97 39 discriminator 1
	lgr	%r2,%r1
	brasl	%r14,chunk_is_used@PLT
	lgr	%r1,%r2
	.loc 1 97 35 discriminator 1
	ltr	%r1,%r1
	jne	.L44
.LBB2:
	.loc 1 98 19
	lg	%r1,184(%r11)
	lg	%r1,0(%r1)
	stg	%r1,176(%r11)
	.loc 1 100 37
	lg	%r1,184(%r11)
	lg	%r1,0(%r1)
	.loc 1 100 13
	lg	%r10,0(%r1)
	.loc 1 100 51
	lg	%r2,184(%r11)
	brasl	%r14,chunk_length@PLT
	lgr	%r9,%r2
	.loc 1 100 91
	lg	%r1,184(%r11)
	lg	%r1,0(%r1)
	.loc 1 100 73
	lgr	%r2,%r1
	brasl	%r14,chunk_length@PLT
	lgr	%r1,%r2
	.loc 1 100 13
	agr	%r1,%r9
	lghi	%r5,0
	lgr	%r4,%r1
	lgr	%r3,%r10
	lg	%r2,184(%r11)
	brasl	%r14,chunk_write@PLT
	.loc 1 101 13
	lghi	%r4,16
	lghi	%r3,0
	lg	%r2,176(%r11)
	brasl	%r14,memset@PLT
.LBE2:
	.loc 1 97 67
	j	.L43
.L44:
	.loc 1 103 19
	lg	%r1,184(%r11)
	lg	%r1,0(%r1)
	stg	%r1,184(%r11)
.L43:
	.loc 1 96 26
	lg	%r1,184(%r11)
	ltgr	%r1,%r1
	je	.L40
	.loc 1 96 34 discriminator 1
	lg	%r1,184(%r11)
	lg	%r1,0(%r1)
	.loc 1 96 26 discriminator 1
	ltgr	%r1,%r1
	jne	.L45
	j	.L40
.L46:
	.loc 1 86 9
	nopr	%r0
.L40:
	.loc 1 106 1
	lmg	%r9,%r15,264(%r11)
	.cfi_restore 15
	.cfi_restore 14
	.cfi_restore 13
	.cfi_restore 12
	.cfi_restore 11
	.cfi_restore 10
	.cfi_restore 9
	.cfi_def_cfa 15, 160
	br	%r14
	.cfi_endproc
.LFE10:
	.size	freelist_free, .-freelist_free
.Letext0:
	.file 2 "/usr/lib/gcc-cross/s390x-linux-gnu/12/include/stddef.h"
	.file 3 "/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/include/allocator.h"
	.file 4 "/usr/s390x-linux-gnu/include/string.h"
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x400
	.2byte	0x4
	.4byte	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.4byte	.LASF32
	.byte	0xc
	.4byte	.LASF33
	.4byte	.LASF34
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
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x3
	.byte	0x8
	.byte	0x5
	.4byte	.LASF4
	.uleb128 0x3
	.byte	0x10
	.byte	0x4
	.4byte	.LASF5
	.uleb128 0x2
	.4byte	.LASF6
	.byte	0x3
	.byte	0x9
	.byte	0x1d
	.4byte	0x79
	.uleb128 0x5
	.4byte	0x68
	.uleb128 0x6
	.4byte	.LASF6
	.byte	0x10
	.byte	0x3
	.byte	0xb
	.byte	0x8
	.4byte	0xa1
	.uleb128 0x7
	.4byte	.LASF7
	.byte	0x3
	.byte	0xc
	.byte	0x13
	.4byte	0xa1
	.byte	0
	.uleb128 0x7
	.4byte	.LASF8
	.byte	0x3
	.byte	0xd
	.byte	0xf
	.4byte	0x2d
	.byte	0x8
	.byte	0
	.uleb128 0x8
	.byte	0x8
	.4byte	0x68
	.uleb128 0x3
	.byte	0x2
	.byte	0x7
	.4byte	.LASF9
	.uleb128 0x3
	.byte	0x1
	.byte	0x8
	.4byte	.LASF10
	.uleb128 0x9
	.4byte	.LASF35
	.byte	0x4
	.byte	0x3d
	.byte	0xe
	.4byte	0xd5
	.4byte	0xd5
	.uleb128 0xa
	.4byte	0xd5
	.uleb128 0xa
	.4byte	0x53
	.uleb128 0xa
	.4byte	0x40
	.byte	0
	.uleb128 0xb
	.byte	0x8
	.uleb128 0xc
	.4byte	.LASF16
	.byte	0x1
	.byte	0x52
	.byte	0x6
	.8byte	.LFB10
	.8byte	.LFE10-.LFB10
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x148
	.uleb128 0xd
	.4byte	.LASF11
	.byte	0x1
	.byte	0x52
	.byte	0x1a
	.4byte	0xd5
	.uleb128 0x3
	.byte	0x91
	.sleb128 -184
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x52
	.byte	0x26
	.4byte	0xd5
	.uleb128 0x3
	.byte	0x91
	.sleb128 -192
	.uleb128 0xf
	.4byte	.LASF12
	.byte	0x1
	.byte	0x53
	.byte	0x13
	.4byte	0xa1
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
	.uleb128 0x10
	.8byte	.LBB2
	.8byte	.LBE2-.LBB2
	.uleb128 0xf
	.4byte	.LASF13
	.byte	0x1
	.byte	0x62
	.byte	0x13
	.4byte	0xd5
	.uleb128 0x3
	.byte	0x91
	.sleb128 -176
	.byte	0
	.byte	0
	.uleb128 0x11
	.4byte	.LASF36
	.byte	0x1
	.byte	0x38
	.byte	0x7
	.4byte	0xd5
	.8byte	.LFB9
	.8byte	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x1ab
	.uleb128 0xd
	.4byte	.LASF11
	.byte	0x1
	.byte	0x38
	.byte	0x1c
	.4byte	0xd5
	.uleb128 0x3
	.byte	0x91
	.sleb128 -184
	.uleb128 0xd
	.4byte	.LASF14
	.byte	0x1
	.byte	0x38
	.byte	0x29
	.4byte	0x40
	.uleb128 0x3
	.byte	0x91
	.sleb128 -192
	.uleb128 0xf
	.4byte	.LASF15
	.byte	0x1
	.byte	0x39
	.byte	0xc
	.4byte	0x40
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
	.uleb128 0x12
	.string	"cur"
	.byte	0x1
	.byte	0x3a
	.byte	0x13
	.4byte	0xa1
	.uleb128 0x3
	.byte	0x91
	.sleb128 -176
	.byte	0
	.uleb128 0xc
	.4byte	.LASF17
	.byte	0x1
	.byte	0x34
	.byte	0x6
	.8byte	.LFB8
	.8byte	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x1ea
	.uleb128 0xd
	.4byte	.LASF11
	.byte	0x1
	.byte	0x34
	.byte	0x1a
	.4byte	0xd5
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
	.uleb128 0xd
	.4byte	.LASF18
	.byte	0x1
	.byte	0x34
	.byte	0x27
	.4byte	0x40
	.uleb128 0x3
	.byte	0x91
	.sleb128 -176
	.byte	0
	.uleb128 0x13
	.4byte	.LASF24
	.byte	0x1
	.byte	0x27
	.byte	0xd
	.8byte	.LFB7
	.8byte	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x249
	.uleb128 0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x27
	.byte	0x27
	.4byte	0xa1
	.uleb128 0x3
	.byte	0x91
	.sleb128 -184
	.uleb128 0xd
	.4byte	.LASF15
	.byte	0x1
	.byte	0x27
	.byte	0x35
	.4byte	0x40
	.uleb128 0x3
	.byte	0x91
	.sleb128 -192
	.uleb128 0xf
	.4byte	.LASF19
	.byte	0x1
	.byte	0x28
	.byte	0x13
	.4byte	0xa1
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
	.uleb128 0xf
	.4byte	.LASF20
	.byte	0x1
	.byte	0x29
	.byte	0x9
	.4byte	0x40
	.uleb128 0x3
	.byte	0x91
	.sleb128 -176
	.byte	0
	.uleb128 0x14
	.4byte	.LASF21
	.byte	0x1
	.byte	0x23
	.byte	0x16
	.4byte	0xa1
	.8byte	.LFB6
	.8byte	.LFE6-.LFB6
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x27c
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x23
	.byte	0x2c
	.4byte	0xd5
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
	.byte	0
	.uleb128 0x14
	.4byte	.LASF22
	.byte	0x1
	.byte	0x1f
	.byte	0x17
	.4byte	0x2af
	.8byte	.LFB5
	.8byte	.LFE5-.LFB5
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x2af
	.uleb128 0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x1f
	.byte	0x33
	.4byte	0xa1
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
	.byte	0
	.uleb128 0x8
	.byte	0x8
	.4byte	0x2b5
	.uleb128 0x3
	.byte	0x1
	.byte	0x8
	.4byte	.LASF23
	.uleb128 0x15
	.4byte	.LASF25
	.byte	0x1
	.byte	0x1a
	.byte	0xd
	.8byte	.LFB4
	.8byte	.LFE4-.LFB4
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x31b
	.uleb128 0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x1a
	.byte	0x27
	.4byte	0xa1
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
	.uleb128 0xd
	.4byte	.LASF7
	.byte	0x1
	.byte	0x1a
	.byte	0x3c
	.4byte	0xa1
	.uleb128 0x3
	.byte	0x91
	.sleb128 -176
	.uleb128 0xd
	.4byte	.LASF8
	.byte	0x1
	.byte	0x1a
	.byte	0x49
	.4byte	0x40
	.uleb128 0x3
	.byte	0x91
	.sleb128 -184
	.uleb128 0xd
	.4byte	.LASF26
	.byte	0x1
	.byte	0x1a
	.byte	0x55
	.4byte	0x53
	.uleb128 0x3
	.byte	0x91
	.sleb128 -188
	.byte	0
	.uleb128 0x13
	.4byte	.LASF27
	.byte	0x1
	.byte	0x12
	.byte	0xd
	.8byte	.LFB3
	.8byte	.LFE3-.LFB3
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x35a
	.uleb128 0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0x12
	.byte	0x2a
	.4byte	0xa1
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
	.uleb128 0xd
	.4byte	.LASF26
	.byte	0x1
	.byte	0x12
	.byte	0x35
	.4byte	0x53
	.uleb128 0x3
	.byte	0x91
	.sleb128 -172
	.byte	0
	.uleb128 0x14
	.4byte	.LASF28
	.byte	0x1
	.byte	0xe
	.byte	0xc
	.4byte	0x53
	.8byte	.LFB2
	.8byte	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x38d
	.uleb128 0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0xe
	.byte	0x2e
	.4byte	0x38d
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
	.byte	0
	.uleb128 0x8
	.byte	0x8
	.4byte	0x74
	.uleb128 0x14
	.4byte	.LASF29
	.byte	0x1
	.byte	0xa
	.byte	0xf
	.4byte	0x40
	.8byte	.LFB1
	.8byte	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x3c6
	.uleb128 0xd
	.4byte	.LASF12
	.byte	0x1
	.byte	0xa
	.byte	0x30
	.4byte	0x38d
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
	.byte	0
	.uleb128 0x16
	.4byte	.LASF30
	.byte	0x1
	.byte	0x5
	.byte	0xf
	.4byte	0x40
	.8byte	.LFB0
	.8byte	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.4byte	.LASF31
	.byte	0x1
	.byte	0x5
	.byte	0x1f
	.4byte	0x40
	.uleb128 0x3
	.byte	0x91
	.sleb128 -176
	.uleb128 0x12
	.string	"m"
	.byte	0x1
	.byte	0x6
	.byte	0xc
	.4byte	0x40
	.uleb128 0x3
	.byte	0x91
	.sleb128 -168
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
.LASF37:
	.string	"unknown"
.LASF3:
	.string	"long unsigned int"
.LASF29:
	.string	"chunk_length"
.LASF9:
	.string	"short unsigned int"
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
.LASF38:
	.string	"void"
.LASF4:
	.string	"long long int"
.LASF34:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator"
.LASF17:
	.string	"freelist_init"
.LASF32:
	.string	"GNU C17 12.2.0 -march=z196 -m64 -mzarch -gdwarf-4 -gctf -fasynchronous-unwind-tables"
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
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
