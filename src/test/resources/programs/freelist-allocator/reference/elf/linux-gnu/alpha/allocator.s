	.set noreorder
	.set volatile
	.set noat
	.set nomacro
	.section	.ctf,"",@progbits
$Lctf0:
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
	.4byte	0x10
	.4byte	0x1b
	.4byte	0x18
	.4byte	0x13
	.4byte	0x1d
	.4byte	0x15
	.4byte	0x14
	.4byte	0x1e
	.4byte	0x1a
	.4byte	0x19
	.4byte	0x11
	.4byte	0x12
	.4byte	0x8e
	.4byte	0x113
	.4byte	0xea
	.4byte	0xb2
	.4byte	0x121
	.4byte	0xcc
	.4byte	0xc0
	.4byte	0x12e
	.4byte	0x104
	.4byte	0xf8
	.4byte	0x95
	.4byte	0xa3
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
	.4byte	0x3000008
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
$Ltext0:
	.file 1 "src/allocator.c"
	.align 2
	.ent align_up
$align_up..ng:
align_up:
	.eflag 48
	.frame $15,48,$26,0
	.mask 0x4008000,-48
$LFB0:
	.loc 1 5 38
	.cfi_startproc
	lda $30,-48($30)
	.cfi_def_cfa_offset 48
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -48
	.cfi_offset 15, -40
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 0
	stq $16,32($15)
	.loc 1 6 12
	lda $1,7($31)
	stq $1,16($15)
	.loc 1 7 19
	ldq $2,32($15)
	ldq $1,16($15)
	addq $2,$1,$2
	.loc 1 7 26
	ldq $1,16($15)
	ornot $31,$1,$1
	.loc 1 7 24
	and $2,$1,$1
	.loc 1 8 1
	mov $1,$0
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,48($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE0:
	.end align_up
	.align 2
	.ent chunk_length
$chunk_length..ng:
chunk_length:
	.eflag 48
	.frame $15,32,$26,0
	.mask 0x4008000,-32
$LFB1:
	.loc 1 10 55
	.cfi_startproc
	lda $30,-32($30)
	.cfi_def_cfa_offset 32
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -32
	.cfi_offset 15, -24
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 0
	stq $16,16($15)
	.loc 1 11 47
	ldq $1,16($15)
	ldq $1,8($1)
	.loc 1 11 12
	subq $31,$1,$2
	cmovge $1,$1,$2
	mov $2,$1
	.loc 1 12 1
	mov $1,$0
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,32($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE1:
	.end chunk_length
	.align 2
	.ent chunk_is_used
$chunk_is_used..ng:
chunk_is_used:
	.eflag 48
	.frame $15,32,$26,0
	.mask 0x4008000,-32
$LFB2:
	.loc 1 14 53
	.cfi_startproc
	lda $30,-32($30)
	.cfi_def_cfa_offset 32
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -32
	.cfi_offset 15, -24
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 0
	stq $16,16($15)
	.loc 1 15 17
	ldq $1,16($15)
	ldq $1,8($1)
	.loc 1 15 26
	srl $1,63,$1
	and $1,0xff,$1
	addl $31,$1,$1
	.loc 1 16 1
	mov $1,$0
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,32($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE2:
	.end chunk_is_used
	.align 2
	.ent chunk_set_used
chunk_set_used:
	.eflag 48
	.frame $15,32,$26,0
	.mask 0x4008000,-32
$LFB3:
	.loc 1 18 59
	.cfi_startproc
	ldah $29,0($27)		!gpdisp!1
	lda $29,0($29)		!gpdisp!1
$chunk_set_used..ng:
	lda $30,-32($30)
	.cfi_def_cfa_offset 32
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -32
	.cfi_offset 15, -24
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 1
	stq $16,16($15)
	mov $17,$1
	stl $1,24($15)
	.loc 1 19 9
	ldq $16,16($15)
	ldq $27,chunk_is_used($29)		!literal!2
	jsr $26,($27),0		!lituse_jsr!2
	ldah $29,0($26)		!gpdisp!3
	lda $29,0($29)		!gpdisp!3
	mov $0,$1
	mov $1,$2
	.loc 1 19 8
	ldl $1,24($15)
	cmpeq $1,$2,$1
	bne $1,$L10
	.loc 1 23 27
	ldq $1,16($15)
	ldq $1,8($1)
	.loc 1 23 21
	subq $31,$1,$2
	.loc 1 23 19
	ldq $1,16($15)
	stq $2,8($1)
	br $31,$L7
$L10:
	.loc 1 20 9
	bis $31,$31,$31
$L7:
	.loc 1 24 1
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,32($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE3:
	.end chunk_set_used
	.align 2
	.ent chunk_write
$chunk_write..ng:
chunk_write:
	.eflag 48
	.frame $15,48,$26,0
	.mask 0x4008000,-48
$LFB4:
	.loc 1 26 91
	.cfi_startproc
	lda $30,-48($30)
	.cfi_def_cfa_offset 48
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -48
	.cfi_offset 15, -40
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 0
	stq $16,16($15)
	stq $17,24($15)
	stq $18,32($15)
	mov $19,$1
	stl $1,40($15)
	.loc 1 27 17
	ldq $1,16($15)
	ldq $2,24($15)
	stq $2,0($1)
	.loc 1 28 50
	ldl $1,40($15)
	beq $1,$L12
	.loc 1 28 30 discriminator 1
	ldq $1,32($15)
	.loc 1 28 50 discriminator 1
	subq $31,$1,$1
	br $31,$L13
$L12:
	.loc 1 28 50 is_stmt 0 discriminator 2
	ldq $1,32($15)
$L13:
	.loc 1 28 19 is_stmt 1 discriminator 4
	ldq $2,16($15)
	stq $1,8($2)
	.loc 1 29 1 discriminator 4
	bis $31,$31,$31
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,48($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE4:
	.end chunk_write
	.align 2
	.ent chunk_to_data
$chunk_to_data..ng:
chunk_to_data:
	.eflag 48
	.frame $15,32,$26,0
	.mask 0x4008000,-32
$LFB5:
	.loc 1 31 58
	.cfi_startproc
	lda $30,-32($30)
	.cfi_def_cfa_offset 32
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -32
	.cfi_offset 15, -24
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 0
	stq $16,16($15)
	.loc 1 32 38
	ldq $1,16($15)
	lda $1,16($1)
	.loc 1 33 1
	mov $1,$0
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,32($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE5:
	.end chunk_to_data
	.align 2
	.ent chunk_from_data
$chunk_from_data..ng:
chunk_from_data:
	.eflag 48
	.frame $15,32,$26,0
	.mask 0x4008000,-32
$LFB6:
	.loc 1 35 49
	.cfi_startproc
	lda $30,-32($30)
	.cfi_def_cfa_offset 32
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -32
	.cfi_offset 15, -24
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 0
	stq $16,16($15)
	.loc 1 36 12
	ldq $1,16($15)
	lda $1,-16($1)
	.loc 1 37 1
	mov $1,$0
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,32($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE6:
	.end chunk_from_data
	.align 2
	.ent chunk_split
chunk_split:
	.eflag 48
	.frame $15,48,$26,0
	.mask 0x4008000,-48
$LFB7:
	.loc 1 39 64
	.cfi_startproc
	ldah $29,0($27)		!gpdisp!4
	lda $29,0($29)		!gpdisp!4
$chunk_split..ng:
	lda $30,-48($30)
	.cfi_def_cfa_offset 48
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -48
	.cfi_offset 15, -40
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 1
	stq $16,32($15)
	stq $17,40($15)
	.loc 1 40 19
	ldq $2,32($15)
	ldq $1,40($15)
	addq $2,$1,$1
	stq $1,16($15)
	.loc 1 41 19
	ldq $16,32($15)
	ldq $27,chunk_length($29)		!literal!5
	jsr $26,($27),0		!lituse_jsr!5
	ldah $29,0($26)		!gpdisp!6
	lda $29,0($29)		!gpdisp!6
	mov $0,$1
	.loc 1 41 9
	ldq $2,40($15)
	subq $1,$2,$1
	stq $1,24($15)
	.loc 1 44 5
	ldq $1,24($15)
	cmpule $1,31,$1
	bne $1,$L21
	.loc 1 48 5
	ldq $1,32($15)
	ldq $1,0($1)
	mov $31,$19
	ldq $18,24($15)
	mov $1,$17
	ldq $16,16($15)
	ldq $27,chunk_write($29)		!literal!7
	jsr $26,($27),chunk_write		!lituse_jsr!7
	ldah $29,0($26)		!gpdisp!8
	lda $29,0($29)		!gpdisp!8
	.loc 1 49 5
	ldq $16,32($15)
	ldq $27,chunk_is_used($29)		!literal!9
	jsr $26,($27),0		!lituse_jsr!9
	ldah $29,0($26)		!gpdisp!10
	lda $29,0($29)		!gpdisp!10
	mov $0,$1
	mov $1,$19
	ldq $18,40($15)
	ldq $17,16($15)
	ldq $16,32($15)
	ldq $27,chunk_write($29)		!literal!11
	jsr $26,($27),chunk_write		!lituse_jsr!11
	ldah $29,0($26)		!gpdisp!12
	lda $29,0($29)		!gpdisp!12
	br $31,$L18
$L21:
	.loc 1 45 3
	bis $31,$31,$31
$L18:
	.loc 1 50 1
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,48($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE7:
	.end chunk_split
	.align 2
	.globl freelist_init
	.ent freelist_init
freelist_init:
	.eflag 48
	.frame $15,32,$26,0
	.mask 0x4008000,-32
$LFB8:
	.loc 1 52 50
	.cfi_startproc
	ldah $29,0($27)		!gpdisp!13
	lda $29,0($29)		!gpdisp!13
$freelist_init..ng:
	lda $30,-32($30)
	.cfi_def_cfa_offset 32
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -32
	.cfi_offset 15, -24
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 1
	stq $16,16($15)
	stq $17,24($15)
	.loc 1 53 5
	mov $31,$19
	ldq $18,24($15)
	mov $31,$17
	ldq $16,16($15)
	ldq $27,chunk_write($29)		!literal!14
	jsr $26,($27),chunk_write		!lituse_jsr!14
	ldah $29,0($26)		!gpdisp!15
	lda $29,0($29)		!gpdisp!15
	.loc 1 54 1
	bis $31,$31,$31
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,32($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE8:
	.end freelist_init
	.align 2
	.globl freelist_alloc
	.ent freelist_alloc
freelist_alloc:
	.eflag 48
	.frame $15,48,$26,0
	.mask 0x4008000,-48
$LFB9:
	.loc 1 56 47
	.cfi_startproc
	ldah $29,0($27)		!gpdisp!16
	lda $29,0($29)		!gpdisp!16
$freelist_alloc..ng:
	lda $30,-48($30)
	.cfi_def_cfa_offset 48
	stq $26,0($30)
	stq $15,8($30)
	.cfi_offset 26, -48
	.cfi_offset 15, -40
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 1
	stq $16,32($15)
	stq $17,40($15)
	.loc 1 57 47
	ldq $16,40($15)
	ldq $27,align_up($29)		!literal!17
	jsr $26,($27),0		!lituse_jsr!17
	ldah $29,0($26)		!gpdisp!18
	lda $29,0($29)		!gpdisp!18
	mov $0,$1
	.loc 1 57 12
	lda $1,16($1)
	stq $1,16($15)
	.loc 1 60 8
	ldq $1,40($15)
	bne $1,$L24
	.loc 1 61 16
	mov $31,$1
	br $31,$L25
$L24:
	.loc 1 65 5
	ldq $1,16($15)
	cmpule $1,31,$1
	beq $1,$L26
	.loc 1 66 13
	lda $1,32($31)
	stq $1,16($15)
$L26:
	.loc 1 70 14
	ldq $1,32($15)
	stq $1,24($15)
	.loc 1 70 5
	br $31,$L27
$L29:
	.loc 1 71 14
	ldq $16,24($15)
	ldq $27,chunk_is_used($29)		!literal!19
	jsr $26,($27),0		!lituse_jsr!19
	ldah $29,0($26)		!gpdisp!20
	lda $29,0($29)		!gpdisp!20
	mov $0,$1
	.loc 1 71 12
	bne $1,$L28
	.loc 1 71 36 discriminator 1
	ldq $16,24($15)
	ldq $27,chunk_length($29)		!literal!21
	jsr $26,($27),0		!lituse_jsr!21
	ldah $29,0($26)		!gpdisp!22
	lda $29,0($29)		!gpdisp!22
	mov $0,$1
	.loc 1 71 33 discriminator 1
	ldq $2,16($15)
	cmpule $2,$1,$1
	beq $1,$L28
	.loc 1 72 13
	ldq $17,16($15)
	ldq $16,24($15)
	ldq $27,chunk_split($29)		!literal!23
	jsr $26,($27),chunk_split		!lituse_jsr!23
	ldah $29,0($26)		!gpdisp!24
	lda $29,0($29)		!gpdisp!24
	.loc 1 73 13
	lda $17,1($31)
	ldq $16,24($15)
	ldq $27,chunk_set_used($29)		!literal!25
	jsr $26,($27),chunk_set_used		!lituse_jsr!25
	ldah $29,0($26)		!gpdisp!26
	lda $29,0($29)		!gpdisp!26
	.loc 1 75 20
	ldq $16,24($15)
	ldq $27,chunk_to_data($29)		!literal!27
	jsr $26,($27),0		!lituse_jsr!27
	ldah $29,0($26)		!gpdisp!28
	lda $29,0($29)		!gpdisp!28
	mov $0,$1
	br $31,$L25
$L28:
	.loc 1 70 56 discriminator 2
	ldq $1,24($15)
	ldq $1,0($1)
	stq $1,24($15)
$L27:
	.loc 1 70 43 discriminator 1
	ldq $1,24($15)
	bne $1,$L29
	.loc 1 79 12
	mov $31,$1
$L25:
	.loc 1 80 1
	mov $1,$0
	mov $15,$30
	ldq $26,0($30)
	ldq $15,8($30)
	lda $30,48($30)
	.cfi_restore 15
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE9:
	.end freelist_alloc
	.align 2
	.globl freelist_free
	.ent freelist_free
freelist_free:
	.eflag 48
	.frame $15,64,$26,0
	.mask 0x4008600,-64
$LFB10:
	.loc 1 82 43
	.cfi_startproc
	ldah $29,0($27)		!gpdisp!29
	lda $29,0($29)		!gpdisp!29
$freelist_free..ng:
	lda $30,-64($30)
	.cfi_def_cfa_offset 64
	stq $26,0($30)
	stq $9,8($30)
	stq $10,16($30)
	stq $15,24($30)
	.cfi_offset 26, -64
	.cfi_offset 9, -56
	.cfi_offset 10, -48
	.cfi_offset 15, -40
	mov $30,$15
	.cfi_def_cfa_register 15
	.prologue 1
	stq $16,48($15)
	stq $17,56($15)
	.loc 1 85 8
	ldq $1,56($15)
	beq $1,$L36
	.loc 1 90 13
	ldq $16,56($15)
	ldq $27,chunk_from_data($29)		!literal!30
	jsr $26,($27),0		!lituse_jsr!30
	ldah $29,0($26)		!gpdisp!31
	lda $29,0($29)		!gpdisp!31
	mov $0,$1
	stq $1,32($15)
	.loc 1 91 5
	mov $31,$17
	ldq $16,32($15)
	ldq $27,chunk_set_used($29)		!literal!32
	jsr $26,($27),chunk_set_used		!lituse_jsr!32
	ldah $29,0($26)		!gpdisp!33
	lda $29,0($29)		!gpdisp!33
	.loc 1 92 20
	ldq $16,32($15)
	ldq $27,chunk_length($29)		!literal!34
	jsr $26,($27),0		!lituse_jsr!34
	ldah $29,0($26)		!gpdisp!35
	lda $29,0($29)		!gpdisp!35
	mov $0,$1
	.loc 1 92 5
	lda $1,-16($1)
	mov $1,$18
	mov $31,$17
	ldq $16,56($15)
	ldq $27,memset($29)		!literal!36
	jsr $26,($27),0		!lituse_jsr!36
	ldah $29,0($26)		!gpdisp!37
	lda $29,0($29)		!gpdisp!37
	.loc 1 95 11
	ldq $1,48($15)
	stq $1,32($15)
	.loc 1 96 11
	br $31,$L33
$L35:
	.loc 1 97 14
	ldq $16,32($15)
	ldq $27,chunk_is_used($29)		!literal!38
	jsr $26,($27),0		!lituse_jsr!38
	ldah $29,0($26)		!gpdisp!39
	lda $29,0($29)		!gpdisp!39
	mov $0,$1
	.loc 1 97 12
	bne $1,$L34
	.loc 1 97 58 discriminator 1
	ldq $1,32($15)
	ldq $1,0($1)
	.loc 1 97 39 discriminator 1
	mov $1,$16
	ldq $27,chunk_is_used($29)		!literal!40
	jsr $26,($27),0		!lituse_jsr!40
	ldah $29,0($26)		!gpdisp!41
	lda $29,0($29)		!gpdisp!41
	mov $0,$1
	.loc 1 97 35 discriminator 1
	bne $1,$L34
$LBB2:
	.loc 1 98 19
	ldq $1,32($15)
	ldq $1,0($1)
	stq $1,40($15)
	.loc 1 100 37
	ldq $1,32($15)
	ldq $1,0($1)
	.loc 1 100 13
	ldq $10,0($1)
	.loc 1 100 51
	ldq $16,32($15)
	ldq $27,chunk_length($29)		!literal!42
	jsr $26,($27),0		!lituse_jsr!42
	ldah $29,0($26)		!gpdisp!43
	lda $29,0($29)		!gpdisp!43
	mov $0,$9
	.loc 1 100 91
	ldq $1,32($15)
	ldq $1,0($1)
	.loc 1 100 73
	mov $1,$16
	ldq $27,chunk_length($29)		!literal!44
	jsr $26,($27),0		!lituse_jsr!44
	ldah $29,0($26)		!gpdisp!45
	lda $29,0($29)		!gpdisp!45
	mov $0,$1
	.loc 1 100 13
	addq $9,$1,$1
	mov $31,$19
	mov $1,$18
	mov $10,$17
	ldq $16,32($15)
	ldq $27,chunk_write($29)		!literal!46
	jsr $26,($27),chunk_write		!lituse_jsr!46
	ldah $29,0($26)		!gpdisp!47
	lda $29,0($29)		!gpdisp!47
	.loc 1 101 13
	lda $18,16($31)
	mov $31,$17
	ldq $16,40($15)
	ldq $27,memset($29)		!literal!48
	jsr $26,($27),0		!lituse_jsr!48
	ldah $29,0($26)		!gpdisp!49
	lda $29,0($29)		!gpdisp!49
$LBE2:
	.loc 1 97 67
	br $31,$L33
$L34:
	.loc 1 103 19
	ldq $1,32($15)
	ldq $1,0($1)
	stq $1,32($15)
$L33:
	.loc 1 96 26
	ldq $1,32($15)
	beq $1,$L30
	.loc 1 96 34 discriminator 1
	ldq $1,32($15)
	ldq $1,0($1)
	.loc 1 96 26 discriminator 1
	bne $1,$L35
	br $31,$L30
$L36:
	.loc 1 86 9
	bis $31,$31,$31
$L30:
	.loc 1 106 1
	mov $15,$30
	ldq $26,0($30)
	ldq $9,8($30)
	ldq $10,16($30)
	ldq $15,24($30)
	lda $30,64($30)
	.cfi_restore 15
	.cfi_restore 10
	.cfi_restore 9
	.cfi_restore 26
	.cfi_def_cfa 30, 0
	ret $31,($26),1
	.cfi_endproc
$LFE10:
	.end freelist_free
$Letext0:
	.file 2 "/usr/lib/gcc-cross/alpha-linux-gnu/12/include/stddef.h"
	.file 3 "/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/include/allocator.h"
	.file 4 "/usr/alpha-linux-gnu/include/string.h"
	.section	.debug_info,"",@progbits
$Ldebug_info0:
	.4byte	0x3e6
	.2byte	0x4
	.4byte	$Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.4byte	$LASF32
	.byte	0xc
	.4byte	$LASF33
	.4byte	$LASF34
	.8byte	$Ltext0
	.8byte	$Letext0-$Ltext0
	.4byte	$Ldebug_line0
	.uleb128 0x2
	.4byte	$LASF0
	.byte	0x2
	.byte	0x91
	.byte	0x1a
	.4byte	0x39
	.uleb128 0x3
	.byte	0x8
	.byte	0x5
	.4byte	$LASF2
	.uleb128 0x2
	.4byte	$LASF1
	.byte	0x2
	.byte	0xd6
	.byte	0x17
	.4byte	0x4c
	.uleb128 0x3
	.byte	0x8
	.byte	0x7
	.4byte	$LASF3
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x3
	.byte	0x8
	.byte	0x5
	.4byte	$LASF4
	.uleb128 0x3
	.byte	0x10
	.byte	0x4
	.4byte	$LASF5
	.uleb128 0x2
	.4byte	$LASF6
	.byte	0x3
	.byte	0x9
	.byte	0x1d
	.4byte	0x79
	.uleb128 0x5
	.4byte	0x68
	.uleb128 0x6
	.4byte	$LASF6
	.byte	0x10
	.byte	0x3
	.byte	0xb
	.byte	0x8
	.4byte	0xa1
	.uleb128 0x7
	.4byte	$LASF7
	.byte	0x3
	.byte	0xc
	.byte	0x13
	.4byte	0xa1
	.byte	0
	.uleb128 0x7
	.4byte	$LASF8
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
	.4byte	$LASF9
	.uleb128 0x3
	.byte	0x1
	.byte	0x6
	.4byte	$LASF10
	.uleb128 0x9
	.4byte	$LASF35
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
	.4byte	$LASF16
	.byte	0x1
	.byte	0x52
	.byte	0x6
	.8byte	$LFB10
	.8byte	$LFE10-$LFB10
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x144
	.uleb128 0xd
	.4byte	$LASF11
	.byte	0x1
	.byte	0x52
	.byte	0x1a
	.4byte	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x52
	.byte	0x26
	.4byte	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.uleb128 0xf
	.4byte	$LASF12
	.byte	0x1
	.byte	0x53
	.byte	0x13
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0x10
	.8byte	$LBB2
	.8byte	$LBE2-$LBB2
	.uleb128 0xf
	.4byte	$LASF13
	.byte	0x1
	.byte	0x62
	.byte	0x13
	.4byte	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.byte	0
	.uleb128 0x11
	.4byte	$LASF36
	.byte	0x1
	.byte	0x38
	.byte	0x7
	.4byte	0xd5
	.8byte	$LFB9
	.8byte	$LFE9-$LFB9
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x1a3
	.uleb128 0xd
	.4byte	$LASF11
	.byte	0x1
	.byte	0x38
	.byte	0x1c
	.4byte	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0xd
	.4byte	$LASF14
	.byte	0x1
	.byte	0x38
	.byte	0x29
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.uleb128 0xf
	.4byte	$LASF15
	.byte	0x1
	.byte	0x39
	.byte	0xc
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0x12
	.string	"cur"
	.byte	0x1
	.byte	0x3a
	.byte	0x13
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0xc
	.4byte	$LASF17
	.byte	0x1
	.byte	0x34
	.byte	0x6
	.8byte	$LFB8
	.8byte	$LFE8-$LFB8
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x1e0
	.uleb128 0xd
	.4byte	$LASF11
	.byte	0x1
	.byte	0x34
	.byte	0x1a
	.4byte	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0xd
	.4byte	$LASF18
	.byte	0x1
	.byte	0x34
	.byte	0x27
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x13
	.4byte	$LASF24
	.byte	0x1
	.byte	0x27
	.byte	0xd
	.8byte	$LFB7
	.8byte	$LFE7-$LFB7
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x23b
	.uleb128 0xd
	.4byte	$LASF12
	.byte	0x1
	.byte	0x27
	.byte	0x27
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0xd
	.4byte	$LASF15
	.byte	0x1
	.byte	0x27
	.byte	0x35
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.uleb128 0xf
	.4byte	$LASF19
	.byte	0x1
	.byte	0x28
	.byte	0x13
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0xf
	.4byte	$LASF20
	.byte	0x1
	.byte	0x29
	.byte	0x9
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.byte	0
	.uleb128 0x14
	.4byte	$LASF21
	.byte	0x1
	.byte	0x23
	.byte	0x16
	.4byte	0xa1
	.8byte	$LFB6
	.8byte	$LFE6-$LFB6
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x26d
	.uleb128 0xe
	.string	"ptr"
	.byte	0x1
	.byte	0x23
	.byte	0x2c
	.4byte	0xd5
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0x14
	.4byte	$LASF22
	.byte	0x1
	.byte	0x1f
	.byte	0x17
	.4byte	0x29f
	.8byte	$LFB5
	.8byte	$LFE5-$LFB5
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x29f
	.uleb128 0xd
	.4byte	$LASF12
	.byte	0x1
	.byte	0x1f
	.byte	0x33
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0x8
	.byte	0x8
	.4byte	0x2a5
	.uleb128 0x3
	.byte	0x1
	.byte	0x8
	.4byte	$LASF23
	.uleb128 0x15
	.4byte	$LASF25
	.byte	0x1
	.byte	0x1a
	.byte	0xd
	.8byte	$LFB4
	.8byte	$LFE4-$LFB4
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x307
	.uleb128 0xd
	.4byte	$LASF12
	.byte	0x1
	.byte	0x1a
	.byte	0x27
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.uleb128 0xd
	.4byte	$LASF7
	.byte	0x1
	.byte	0x1a
	.byte	0x3c
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -24
	.uleb128 0xd
	.4byte	$LASF8
	.byte	0x1
	.byte	0x1a
	.byte	0x49
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0xd
	.4byte	$LASF26
	.byte	0x1
	.byte	0x1a
	.byte	0x55
	.4byte	0x53
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x13
	.4byte	$LASF27
	.byte	0x1
	.byte	0x12
	.byte	0xd
	.8byte	$LFB3
	.8byte	$LFE3-$LFB3
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x344
	.uleb128 0xd
	.4byte	$LASF12
	.byte	0x1
	.byte	0x12
	.byte	0x2a
	.4byte	0xa1
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0xd
	.4byte	$LASF26
	.byte	0x1
	.byte	0x12
	.byte	0x35
	.4byte	0x53
	.uleb128 0x2
	.byte	0x91
	.sleb128 -8
	.byte	0
	.uleb128 0x14
	.4byte	$LASF28
	.byte	0x1
	.byte	0xe
	.byte	0xc
	.4byte	0x53
	.8byte	$LFB2
	.8byte	$LFE2-$LFB2
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x376
	.uleb128 0xd
	.4byte	$LASF12
	.byte	0x1
	.byte	0xe
	.byte	0x2e
	.4byte	0x376
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0x8
	.byte	0x8
	.4byte	0x74
	.uleb128 0x14
	.4byte	$LASF29
	.byte	0x1
	.byte	0xa
	.byte	0xf
	.4byte	0x40
	.8byte	$LFB1
	.8byte	$LFE1-$LFB1
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x3ae
	.uleb128 0xd
	.4byte	$LASF12
	.byte	0x1
	.byte	0xa
	.byte	0x30
	.4byte	0x376
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.byte	0
	.uleb128 0x16
	.4byte	$LASF30
	.byte	0x1
	.byte	0x5
	.byte	0xf
	.4byte	0x40
	.8byte	$LFB0
	.8byte	$LFE0-$LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0xd
	.4byte	$LASF31
	.byte	0x1
	.byte	0x5
	.byte	0x1f
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0x12
	.string	"m"
	.byte	0x1
	.byte	0x6
	.byte	0xc
	.4byte	0x40
	.uleb128 0x2
	.byte	0x91
	.sleb128 -32
	.byte	0
	.byte	0
	.section	.debug_abbrev,"",@progbits
$Ldebug_abbrev0:
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
	.4byte	$Ldebug_info0
	.byte	0x8
	.byte	0
	.2byte	0
	.2byte	0
	.8byte	$Ltext0
	.8byte	$Letext0-$Ltext0
	.8byte	0
	.8byte	0
	.section	.debug_line,"",@progbits
$Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
$LASF18:
	.string	"heap_size"
$LASF1:
	.string	"size_t"
$LASF7:
	.string	"next"
$LASF31:
	.string	"value"
$LASF15:
	.string	"requested"
$LASF36:
	.string	"freelist_alloc"
$LASF16:
	.string	"freelist_free"
$LASF22:
	.string	"chunk_to_data"
$LASF32:
	.string	"GNU C17 12.2.0 -gdwarf-4 -gctf"
$LASF14:
	.string	"size"
$LASF30:
	.string	"align_up"
$LASF3:
	.string	"long unsigned int"
$LASF29:
	.string	"chunk_length"
$LASF9:
	.string	"short unsigned int"
$LASF19:
	.string	"new_chunk"
$LASF13:
	.string	"old_next"
$LASF6:
	.string	"chunk_header"
$LASF35:
	.string	"memset"
$LASF28:
	.string	"chunk_is_used"
$LASF0:
	.string	"ptrdiff_t"
$LASF20:
	.string	"new_len"
$LASF12:
	.string	"chunk"
$LASF23:
	.string	"unsigned char"
$LASF10:
	.string	"char"
$LASF11:
	.string	"heap"
$LASF37:
	.string	"void"
$LASF4:
	.string	"long long int"
$LASF34:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator"
$LASF17:
	.string	"freelist_init"
$LASF38:
	.string	"unknown"
$LASF21:
	.string	"chunk_from_data"
$LASF26:
	.string	"used"
$LASF24:
	.string	"chunk_split"
$LASF33:
	.string	"src/allocator.c"
$LASF25:
	.string	"chunk_write"
$LASF2:
	.string	"long int"
$LASF27:
	.string	"chunk_set_used"
$LASF5:
	.string	"long double"
$LASF8:
	.string	"length"
	.ident	"GCC: (Debian 12.2.0-13) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
