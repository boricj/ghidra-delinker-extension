	.section .mdebug.abi32
	.previous
	.nan	legacy
	.module	fp=xx
	.module	nooddspreg
	.module	arch=mips3
	.text
$Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "/home/boricj/Documents/ghidra/plugins/unlinker/src/test/resources/ascii-table/src/ctype.c"
	.align	2
	.globl	isalnum
$LVL0 = .
$LFB0 = .
	.loc 1 87 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	isalnum
	.type	isalnum, @function
isalnum:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 88 2 view $LVU1
	.loc 1 88 23 is_stmt 0 view $LVU2
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L3
	nop

	.loc 1 88 40 discriminator 1 view $LVU3
	andi	$4,$4,0xff
$LVL1 = .
	.loc 1 88 39 discriminator 1 view $LVU4
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 88 23 discriminator 1 view $LVU5
	andi	$2,$2,0x7
	jr	$31
	nop

$LVL2 = .
$L3:
	.loc 1 88 23 view $LVU6
	move	$2,$0
	.loc 1 89 1 view $LVU7
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	isalnum
	.cfi_endproc
$LFE0:
	.size	isalnum, .-isalnum
	.align	2
	.globl	isalpha
$LVL3 = .
$LFB1 = .
	.loc 1 92 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	isalpha
	.type	isalpha, @function
isalpha:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 93 2 view $LVU9
	.loc 1 93 23 is_stmt 0 view $LVU10
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L6
	nop

	.loc 1 93 40 discriminator 1 view $LVU11
	andi	$4,$4,0xff
$LVL4 = .
	.loc 1 93 39 discriminator 1 view $LVU12
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 93 23 discriminator 1 view $LVU13
	andi	$2,$2,0x3
	jr	$31
	nop

$LVL5 = .
$L6:
	.loc 1 93 23 view $LVU14
	move	$2,$0
	.loc 1 94 1 view $LVU15
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	isalpha
	.cfi_endproc
$LFE1:
	.size	isalpha, .-isalpha
	.align	2
	.globl	iscntrl
$LVL6 = .
$LFB2 = .
	.loc 1 97 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	iscntrl
	.type	iscntrl, @function
iscntrl:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 98 2 view $LVU17
	.loc 1 98 23 is_stmt 0 view $LVU18
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L9
	nop

	.loc 1 98 40 discriminator 1 view $LVU19
	andi	$4,$4,0xff
$LVL7 = .
	.loc 1 98 39 discriminator 1 view $LVU20
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 98 23 discriminator 1 view $LVU21
	andi	$2,$2,0x20
	jr	$31
	nop

$LVL8 = .
$L9:
	.loc 1 98 23 view $LVU22
	move	$2,$0
	.loc 1 99 1 view $LVU23
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	iscntrl
	.cfi_endproc
$LFE2:
	.size	iscntrl, .-iscntrl
	.align	2
	.globl	isdigit
$LVL9 = .
$LFB3 = .
	.loc 1 102 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	isdigit
	.type	isdigit, @function
isdigit:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 103 2 view $LVU25
	.loc 1 103 23 is_stmt 0 view $LVU26
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L12
	nop

	.loc 1 103 40 discriminator 1 view $LVU27
	andi	$4,$4,0xff
$LVL10 = .
	.loc 1 103 39 discriminator 1 view $LVU28
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 103 23 discriminator 1 view $LVU29
	andi	$2,$2,0x4
	jr	$31
	nop

$LVL11 = .
$L12:
	.loc 1 103 23 view $LVU30
	move	$2,$0
	.loc 1 104 1 view $LVU31
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	isdigit
	.cfi_endproc
$LFE3:
	.size	isdigit, .-isdigit
	.align	2
	.globl	isgraph
$LVL12 = .
$LFB4 = .
	.loc 1 107 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	isgraph
	.type	isgraph, @function
isgraph:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 108 2 view $LVU33
	.loc 1 108 23 is_stmt 0 view $LVU34
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L15
	nop

	.loc 1 108 40 discriminator 1 view $LVU35
	andi	$4,$4,0xff
$LVL13 = .
	.loc 1 108 39 discriminator 1 view $LVU36
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 108 23 discriminator 1 view $LVU37
	andi	$2,$2,0x17
	jr	$31
	nop

$LVL14 = .
$L15:
	.loc 1 108 23 view $LVU38
	move	$2,$0
	.loc 1 109 1 view $LVU39
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	isgraph
	.cfi_endproc
$LFE4:
	.size	isgraph, .-isgraph
	.align	2
	.globl	islower
$LVL15 = .
$LFB5 = .
	.loc 1 112 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	islower
	.type	islower, @function
islower:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 113 2 view $LVU41
	.loc 1 113 23 is_stmt 0 view $LVU42
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L18
	nop

	.loc 1 113 40 discriminator 1 view $LVU43
	andi	$4,$4,0xff
$LVL16 = .
	.loc 1 113 39 discriminator 1 view $LVU44
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 113 23 discriminator 1 view $LVU45
	andi	$2,$2,0x2
	jr	$31
	nop

$LVL17 = .
$L18:
	.loc 1 113 23 view $LVU46
	move	$2,$0
	.loc 1 114 1 view $LVU47
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	islower
	.cfi_endproc
$LFE5:
	.size	islower, .-islower
	.align	2
	.globl	isprint
$LVL18 = .
$LFB6 = .
	.loc 1 117 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	isprint
	.type	isprint, @function
isprint:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 118 2 view $LVU49
	.loc 1 118 23 is_stmt 0 view $LVU50
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L21
	nop

	.loc 1 118 40 discriminator 1 view $LVU51
	andi	$4,$4,0xff
$LVL19 = .
	.loc 1 118 39 discriminator 1 view $LVU52
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 118 23 discriminator 1 view $LVU53
	andi	$2,$2,0x97
	jr	$31
	nop

$LVL20 = .
$L21:
	.loc 1 118 23 view $LVU54
	move	$2,$0
	.loc 1 119 1 view $LVU55
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	isprint
	.cfi_endproc
$LFE6:
	.size	isprint, .-isprint
	.align	2
	.globl	ispunct
$LVL21 = .
$LFB7 = .
	.loc 1 122 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	ispunct
	.type	ispunct, @function
ispunct:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 123 2 view $LVU57
	.loc 1 123 23 is_stmt 0 view $LVU58
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L24
	nop

	.loc 1 123 40 discriminator 1 view $LVU59
	andi	$4,$4,0xff
$LVL22 = .
	.loc 1 123 39 discriminator 1 view $LVU60
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 123 23 discriminator 1 view $LVU61
	andi	$2,$2,0x10
	jr	$31
	nop

$LVL23 = .
$L24:
	.loc 1 123 23 view $LVU62
	move	$2,$0
	.loc 1 124 1 view $LVU63
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	ispunct
	.cfi_endproc
$LFE7:
	.size	ispunct, .-ispunct
	.align	2
	.globl	isspace
$LVL24 = .
$LFB8 = .
	.loc 1 127 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	isspace
	.type	isspace, @function
isspace:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 128 2 view $LVU65
	.loc 1 128 23 is_stmt 0 view $LVU66
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L27
	nop

	.loc 1 128 40 discriminator 1 view $LVU67
	andi	$4,$4,0xff
$LVL25 = .
	.loc 1 128 39 discriminator 1 view $LVU68
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 128 23 discriminator 1 view $LVU69
	andi	$2,$2,0x8
	jr	$31
	nop

$LVL26 = .
$L27:
	.loc 1 128 23 view $LVU70
	move	$2,$0
	.loc 1 129 1 view $LVU71
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	isspace
	.cfi_endproc
$LFE8:
	.size	isspace, .-isspace
	.align	2
	.globl	isupper
$LVL27 = .
$LFB9 = .
	.loc 1 132 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	isupper
	.type	isupper, @function
isupper:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 133 2 view $LVU73
	.loc 1 133 23 is_stmt 0 view $LVU74
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L30
	nop

	.loc 1 133 40 discriminator 1 view $LVU75
	andi	$4,$4,0xff
$LVL28 = .
	.loc 1 133 39 discriminator 1 view $LVU76
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 133 23 discriminator 1 view $LVU77
	andi	$2,$2,0x1
	jr	$31
	nop

$LVL29 = .
$L30:
	.loc 1 133 23 view $LVU78
	move	$2,$0
	.loc 1 134 1 view $LVU79
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	isupper
	.cfi_endproc
$LFE9:
	.size	isupper, .-isupper
	.align	2
	.globl	isxdigit
$LVL30 = .
$LFB10 = .
	.loc 1 137 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	isxdigit
	.type	isxdigit, @function
isxdigit:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 138 2 view $LVU81
	.loc 1 138 23 is_stmt 0 view $LVU82
	li	$2,-1			# 0xffffffffffffffff
	beq	$4,$2,$L33
	nop

	.loc 1 138 40 discriminator 1 view $LVU83
	andi	$4,$4,0xff
$LVL31 = .
	.loc 1 138 39 discriminator 1 view $LVU84
	lui	$2,%hi(_ctype_+1)
	addiu	$2,$2,%lo(_ctype_+1)
	addu	$4,$4,$2
	lb	$2,0($4)
	.loc 1 138 23 discriminator 1 view $LVU85
	andi	$2,$2,0x44
	jr	$31
	nop

$LVL32 = .
$L33:
	.loc 1 138 23 view $LVU86
	move	$2,$0
	.loc 1 139 1 view $LVU87
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	isxdigit
	.cfi_endproc
$LFE10:
	.size	isxdigit, .-isxdigit
	.globl	_ctype_
	.rdata
	.align	2
	.type	_ctype_, @object
	.size	_ctype_, 257
_ctype_:
	.ascii	"\000         (((((                  \210\020\020\020\020"
	.ascii	"\020\020\020\020\020\020\020\020\020\020\020\004\004\004"
	.ascii	"\004\004\004\004\004\004\004\020\020\020\020\020\020\020"
	.ascii	"AAAAAA\001\001\001\001\001\001\001\001\001\001\001\001\001"
	.ascii	"\001\001\001\001\001\001\001\020\020\020\020\020\020BBBB"
	.ascii	"BB\002\002\002\002\002\002\002\002\002\002\002\002\002\002"
	.ascii	"\002\002\002\002\002\002\020\020\020\020 \000\000\000\000"
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
	.ascii	"\000\000\000\000\000\000\000\000\000\000\000\000"
	.text
$Letext0:
	.section	.debug_info,"",@progbits
$Ldebug_info0:
	.4byte	0x25a
	.2byte	0x4
	.4byte	$Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	$LASF12
	.byte	0xc
	.4byte	$LASF13
	.4byte	$LASF14
	.4byte	$Ltext0
	.4byte	$Letext0-$Ltext0
	.4byte	$Ldebug_line0
	.uleb128 0x2
	.4byte	0x49
	.4byte	0x36
	.uleb128 0x3
	.4byte	0x3b
	.2byte	0x100
	.byte	0
	.uleb128 0x4
	.4byte	0x25
	.uleb128 0x5
	.byte	0x4
	.byte	0x7
	.4byte	$LASF0
	.uleb128 0x5
	.byte	0x1
	.byte	0x6
	.4byte	$LASF1
	.uleb128 0x4
	.4byte	0x42
	.uleb128 0x6
	.4byte	$LASF15
	.byte	0x1
	.byte	0x31
	.byte	0xc
	.4byte	0x36
	.uleb128 0x5
	.byte	0x3
	.4byte	_ctype_
	.uleb128 0x7
	.4byte	$LASF2
	.byte	0x1
	.byte	0x88
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB10
	.4byte	$LFE10-$LFB10
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x8e
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x88
	.byte	0x12
	.4byte	0x8e
	.4byte	$LLST10
	.4byte	$LVUS10
	.byte	0
	.uleb128 0x9
	.byte	0x4
	.byte	0x5
	.ascii	"int\000"
	.uleb128 0x7
	.4byte	$LASF3
	.byte	0x1
	.byte	0x83
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB9
	.4byte	$LFE9-$LFB9
	.uleb128 0x1
	.byte	0x9c
	.4byte	0xc3
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x83
	.byte	0x11
	.4byte	0x8e
	.4byte	$LLST9
	.4byte	$LVUS9
	.byte	0
	.uleb128 0x7
	.4byte	$LASF4
	.byte	0x1
	.byte	0x7e
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB8
	.4byte	$LFE8-$LFB8
	.uleb128 0x1
	.byte	0x9c
	.4byte	0xf1
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x7e
	.byte	0x11
	.4byte	0x8e
	.4byte	$LLST8
	.4byte	$LVUS8
	.byte	0
	.uleb128 0x7
	.4byte	$LASF5
	.byte	0x1
	.byte	0x79
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB7
	.4byte	$LFE7-$LFB7
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x11f
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x79
	.byte	0x11
	.4byte	0x8e
	.4byte	$LLST7
	.4byte	$LVUS7
	.byte	0
	.uleb128 0x7
	.4byte	$LASF6
	.byte	0x1
	.byte	0x74
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB6
	.4byte	$LFE6-$LFB6
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x14d
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x74
	.byte	0x11
	.4byte	0x8e
	.4byte	$LLST6
	.4byte	$LVUS6
	.byte	0
	.uleb128 0x7
	.4byte	$LASF7
	.byte	0x1
	.byte	0x6f
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB5
	.4byte	$LFE5-$LFB5
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x17b
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x6f
	.byte	0x11
	.4byte	0x8e
	.4byte	$LLST5
	.4byte	$LVUS5
	.byte	0
	.uleb128 0x7
	.4byte	$LASF8
	.byte	0x1
	.byte	0x6a
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB4
	.4byte	$LFE4-$LFB4
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x1a9
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x6a
	.byte	0x11
	.4byte	0x8e
	.4byte	$LLST4
	.4byte	$LVUS4
	.byte	0
	.uleb128 0x7
	.4byte	$LASF9
	.byte	0x1
	.byte	0x65
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB3
	.4byte	$LFE3-$LFB3
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x1d7
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x65
	.byte	0x11
	.4byte	0x8e
	.4byte	$LLST3
	.4byte	$LVUS3
	.byte	0
	.uleb128 0x7
	.4byte	$LASF10
	.byte	0x1
	.byte	0x60
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB2
	.4byte	$LFE2-$LFB2
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x205
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x60
	.byte	0x11
	.4byte	0x8e
	.4byte	$LLST2
	.4byte	$LVUS2
	.byte	0
	.uleb128 0x7
	.4byte	$LASF11
	.byte	0x1
	.byte	0x5b
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB1
	.4byte	$LFE1-$LFB1
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x233
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x5b
	.byte	0x11
	.4byte	0x8e
	.4byte	$LLST1
	.4byte	$LVUS1
	.byte	0
	.uleb128 0xa
	.4byte	$LASF16
	.byte	0x1
	.byte	0x56
	.byte	0x5
	.4byte	0x8e
	.4byte	$LFB0
	.4byte	$LFE0-$LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x8
	.ascii	"_c\000"
	.byte	0x1
	.byte	0x56
	.byte	0x11
	.4byte	0x8e
	.4byte	$LLST0
	.4byte	$LVUS0
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
	.uleb128 0x6
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0x5
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
	.uleb128 0x6
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
	.uleb128 0x7
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
	.uleb128 0x8
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
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x9
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
	.section	.debug_loc,"",@progbits
$Ldebug_loc0:
$LVUS10:
	.uleb128 0
	.uleb128 $LVU84
	.uleb128 $LVU84
	.uleb128 $LVU86
	.uleb128 $LVU86
	.uleb128 0
$LLST10:
	.4byte	$LVL30-$Ltext0
	.4byte	$LVL31-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL31-$Ltext0
	.4byte	$LVL32-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL32-$Ltext0
	.4byte	$LFE10-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS9:
	.uleb128 0
	.uleb128 $LVU76
	.uleb128 $LVU76
	.uleb128 $LVU78
	.uleb128 $LVU78
	.uleb128 0
$LLST9:
	.4byte	$LVL27-$Ltext0
	.4byte	$LVL28-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL28-$Ltext0
	.4byte	$LVL29-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL29-$Ltext0
	.4byte	$LFE9-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS8:
	.uleb128 0
	.uleb128 $LVU68
	.uleb128 $LVU68
	.uleb128 $LVU70
	.uleb128 $LVU70
	.uleb128 0
$LLST8:
	.4byte	$LVL24-$Ltext0
	.4byte	$LVL25-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL25-$Ltext0
	.4byte	$LVL26-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL26-$Ltext0
	.4byte	$LFE8-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS7:
	.uleb128 0
	.uleb128 $LVU60
	.uleb128 $LVU60
	.uleb128 $LVU62
	.uleb128 $LVU62
	.uleb128 0
$LLST7:
	.4byte	$LVL21-$Ltext0
	.4byte	$LVL22-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL22-$Ltext0
	.4byte	$LVL23-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL23-$Ltext0
	.4byte	$LFE7-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS6:
	.uleb128 0
	.uleb128 $LVU52
	.uleb128 $LVU52
	.uleb128 $LVU54
	.uleb128 $LVU54
	.uleb128 0
$LLST6:
	.4byte	$LVL18-$Ltext0
	.4byte	$LVL19-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL19-$Ltext0
	.4byte	$LVL20-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL20-$Ltext0
	.4byte	$LFE6-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS5:
	.uleb128 0
	.uleb128 $LVU44
	.uleb128 $LVU44
	.uleb128 $LVU46
	.uleb128 $LVU46
	.uleb128 0
$LLST5:
	.4byte	$LVL15-$Ltext0
	.4byte	$LVL16-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL16-$Ltext0
	.4byte	$LVL17-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL17-$Ltext0
	.4byte	$LFE5-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS4:
	.uleb128 0
	.uleb128 $LVU36
	.uleb128 $LVU36
	.uleb128 $LVU38
	.uleb128 $LVU38
	.uleb128 0
$LLST4:
	.4byte	$LVL12-$Ltext0
	.4byte	$LVL13-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL13-$Ltext0
	.4byte	$LVL14-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL14-$Ltext0
	.4byte	$LFE4-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS3:
	.uleb128 0
	.uleb128 $LVU28
	.uleb128 $LVU28
	.uleb128 $LVU30
	.uleb128 $LVU30
	.uleb128 0
$LLST3:
	.4byte	$LVL9-$Ltext0
	.4byte	$LVL10-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL10-$Ltext0
	.4byte	$LVL11-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL11-$Ltext0
	.4byte	$LFE3-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS2:
	.uleb128 0
	.uleb128 $LVU20
	.uleb128 $LVU20
	.uleb128 $LVU22
	.uleb128 $LVU22
	.uleb128 0
$LLST2:
	.4byte	$LVL6-$Ltext0
	.4byte	$LVL7-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL7-$Ltext0
	.4byte	$LVL8-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL8-$Ltext0
	.4byte	$LFE2-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS1:
	.uleb128 0
	.uleb128 $LVU12
	.uleb128 $LVU12
	.uleb128 $LVU14
	.uleb128 $LVU14
	.uleb128 0
$LLST1:
	.4byte	$LVL3-$Ltext0
	.4byte	$LVL4-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL4-$Ltext0
	.4byte	$LVL5-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL5-$Ltext0
	.4byte	$LFE1-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS0:
	.uleb128 0
	.uleb128 $LVU4
	.uleb128 $LVU4
	.uleb128 $LVU6
	.uleb128 $LVU6
	.uleb128 0
$LLST0:
	.4byte	$LVL0-$Ltext0
	.4byte	$LVL1-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL1-$Ltext0
	.4byte	$LVL2-$Ltext0
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	$LVL2-$Ltext0
	.4byte	$LFE0-$Ltext0
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
	.section	.debug_aranges,"",@progbits
	.4byte	0x1c
	.2byte	0x2
	.4byte	$Ldebug_info0
	.byte	0x4
	.byte	0
	.2byte	0
	.2byte	0
	.4byte	$Ltext0
	.4byte	$Letext0-$Ltext0
	.4byte	0
	.4byte	0
	.section	.debug_line,"",@progbits
$Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
$LASF14:
	.ascii	"/home/boricj/Documents/ghidra/plugins/unlinker/src/test/"
	.ascii	"resources/ascii-table/reference/freestanding\000"
$LASF0:
	.ascii	"unsigned int\000"
$LASF6:
	.ascii	"isprint\000"
$LASF15:
	.ascii	"_ctype_\000"
$LASF8:
	.ascii	"isgraph\000"
$LASF11:
	.ascii	"isalpha\000"
$LASF7:
	.ascii	"islower\000"
$LASF16:
	.ascii	"isalnum\000"
$LASF5:
	.ascii	"ispunct\000"
$LASF10:
	.ascii	"iscntrl\000"
$LASF9:
	.ascii	"isdigit\000"
$LASF13:
	.ascii	"/home/boricj/Documents/ghidra/plugins/unlinker/src/test/"
	.ascii	"resources/ascii-table/src/ctype.c\000"
$LASF2:
	.ascii	"isxdigit\000"
$LASF4:
	.ascii	"isspace\000"
$LASF12:
	.ascii	"GNU C17 12.2.0 -G 4 -mel -march=mips3 -mno-abicalls -mlo"
	.ascii	"ng-calls -mno-check-zero-division -mfpxx -mllsc -mno-lxc"
	.ascii	"1-sxc1 -mno-madd4 -mips3 -mno-shared -mabi=32 -gdwarf-4 "
	.ascii	"-Og -ffreestanding -fno-pic -fno-plt\000"
$LASF1:
	.ascii	"char\000"
$LASF3:
	.ascii	"isupper\000"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
