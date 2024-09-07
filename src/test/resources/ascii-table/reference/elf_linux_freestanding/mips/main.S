	.section .mdebug.abi32
	.previous
	.nan	legacy
	.module	fp=xx
	.module	nooddspreg
	.module	arch=mips3
	.text
$Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "/home/boricj/Documents/ghidra-delinker-extension/src/test/resources/ascii-table/src/main.c"
	.align	2
$LFB36 = .
	.file 2 "/home/boricj/Documents/linux/tools/include/nolibc/sys.h"
	.loc 2 485 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	sys_getpid
	.type	sys_getpid, @function
sys_getpid:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 2 486 2 view $LVU1
$LBB2 = .
	.loc 2 486 9 view $LVU2
	li	$2,4020			# 0xfb4
	.loc 2 486 9 view $LVU3
	.loc 2 486 9 view $LVU4
#APP
 # 486 "/home/boricj/Documents/linux/tools/include/nolibc/sys.h" 1
	addiu $sp, $sp, -32
syscall
addiu $sp, $sp, 32

 # 0 "" 2
	.loc 2 486 9 view $LVU5
#NO_APP
	beq	$7,$0,$L1
	.loc 2 486 9 is_stmt 0 discriminator 1 view $LVU6
	subu	$2,$0,$2
$L1:
$LBE2 = .
	.loc 2 487 1 view $LVU7
	jr	$31
	.end	sys_getpid
	.cfi_endproc
$LFE36:
	.size	sys_getpid, .-sys_getpid
	.align	2
$LVL0 = .
$LFB49 = .
	.loc 2 622 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	sys_kill
	.type	sys_kill, @function
sys_kill:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 2 623 2 view $LVU9
$LBB3 = .
	.loc 2 623 9 view $LVU10
	li	$2,4037			# 0xfc5
	.loc 2 623 9 view $LVU11
	.loc 2 623 9 view $LVU12
	.loc 2 623 9 view $LVU13
	.loc 2 623 9 view $LVU14
#APP
 # 623 "/home/boricj/Documents/linux/tools/include/nolibc/sys.h" 1
	addiu $sp, $sp, -32
syscall
addiu $sp, $sp, 32

 # 0 "" 2
	.loc 2 623 9 view $LVU15
#NO_APP
	beq	$7,$0,$L4
	.loc 2 623 9 is_stmt 0 discriminator 1 view $LVU16
	subu	$2,$0,$2
$L4:
$LBE3 = .
	.loc 2 624 1 view $LVU17
	jr	$31
	.end	sys_kill
	.cfi_endproc
$LFE49:
	.size	sys_kill, .-sys_kill
	.align	2
$LVL1 = .
$LFB101 = .
	.loc 2 1388 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	sys_write
	.type	sys_write, @function
sys_write:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 2 1389 2 view $LVU19
$LBB4 = .
	.loc 2 1389 9 view $LVU20
	li	$2,4004			# 0xfa4
	.loc 2 1389 9 view $LVU21
	.loc 2 1389 9 view $LVU22
	.loc 2 1389 9 view $LVU23
	.loc 2 1389 9 view $LVU24
	.loc 2 1389 9 view $LVU25
#APP
 # 1389 "/home/boricj/Documents/linux/tools/include/nolibc/sys.h" 1
	addiu $sp, $sp, -32
syscall
addiu $sp, $sp, 32

 # 0 "" 2
	.loc 2 1389 9 view $LVU26
#NO_APP
	beq	$7,$0,$L7
	.loc 2 1389 9 is_stmt 0 discriminator 1 view $LVU27
	subu	$2,$0,$2
$L7:
$LBE4 = .
	.loc 2 1390 1 view $LVU28
	jr	$31
	.end	sys_write
	.cfi_endproc
$LFE101:
	.size	sys_write, .-sys_write
	.align	2
$LVL2 = .
$LFB102 = .
	.loc 2 1394 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	write
	.type	write, @function
write:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 2 1394 1 is_stmt 0 view $LVU30
	addiu	$sp,$sp,-24
	.cfi_def_cfa_offset 24
	sw	$31,20($sp)
	.cfi_offset 31, -4
	.loc 2 1395 2 is_stmt 1 view $LVU31
	.loc 2 1395 16 is_stmt 0 view $LVU32
	lui	$2,%hi(sys_write)
	addiu	$2,$2,%lo(sys_write)
	jalr	$2
	nop

$LVL3 = .
	.loc 2 1397 2 is_stmt 1 view $LVU33
	.loc 2 1397 5 is_stmt 0 view $LVU34
	bltz	$2,$L13
	nop

$LVL4 = .
$L10:
	.loc 2 1402 1 view $LVU35
	lw	$31,20($sp)
	addiu	$sp,$sp,24
	.cfi_remember_state
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	jr	$31
	nop

$LVL5 = .
$L13:
	.cfi_restore_state
	.loc 2 1398 3 is_stmt 1 view $LVU36
	.loc 2 1398 3 view $LVU37
	subu	$2,$0,$2
$LVL6 = .
	.loc 2 1398 3 is_stmt 0 view $LVU38
	lui	$3,%hi(errno)
	sw	$2,%lo(errno)($3)
	.loc 2 1398 3 is_stmt 1 view $LVU39
	.loc 2 1399 3 view $LVU40
$LVL7 = .
	.loc 2 1399 7 is_stmt 0 view $LVU41
	li	$2,-1			# 0xffffffffffffffff
	.loc 2 1401 2 is_stmt 1 view $LVU42
	.loc 2 1401 9 is_stmt 0 view $LVU43
	b	$L10
	nop

	.set	macro
	.set	reorder
	.end	write
	.cfi_endproc
$LFE102:
	.size	write, .-write
	.align	2
$LVL8 = .
$LFB111 = .
	.file 3 "/home/boricj/Documents/linux/tools/include/nolibc/string.h"
	.loc 3 32 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	_nolibc_memcpy_up
	.type	_nolibc_memcpy_up, @function
_nolibc_memcpy_up:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 3 32 1 is_stmt 0 view $LVU45
	move	$2,$4
	.loc 3 33 2 is_stmt 1 view $LVU46
$LVL9 = .
	.loc 3 35 2 view $LVU47
	.loc 3 33 9 is_stmt 0 view $LVU48
	move	$3,$0
	.loc 3 35 8 view $LVU49
	b	$L15
	nop

$LVL10 = .
$L16:
	.loc 3 36 3 is_stmt 1 view $LVU50
	.loc 3 36 16 is_stmt 0 view $LVU51
	addu	$7,$2,$3
	.loc 3 36 43 view $LVU52
	addu	$8,$5,$3
	lb	$8,0($8)
	.loc 3 36 22 view $LVU53
	sb	$8,0($7)
	.loc 3 37 3 is_stmt 1 view $LVU54
	.loc 3 37 6 is_stmt 0 view $LVU55
	addiu	$3,$3,1
$LVL11 = .
$L15:
	.loc 3 35 13 is_stmt 1 view $LVU56
	sltu	$7,$3,$6
	bne	$7,$0,$L16
	nop

	.loc 3 39 2 view $LVU57
	.loc 3 40 1 is_stmt 0 view $LVU58
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	_nolibc_memcpy_up
	.cfi_endproc
$LFE111:
	.size	_nolibc_memcpy_up, .-_nolibc_memcpy_up
	.align	2
$LVL12 = .
$LFB155 = .
	.file 4 "/home/boricj/Documents/linux/tools/include/nolibc/stdio.h"
	.loc 4 51 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	fileno
	.type	fileno, @function
fileno:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 4 52 2 view $LVU60
	.loc 4 54 2 view $LVU61
	.loc 4 54 5 is_stmt 0 view $LVU62
	bgez	$4,$L20
	nop

	.loc 4 58 2 is_stmt 1 view $LVU63
	.loc 4 58 9 is_stmt 0 view $LVU64
	nor	$2,$0,$4
	.loc 4 59 1 view $LVU65
	jr	$31
	nop

$L20:
	.loc 4 55 3 is_stmt 1 view $LVU66
	.loc 4 55 3 view $LVU67
	lui	$2,%hi(errno)
	li	$3,9			# 0x9
	sw	$3,%lo(errno)($2)
	.loc 4 55 3 view $LVU68
	.loc 4 56 3 view $LVU69
	.loc 4 56 10 is_stmt 0 view $LVU70
	li	$2,-1			# 0xffffffffffffffff
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	fileno
	.cfi_endproc
$LFE155:
	.size	fileno, .-fileno
	.align	2
$LVL13 = .
$LFB160 = .
	.loc 4 121 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	fputc
	.type	fputc, @function
fputc:
	.frame	$sp,32,$31		# vars= 8, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 4 121 1 is_stmt 0 view $LVU72
	addiu	$sp,$sp,-32
	.cfi_def_cfa_offset 32
	sw	$31,28($sp)
	.cfi_offset 31, -4
	.loc 4 122 2 is_stmt 1 view $LVU73
	.loc 4 122 16 is_stmt 0 view $LVU74
	sb	$4,16($sp)
	.loc 4 124 2 is_stmt 1 view $LVU75
	.loc 4 124 6 is_stmt 0 view $LVU76
	move	$4,$5
$LVL14 = .
	.loc 4 124 6 view $LVU77
	lui	$2,%hi(fileno)
	addiu	$2,$2,%lo(fileno)
	jalr	$2
	nop

$LVL15 = .
	.loc 4 124 6 view $LVU78
	li	$6,1			# 0x1
	addiu	$5,$sp,16
	move	$4,$2
	lui	$2,%hi(write)
	addiu	$2,$2,%lo(write)
	jalr	$2
	nop

$LVL16 = .
	.loc 4 124 5 view $LVU79
	blez	$2,$L23
	nop

	.loc 4 126 2 is_stmt 1 view $LVU80
	.loc 4 126 9 is_stmt 0 view $LVU81
	lbu	$2,16($sp)
$L21:
	.loc 4 127 1 view $LVU82
	lw	$31,28($sp)
	addiu	$sp,$sp,32
	.cfi_remember_state
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	jr	$31
	nop

$L23:
	.cfi_restore_state
	.loc 4 125 10 view $LVU83
	li	$2,-1			# 0xffffffffffffffff
	b	$L21
	nop

	.set	macro
	.set	reorder
	.end	fputc
	.cfi_endproc
$LFE160:
	.size	fputc, .-fputc
	.align	2
$LVL17 = .
$LFB161 = .
	.loc 4 131 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	putchar
	.type	putchar, @function
putchar:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 4 131 1 is_stmt 0 view $LVU85
	addiu	$sp,$sp,-24
	.cfi_def_cfa_offset 24
	sw	$31,20($sp)
	.cfi_offset 31, -4
	.loc 4 132 2 is_stmt 1 view $LVU86
	.loc 4 132 9 is_stmt 0 view $LVU87
	li	$5,-2			# 0xfffffffffffffffe
	lui	$2,%hi(fputc)
	addiu	$2,$2,%lo(fputc)
	jalr	$2
	nop

$LVL18 = .
	.loc 4 133 1 view $LVU88
	lw	$31,20($sp)
	addiu	$sp,$sp,24
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	putchar
	.cfi_endproc
$LFE161:
	.size	putchar, .-putchar
	.align	2
	.weak	__start
$LFB0 = .
	.file 5 "/home/boricj/Documents/linux/tools/include/nolibc/arch-mips.h"
	.loc 5 186 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	__start
	.type	__start, @function
__start:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 5 187 2 view $LVU90
#APP
 # 187 "/home/boricj/Documents/linux/tools/include/nolibc/arch-mips.h" 1
	.set push
.set    noreorder
.option pic0
lw $a0,($sp)
addiu  $a1, $sp, 4
sll $a2, $a0, 2
add   $a2, $a2, $a1
addiu $a2, $a2, 4
lui $a3, %hi(environ)
addiu $a3, %lo(environ)
sw $a2,($a3)
move $t0, $a2
0:lw $a3, ($t0)
bne $a3, $0, 0b
addiu $t0, $t0, 4
lui $a3, %hi(_auxv)
addiu $a3, %lo(_auxv)
sw $t0, ($a3)
li $t0, -8
and $sp, $sp, $t0
addiu $sp,$sp,-16
lui $gp, %hi(_gp)
addiu $gp, %lo(_gp)
jal main
nop
move $a0, $v0
li $v0, 4001
syscall
.set pop

 # 0 "" 2
	.loc 5 229 2 view $LVU91
#NO_APP
	.end	__start
	.cfi_endproc
$LFE0:
	.size	__start, .-__start
	.section	.text.nolibc_raise,"ax",@progbits
	.align	2
	.weak	raise
$LVL19 = .
$LFB105 = .
	.file 6 "/home/boricj/Documents/linux/tools/include/nolibc/signal.h"
	.loc 6 18 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	raise
	.type	raise, @function
raise:
	.frame	$sp,24,$31		# vars= 0, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 6 18 1 is_stmt 0 view $LVU93
	addiu	$sp,$sp,-24
	.cfi_def_cfa_offset 24
	sw	$31,20($sp)
	sw	$16,16($sp)
	.cfi_offset 31, -4
	.cfi_offset 16, -8
	move	$16,$4
	.loc 6 19 2 is_stmt 1 view $LVU94
	.loc 6 19 9 is_stmt 0 view $LVU95
	lui	$2,%hi(sys_getpid)
	addiu	$2,$2,%lo(sys_getpid)
	jalr	$2
	nop

$LVL20 = .
	.loc 6 19 9 view $LVU96
	move	$5,$16
	move	$4,$2
	lui	$2,%hi(sys_kill)
	addiu	$2,$2,%lo(sys_kill)
	jalr	$2
	nop

$LVL21 = .
	.loc 6 20 1 view $LVU97
	lw	$31,20($sp)
	lw	$16,16($sp)
$LVL22 = .
	.loc 6 20 1 view $LVU98
	addiu	$sp,$sp,24
	.cfi_restore 16
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	raise
	.cfi_endproc
$LFE105:
	.size	raise, .-raise
	.section	.text.nolibc_memmove,"ax",@progbits
	.align	2
	.weak	memmove
$LVL23 = .
$LFB113 = .
	.loc 3 57 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	memmove
	.type	memmove, @function
memmove:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 3 57 1 is_stmt 0 view $LVU100
	move	$2,$4
	.loc 3 58 2 is_stmt 1 view $LVU101
	.loc 3 60 2 view $LVU102
$LVL24 = .
	.loc 3 61 2 view $LVU103
	.loc 3 63 2 view $LVU104
	.loc 3 63 5 is_stmt 0 view $LVU105
	sltu	$3,$4,$5
	bne	$3,$0,$L35
	nop

	.loc 3 60 6 view $LVU106
	move	$3,$6
	.loc 3 61 6 view $LVU107
	li	$4,-1			# 0xffffffffffffffff
$LVL25 = .
	.loc 3 61 6 view $LVU108
	b	$L33
	nop

$LVL26 = .
$L34:
	.loc 3 69 3 is_stmt 1 view $LVU109
	.loc 3 69 7 is_stmt 0 view $LVU110
	addu	$3,$3,$4
$LVL27 = .
	.loc 3 70 3 is_stmt 1 view $LVU111
	.loc 3 70 16 is_stmt 0 view $LVU112
	addu	$7,$2,$3
	.loc 3 70 43 view $LVU113
	addu	$8,$5,$3
	lb	$8,0($8)
	.loc 3 70 22 view $LVU114
	sb	$8,0($7)
	.loc 3 71 3 is_stmt 1 view $LVU115
	.loc 3 71 6 is_stmt 0 view $LVU116
	addiu	$6,$6,-1
$LVL28 = .
$L33:
	.loc 3 68 9 is_stmt 1 view $LVU117
	bne	$6,$0,$L34
	nop

	.loc 3 73 2 view $LVU118
	.loc 3 74 1 is_stmt 0 view $LVU119
	jr	$31
	nop

$LVL29 = .
$L35:
	.loc 3 64 7 view $LVU120
	li	$3,-1			# 0xffffffffffffffff
	.loc 3 65 7 view $LVU121
	li	$4,1			# 0x1
$LVL30 = .
	.loc 3 65 7 view $LVU122
	b	$L33
	nop

	.set	macro
	.set	reorder
	.end	memmove
	.cfi_endproc
$LFE113:
	.size	memmove, .-memmove
	.section	.text.nolibc_memcpy,"ax",@progbits
	.align	2
	.weak	memcpy
$LVL31 = .
$LFB114 = .
	.loc 3 79 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	memcpy
	.type	memcpy, @function
memcpy:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 3 79 1 is_stmt 0 view $LVU124
	addiu	$sp,$sp,-24
	.cfi_def_cfa_offset 24
	sw	$31,20($sp)
	.cfi_offset 31, -4
	.loc 3 80 2 is_stmt 1 view $LVU125
	.loc 3 80 9 is_stmt 0 view $LVU126
	lui	$2,%hi(_nolibc_memcpy_up)
	addiu	$2,$2,%lo(_nolibc_memcpy_up)
	jalr	$2
	nop

$LVL32 = .
	.loc 3 81 1 view $LVU127
	lw	$31,20($sp)
	addiu	$sp,$sp,24
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	memcpy
	.cfi_endproc
$LFE114:
	.size	memcpy, .-memcpy
	.section	.text.nolibc_memset,"ax",@progbits
	.align	2
	.weak	memset
$LVL33 = .
$LFB115 = .
	.loc 3 88 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	memset
	.type	memset, @function
memset:
	.frame	$sp,0,$31		# vars= 0, regs= 0/0, args= 0, gp= 0
	.mask	0x00000000,0
	.fmask	0x00000000,0
	.loc 3 88 1 is_stmt 0 view $LVU129
	move	$2,$4
	.loc 3 89 2 is_stmt 1 view $LVU130
$LVL34 = .
	.loc 3 91 2 view $LVU131
	.loc 3 89 8 is_stmt 0 view $LVU132
	move	$3,$4
	.loc 3 91 8 view $LVU133
	b	$L40
$LVL35 = .
$L41:
	.loc 3 93 3 is_stmt 1 view $LVU134
	.loc 3 94 3 view $LVU135
$LVL36 = .
	.loc 3 94 10 is_stmt 0 view $LVU136
	sb	$5,0($3)
	.loc 3 94 6 view $LVU137
	addiu	$3,$3,1
$LVL37 = .
	.loc 3 91 12 view $LVU138
	move	$6,$7
$LVL38 = .
$L40:
	.loc 3 91 9 is_stmt 1 view $LVU139
	.loc 3 91 12 is_stmt 0 view $LVU140
	addiu	$7,$6,-1
$LVL39 = .
	.loc 3 91 9 view $LVU141
	bne	$6,$0,$L41
	.loc 3 96 2 is_stmt 1 view $LVU142
	.loc 3 97 1 is_stmt 0 view $LVU143
	jr	$31
	.end	memset
	.cfi_endproc
$LFE115:
	.size	memset, .-memset
	.section	.text.nolibc_abort,"ax",@progbits
	.align	2
	.weak	abort
$LFB129 = .
	.file 7 "/home/boricj/Documents/linux/tools/include/nolibc/stdlib.h"
	.loc 7 35 1 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	abort
	.type	abort, @function
abort:
	.frame	$sp,24,$31		# vars= 0, regs= 1/0, args= 16, gp= 0
	.mask	0x80000000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	addiu	$sp,$sp,-24
	.cfi_def_cfa_offset 24
	sw	$31,20($sp)
	.cfi_offset 31, -4
	.loc 7 36 2 view $LVU145
	lui	$2,%hi(sys_getpid)
	addiu	$2,$2,%lo(sys_getpid)
	jalr	$2
	nop

$LVL40 = .
	li	$5,6			# 0x6
	move	$4,$2
	lui	$2,%hi(sys_kill)
	addiu	$2,$2,%lo(sys_kill)
	jalr	$2
	nop

$LVL41 = .
$L43:
	.loc 7 37 2 discriminator 1 view $LVU146
	.loc 7 37 2 discriminator 1 view $LVU147
	b	$L43
	nop

	.set	macro
	.set	reorder
	.end	abort
	.cfi_endproc
$LFE129:
	.size	abort, .-abort
	.text
	.align	2
	.globl	print_number
$LVL42 = .
$LFB172 = .
	.loc 1 25 28 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	print_number
	.type	print_number, @function
print_number:
	.frame	$sp,32,$31		# vars= 0, regs= 3/0, args= 16, gp= 0
	.mask	0x80030000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 25 28 is_stmt 0 view $LVU149
	addiu	$sp,$sp,-32
	.cfi_def_cfa_offset 32
	sw	$31,28($sp)
	sw	$17,24($sp)
	sw	$16,20($sp)
	.cfi_offset 31, -4
	.cfi_offset 17, -8
	.cfi_offset 16, -12
	move	$17,$4
	.loc 1 26 5 is_stmt 1 view $LVU150
	.loc 1 28 5 view $LVU151
$LVL43 = .
	.loc 1 28 12 is_stmt 0 view $LVU152
	li	$16,3			# 0x3
	.loc 1 28 5 view $LVU153
	b	$L46
	nop

$LVL44 = .
$L47:
$LBB5 = .
	.loc 1 34 13 is_stmt 1 view $LVU154
	addiu	$4,$4,87
$LVL45 = .
	.loc 1 34 13 is_stmt 0 view $LVU155
	lui	$2,%hi(putchar)
	addiu	$2,$2,%lo(putchar)
	jalr	$2
	nop

$LVL46 = .
$L48:
	.loc 1 34 13 view $LVU156
$LBE5 = .
	.loc 1 28 26 is_stmt 1 discriminator 2 view $LVU157
	addiu	$16,$16,-1
$LVL47 = .
$L46:
	.loc 1 28 19 discriminator 1 view $LVU158
	bltz	$16,$L51
	nop

$LBB6 = .
	.loc 1 29 9 view $LVU159
	.loc 1 29 32 is_stmt 0 view $LVU160
	sll	$2,$16,2
	.loc 1 29 26 view $LVU161
	sra	$2,$17,$2
	.loc 1 29 13 view $LVU162
	sra	$3,$2,31
	srl	$3,$3,28
	addu	$4,$2,$3
	andi	$4,$4,0xf
	subu	$4,$4,$3
$LVL48 = .
	.loc 1 31 9 is_stmt 1 view $LVU163
	.loc 1 31 12 is_stmt 0 view $LVU164
	slt	$2,$4,10
	beq	$2,$0,$L47
	nop

	.loc 1 32 13 is_stmt 1 view $LVU165
	addiu	$4,$4,48
$LVL49 = .
	.loc 1 32 13 is_stmt 0 view $LVU166
	lui	$2,%hi(putchar)
	addiu	$2,$2,%lo(putchar)
	jalr	$2
	nop

$LVL50 = .
	.loc 1 32 13 view $LVU167
	b	$L48
	nop

$LVL51 = .
$L51:
	.loc 1 32 13 view $LVU168
$LBE6 = .
	.loc 1 36 1 view $LVU169
	lw	$31,28($sp)
	lw	$17,24($sp)
$LVL52 = .
	.loc 1 36 1 view $LVU170
	lw	$16,20($sp)
$LVL53 = .
	.loc 1 36 1 view $LVU171
	addiu	$sp,$sp,32
	.cfi_restore 16
	.cfi_restore 17
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	print_number
	.cfi_endproc
$LFE172:
	.size	print_number, .-print_number
	.align	2
	.globl	print_ascii_entry
$LVL54 = .
$LFB173 = .
	.loc 1 38 101 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	print_ascii_entry
	.type	print_ascii_entry, @function
print_ascii_entry:
	.frame	$sp,40,$31		# vars= 0, regs= 6/0, args= 16, gp= 0
	.mask	0x801f0000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	.loc 1 38 101 is_stmt 0 view $LVU173
	addiu	$sp,$sp,-40
	.cfi_def_cfa_offset 40
	sw	$31,36($sp)
	sw	$20,32($sp)
	sw	$19,28($sp)
	sw	$18,24($sp)
	sw	$17,20($sp)
	sw	$16,16($sp)
	.cfi_offset 31, -4
	.cfi_offset 20, -8
	.cfi_offset 19, -12
	.cfi_offset 18, -16
	.cfi_offset 17, -20
	.cfi_offset 16, -24
	move	$18,$4
	move	$20,$5
	move	$19,$6
	.loc 1 39 5 is_stmt 1 view $LVU174
	.loc 1 41 5 view $LVU175
	lui	$2,%hi(print_number)
	addiu	$2,$2,%lo(print_number)
	jalr	$2
	nop

$LVL55 = .
	.loc 1 42 5 view $LVU176
	li	$4,32			# 0x20
	lui	$2,%hi(putchar)
	addiu	$2,$2,%lo(putchar)
	jalr	$2
	nop

$LVL56 = .
	.loc 1 44 5 view $LVU177
	.loc 1 44 9 is_stmt 0 view $LVU178
	move	$4,$18
	lui	$2,%hi(isgraph)
	addiu	$2,$2,%lo(isgraph)
	jalr	$2
	nop

$LVL57 = .
	.loc 1 44 8 view $LVU179
	beq	$2,$0,$L53
	nop

	.loc 1 45 9 is_stmt 1 view $LVU180
	move	$4,$18
	lui	$2,%hi(putchar)
	addiu	$2,$2,%lo(putchar)
	jalr	$2
	nop

$LVL58 = .
$L54:
	.loc 1 48 5 view $LVU181
	li	$4,32			# 0x20
	lui	$2,%hi(putchar)
	addiu	$2,$2,%lo(putchar)
	jalr	$2
	nop

$LVL59 = .
	.loc 1 50 5 view $LVU182
	.loc 1 50 12 is_stmt 0 view $LVU183
	move	$17,$0
	.loc 1 50 5 view $LVU184
	b	$L55
	nop

$LVL60 = .
$L53:
	.loc 1 47 9 is_stmt 1 view $LVU185
	li	$4,32			# 0x20
	lui	$2,%hi(putchar)
	addiu	$2,$2,%lo(putchar)
	jalr	$2
	nop

$LVL61 = .
	b	$L54
	nop

$LVL62 = .
$L56:
$LBB7 = .
	.loc 1 56 13 view $LVU186
	li	$4,32			# 0x20
	lui	$2,%hi(putchar)
	addiu	$2,$2,%lo(putchar)
	jalr	$2
	nop

$LVL63 = .
$L57:
$LBE7 = .
	.loc 1 50 44 discriminator 2 view $LVU187
	addiu	$17,$17,1
$LVL64 = .
$L55:
	.loc 1 50 19 discriminator 1 view $LVU188
	slt	$2,$17,$19
	beq	$2,$0,$L60
	nop

$LBB8 = .
	.loc 1 51 9 view $LVU189
	.loc 1 51 53 is_stmt 0 view $LVU190
	sll	$16,$17,3
	.loc 1 51 31 view $LVU191
	addu	$16,$20,$16
$LVL65 = .
	.loc 1 53 9 is_stmt 1 view $LVU192
	.loc 1 53 21 is_stmt 0 view $LVU193
	lw	$2,0($16)
	.loc 1 53 13 view $LVU194
	move	$4,$18
	jalr	$2
	nop

$LVL66 = .
	.loc 1 53 12 view $LVU195
	beq	$2,$0,$L56
	nop

	.loc 1 54 13 is_stmt 1 view $LVU196
	lb	$4,4($16)
	lui	$2,%hi(putchar)
	addiu	$2,$2,%lo(putchar)
	jalr	$2
	nop

$LVL67 = .
	b	$L57
	nop

$LVL68 = .
$L60:
	.loc 1 54 13 is_stmt 0 view $LVU197
$LBE8 = .
	.loc 1 58 1 view $LVU198
	lw	$31,36($sp)
	lw	$20,32($sp)
$LVL69 = .
	.loc 1 58 1 view $LVU199
	lw	$19,28($sp)
$LVL70 = .
	.loc 1 58 1 view $LVU200
	lw	$18,24($sp)
	lw	$17,20($sp)
$LVL71 = .
	.loc 1 58 1 view $LVU201
	lw	$16,16($sp)
	addiu	$sp,$sp,40
	.cfi_restore 16
	.cfi_restore 17
	.cfi_restore 18
	.cfi_restore 19
	.cfi_restore 20
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	print_ascii_entry
	.cfi_endproc
$LFE173:
	.size	print_ascii_entry, .-print_ascii_entry
	.align	2
	.globl	main
$LFB174 = .
	.loc 1 60 12 is_stmt 1 view -0
	.cfi_startproc
	.set	nomips16
	.set	nomicromips
	.ent	main
	.type	main, @function
main:
	.frame	$sp,24,$31		# vars= 0, regs= 2/0, args= 16, gp= 0
	.mask	0x80010000,-4
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	addiu	$sp,$sp,-24
	.cfi_def_cfa_offset 24
	sw	$31,20($sp)
	sw	$16,16($sp)
	.cfi_offset 31, -4
	.cfi_offset 16, -8
	.loc 1 61 5 view $LVU203
	.loc 1 63 5 view $LVU204
$LVL72 = .
	.loc 1 63 12 is_stmt 0 view $LVU205
	move	$16,$0
	.loc 1 63 5 view $LVU206
	b	$L62
	nop

$LVL73 = .
$L68:
$LBB9 = .
	.loc 1 70 9 view $LVU207
	li	$4,10			# 0xa
$L63:
	.loc 1 70 9 discriminator 4 view $LVU208
	lui	$2,%hi(putchar)
	addiu	$2,$2,%lo(putchar)
	jalr	$2
	nop

$LVL74 = .
$LBE9 = .
	.loc 1 63 27 is_stmt 1 discriminator 4 view $LVU209
	addiu	$16,$16,1
$LVL75 = .
$L62:
	.loc 1 63 19 discriminator 2 view $LVU210
	slt	$2,$16,128
	beq	$2,$0,$L67
	nop

$LBB10 = .
	.loc 1 64 9 view $LVU211
	.loc 1 64 19 is_stmt 0 view $LVU212
	lw	$3,%gp_rel(COLUMNS)($28)
	.loc 1 64 13 view $LVU213
	div	$0,$16,$3
	mfhi	$2
	mflo	$5
$LVL76 = .
	.loc 1 65 9 is_stmt 1 view $LVU214
	.loc 1 66 9 view $LVU215
	.loc 1 66 27 is_stmt 0 view $LVU216
	sll	$2,$2,7
	nop
$LVL77 = .
	.loc 1 66 33 view $LVU217
	div	$0,$2,$3
$LVL78 = .
	.loc 1 66 33 view $LVU218
	mflo	$4
	.loc 1 66 13 view $LVU219
	addu	$4,$4,$5
$LVL79 = .
	.loc 1 68 9 is_stmt 1 view $LVU220
	li	$6,10			# 0xa
	lui	$5,%hi(s_ascii_properties)
$LVL80 = .
	.loc 1 68 9 is_stmt 0 view $LVU221
	addiu	$5,$5,%lo(s_ascii_properties)
	sll	$4,$4,24
$LVL81 = .
	.loc 1 68 9 view $LVU222
	sra	$4,$4,24
	lui	$2,%hi(print_ascii_entry)
	addiu	$2,$2,%lo(print_ascii_entry)
	jalr	$2
	nop

$LVL82 = .
	.loc 1 70 9 is_stmt 1 view $LVU223
	.loc 1 70 19 is_stmt 0 view $LVU224
	lw	$2,%gp_rel(COLUMNS)($28)
	div	$0,$16,$2
	mfhi	$3
	.loc 1 70 40 view $LVU225
	addiu	$2,$2,-1
	.loc 1 70 9 view $LVU226
	beq	$3,$2,$L68
	nop

	li	$4,9			# 0x9
	b	$L63
	nop

$LVL83 = .
$L67:
	.loc 1 70 9 view $LVU227
$LBE10 = .
	.loc 1 73 5 is_stmt 1 view $LVU228
	.loc 1 74 1 is_stmt 0 view $LVU229
	move	$2,$0
	lw	$31,20($sp)
	lw	$16,16($sp)
$LVL84 = .
	.loc 1 74 1 view $LVU230
	addiu	$sp,$sp,24
	.cfi_restore 16
	.cfi_restore 31
	.cfi_def_cfa_offset 0
	jr	$31
	nop

	.set	macro
	.set	reorder
	.end	main
	.cfi_endproc
$LFE174:
	.size	main, .-main
	.globl	COLUMNS
	.section	.sdata,"aw"
	.align	2
	.type	COLUMNS, @object
	.size	COLUMNS, 4
COLUMNS:
	.word	4
	.globl	s_ascii_properties
	.rdata
	.align	2
	.type	s_ascii_properties, @object
	.size	s_ascii_properties, 80
s_ascii_properties:
	.word	isgraph
	.byte	103
	.space	3
	.word	isprint
	.byte	112
	.space	3
	.word	iscntrl
	.byte	99
	.space	3
	.word	isspace
	.byte	115
	.space	3
	.word	ispunct
	.byte	33
	.space	3
	.word	isalnum
	.byte	65
	.space	3
	.word	isalpha
	.byte	97
	.space	3
	.word	isdigit
	.byte	100
	.space	3
	.word	isupper
	.byte	85
	.space	3
	.word	islower
	.byte	108
	.space	3
	.globl	NUM_ASCII_PROPERTIES
	.section	.sdata
	.align	2
	.type	NUM_ASCII_PROPERTIES, @object
	.size	NUM_ASCII_PROPERTIES, 4
NUM_ASCII_PROPERTIES:
	.word	10
	.weak	errno
	.section	.sbss,"aw",@nobits
	.align	2
	.type	errno, @object
	.size	errno, 4
errno:
	.space	4
	.weak	_auxv
	.align	2
	.type	_auxv, @object
	.size	_auxv, 4
_auxv:
	.space	4
	.weak	environ
	.align	2
	.type	environ, @object
	.size	environ, 4
environ:
	.space	4
	.text
$Letext0:
	.file 8 "/home/boricj/Documents/linux/tools/include/nolibc/stdint.h"
	.file 9 "/home/boricj/Documents/linux/tools/include/nolibc/std.h"
	.file 10 "/home/boricj/Documents/linux/tools/include/nolibc/errno.h"
	.file 11 "../../include/ctype.h"
	.section	.debug_info,"",@progbits
$Ldebug_info0:
	.4byte	0xa8b
	.2byte	0x4
	.4byte	$Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	$LASF67
	.byte	0xc
	.4byte	$LASF68
	.4byte	$LASF69
	.4byte	$Ldebug_ranges0+0x48
	.4byte	0
	.4byte	$Ldebug_line0
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	$LASF0
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	$LASF1
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.4byte	$LASF2
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.4byte	$LASF3
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	$LASF4
	.uleb128 0x3
	.byte	0x4
	.byte	0x5
	.ascii	"int\000"
	.uleb128 0x4
	.4byte	0x48
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	$LASF5
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	$LASF6
	.uleb128 0x5
	.4byte	$LASF8
	.byte	0x8
	.byte	0x12
	.byte	0x1e
	.4byte	0x6e
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	$LASF7
	.uleb128 0x4
	.4byte	0x6e
	.uleb128 0x5
	.4byte	$LASF9
	.byte	0x8
	.byte	0x13
	.byte	0x1d
	.4byte	0x86
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.4byte	$LASF10
	.uleb128 0x5
	.4byte	$LASF11
	.byte	0x8
	.byte	0x15
	.byte	0x1c
	.4byte	0x86
	.uleb128 0x5
	.4byte	$LASF12
	.byte	0x9
	.byte	0x1b
	.byte	0x1f
	.4byte	0x48
	.uleb128 0x6
	.4byte	$LASF14
	.byte	0x5
	.byte	0xb5
	.byte	0x8
	.4byte	0xb7
	.uleb128 0x5
	.byte	0x3
	.4byte	environ
	.uleb128 0x7
	.byte	0x4
	.4byte	0xbd
	.uleb128 0x7
	.byte	0x4
	.4byte	0xc3
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	$LASF13
	.uleb128 0x6
	.4byte	$LASF15
	.byte	0x5
	.byte	0xb6
	.byte	0x16
	.4byte	0xdc
	.uleb128 0x5
	.byte	0x3
	.4byte	_auxv
	.uleb128 0x7
	.byte	0x4
	.4byte	0x75
	.uleb128 0x6
	.4byte	$LASF16
	.byte	0xa
	.byte	0xe
	.byte	0x5
	.4byte	0x48
	.uleb128 0x5
	.byte	0x3
	.4byte	errno
	.uleb128 0x8
	.byte	0x4
	.uleb128 0x9
	.4byte	0xc3
	.4byte	0x106
	.uleb128 0xa
	.4byte	0x41
	.byte	0x14
	.byte	0
	.uleb128 0xb
	.4byte	$LASF70
	.byte	0x7
	.byte	0x1a
	.byte	0x25
	.4byte	0xf6
	.uleb128 0xc
	.4byte	$LASF17
	.byte	0x1
	.byte	0x4
	.byte	0x1d
	.byte	0x10
	.4byte	0x12d
	.uleb128 0xd
	.4byte	$LASF21
	.byte	0x4
	.byte	0x1e
	.byte	0x7
	.4byte	0x12d
	.byte	0
	.byte	0
	.uleb128 0x9
	.4byte	0xc3
	.4byte	0x13d
	.uleb128 0xa
	.4byte	0x41
	.byte	0
	.byte	0
	.uleb128 0x5
	.4byte	$LASF17
	.byte	0x4
	.byte	0x1f
	.byte	0x3
	.4byte	0x112
	.uleb128 0xe
	.4byte	$LASF18
	.byte	0x4
	.byte	0x21
	.byte	0x2c
	.4byte	0x15f
	.4byte	0xffffffff
	.uleb128 0x7
	.byte	0x4
	.4byte	0x13d
	.uleb128 0x4
	.4byte	0x159
	.uleb128 0xe
	.4byte	$LASF19
	.byte	0x4
	.byte	0x22
	.byte	0x2c
	.4byte	0x15f
	.4byte	0xfffffffe
	.uleb128 0xe
	.4byte	$LASF20
	.byte	0x4
	.byte	0x23
	.byte	0x2c
	.4byte	0x15f
	.4byte	0xfffffffd
	.uleb128 0xf
	.byte	0x8
	.byte	0x1
	.byte	0x4
	.byte	0x9
	.4byte	0x1a8
	.uleb128 0xd
	.4byte	$LASF22
	.byte	0x1
	.byte	0x5
	.byte	0xb
	.4byte	0x1b7
	.byte	0
	.uleb128 0xd
	.4byte	$LASF23
	.byte	0x1
	.byte	0x6
	.byte	0xa
	.4byte	0xc3
	.byte	0x4
	.byte	0
	.uleb128 0x10
	.4byte	0x48
	.4byte	0x1b7
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x7
	.byte	0x4
	.4byte	0x1a8
	.uleb128 0x5
	.4byte	$LASF24
	.byte	0x1
	.byte	0x7
	.byte	0x3
	.4byte	0x184
	.uleb128 0x4
	.4byte	0x1bd
	.uleb128 0x6
	.4byte	$LASF25
	.byte	0x1
	.byte	0x9
	.byte	0xb
	.4byte	0x4f
	.uleb128 0x5
	.byte	0x3
	.4byte	NUM_ASCII_PROPERTIES
	.uleb128 0x9
	.4byte	0x1c9
	.4byte	0x1f0
	.uleb128 0xa
	.4byte	0x41
	.byte	0x9
	.byte	0
	.uleb128 0x4
	.4byte	0x1e0
	.uleb128 0x6
	.4byte	$LASF26
	.byte	0x1
	.byte	0xa
	.byte	0x16
	.4byte	0x1f0
	.uleb128 0x5
	.byte	0x3
	.4byte	s_ascii_properties
	.uleb128 0x6
	.4byte	$LASF27
	.byte	0x1
	.byte	0x17
	.byte	0x5
	.4byte	0x48
	.uleb128 0x5
	.byte	0x3
	.4byte	COLUMNS
	.uleb128 0x12
	.4byte	$LASF28
	.byte	0xb
	.byte	0x8
	.byte	0xc
	.4byte	0x48
	.4byte	0x22f
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x12
	.4byte	$LASF29
	.byte	0xb
	.byte	0xc
	.byte	0xc
	.4byte	0x48
	.4byte	0x245
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x12
	.4byte	$LASF30
	.byte	0xb
	.byte	0x6
	.byte	0xc
	.4byte	0x48
	.4byte	0x25b
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x12
	.4byte	$LASF31
	.byte	0xb
	.byte	0x4
	.byte	0xc
	.4byte	0x48
	.4byte	0x271
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x12
	.4byte	$LASF32
	.byte	0xb
	.byte	0x3
	.byte	0xc
	.4byte	0x48
	.4byte	0x287
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x12
	.4byte	$LASF33
	.byte	0xb
	.byte	0xa
	.byte	0xc
	.4byte	0x48
	.4byte	0x29d
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x12
	.4byte	$LASF34
	.byte	0xb
	.byte	0xb
	.byte	0xc
	.4byte	0x48
	.4byte	0x2b3
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x12
	.4byte	$LASF35
	.byte	0xb
	.byte	0x5
	.byte	0xc
	.4byte	0x48
	.4byte	0x2c9
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x12
	.4byte	$LASF36
	.byte	0xb
	.byte	0x9
	.byte	0xc
	.4byte	0x48
	.4byte	0x2df
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x12
	.4byte	$LASF37
	.byte	0xb
	.byte	0x7
	.byte	0xc
	.4byte	0x48
	.4byte	0x2f5
	.uleb128 0x11
	.4byte	0x48
	.byte	0
	.uleb128 0x13
	.4byte	$LASF39
	.byte	0x1
	.byte	0x3c
	.byte	0x5
	.4byte	0x48
	.4byte	$LFB174
	.4byte	$LFE174-$LFB174
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x381
	.uleb128 0x14
	.ascii	"i\000"
	.byte	0x1
	.byte	0x3d
	.byte	0x9
	.4byte	0x48
	.4byte	$LLST29
	.4byte	$LVUS29
	.uleb128 0x15
	.4byte	$Ldebug_ranges0+0x30
	.uleb128 0x14
	.ascii	"x\000"
	.byte	0x1
	.byte	0x40
	.byte	0xd
	.4byte	0x48
	.4byte	$LLST30
	.4byte	$LVUS30
	.uleb128 0x14
	.ascii	"y\000"
	.byte	0x1
	.byte	0x41
	.byte	0xd
	.4byte	0x48
	.4byte	$LLST31
	.4byte	$LVUS31
	.uleb128 0x16
	.4byte	$LASF38
	.byte	0x1
	.byte	0x42
	.byte	0xd
	.4byte	0x48
	.4byte	$LLST32
	.4byte	$LVUS32
	.uleb128 0x17
	.4byte	$LVL74
	.4byte	0x568
	.uleb128 0x18
	.4byte	$LVL82
	.4byte	0x381
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x5
	.byte	0x3
	.4byte	s_ascii_properties
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x56
	.uleb128 0x1
	.byte	0x3a
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x1a
	.4byte	$LASF40
	.byte	0x1
	.byte	0x26
	.byte	0x6
	.4byte	$LFB173
	.4byte	$LFE173-$LFB173
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x4a5
	.uleb128 0x1b
	.4byte	$LASF38
	.byte	0x1
	.byte	0x26
	.byte	0x1d
	.4byte	0xc3
	.4byte	$LLST24
	.4byte	$LVUS24
	.uleb128 0x1b
	.4byte	$LASF41
	.byte	0x1
	.byte	0x26
	.byte	0x3d
	.4byte	0x4a5
	.4byte	$LLST25
	.4byte	$LVUS25
	.uleb128 0x1b
	.4byte	$LASF42
	.byte	0x1
	.byte	0x26
	.byte	0x4f
	.4byte	0x48
	.4byte	$LLST26
	.4byte	$LVUS26
	.uleb128 0x14
	.ascii	"k\000"
	.byte	0x1
	.byte	0x27
	.byte	0x9
	.4byte	0x48
	.4byte	$LLST27
	.4byte	$LVUS27
	.uleb128 0x1c
	.4byte	$Ldebug_ranges0+0x18
	.4byte	0x430
	.uleb128 0x16
	.4byte	$LASF43
	.byte	0x1
	.byte	0x33
	.byte	0x1f
	.4byte	0x4a5
	.4byte	$LLST28
	.4byte	$LVUS28
	.uleb128 0x1d
	.4byte	$LVL63
	.4byte	0x568
	.4byte	0x416
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x8
	.byte	0x20
	.byte	0
	.uleb128 0x1e
	.4byte	$LVL66
	.4byte	0x426
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x82
	.sleb128 0
	.byte	0
	.uleb128 0x17
	.4byte	$LVL67
	.4byte	0x568
	.byte	0
	.uleb128 0x1d
	.4byte	$LVL55
	.4byte	0x4ab
	.4byte	0x444
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x82
	.sleb128 0
	.byte	0
	.uleb128 0x1d
	.4byte	$LVL56
	.4byte	0x568
	.4byte	0x458
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x8
	.byte	0x20
	.byte	0
	.uleb128 0x1d
	.4byte	$LVL57
	.4byte	0x2df
	.4byte	0x46c
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x82
	.sleb128 0
	.byte	0
	.uleb128 0x1d
	.4byte	$LVL58
	.4byte	0x568
	.4byte	0x480
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x82
	.sleb128 0
	.byte	0
	.uleb128 0x1d
	.4byte	$LVL59
	.4byte	0x568
	.4byte	0x494
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x8
	.byte	0x20
	.byte	0
	.uleb128 0x18
	.4byte	$LVL61
	.4byte	0x568
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2
	.byte	0x8
	.byte	0x20
	.byte	0
	.byte	0
	.uleb128 0x7
	.byte	0x4
	.4byte	0x1c9
	.uleb128 0x1a
	.4byte	$LASF44
	.byte	0x1
	.byte	0x19
	.byte	0x6
	.4byte	$LFB172
	.4byte	$LFE172-$LFB172
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x568
	.uleb128 0x1f
	.ascii	"num\000"
	.byte	0x1
	.byte	0x19
	.byte	0x17
	.4byte	0x48
	.4byte	$LLST21
	.4byte	$LVUS21
	.uleb128 0x14
	.ascii	"n\000"
	.byte	0x1
	.byte	0x1a
	.byte	0x9
	.4byte	0x48
	.4byte	$LLST22
	.4byte	$LVUS22
	.uleb128 0x15
	.4byte	$Ldebug_ranges0+0
	.uleb128 0x16
	.4byte	$LASF45
	.byte	0x1
	.byte	0x1d
	.byte	0xd
	.4byte	0x48
	.4byte	$LLST23
	.4byte	$LVUS23
	.uleb128 0x1d
	.4byte	$LVL46
	.4byte	0x568
	.4byte	0x535
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x23
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x22
	.byte	0x3f
	.byte	0x1a
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x1c
	.byte	0x23
	.uleb128 0x57
	.byte	0
	.uleb128 0x18
	.4byte	$LVL50
	.4byte	0x568
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x23
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x22
	.byte	0x3f
	.byte	0x1a
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x1c
	.byte	0x23
	.uleb128 0x30
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x20
	.4byte	$LASF46
	.byte	0x4
	.byte	0x82
	.byte	0x5
	.4byte	0x48
	.4byte	$LFB161
	.4byte	$LFE161-$LFB161
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x5ac
	.uleb128 0x1f
	.ascii	"c\000"
	.byte	0x4
	.byte	0x82
	.byte	0x11
	.4byte	0x48
	.4byte	$LLST9
	.4byte	$LVUS9
	.uleb128 0x18
	.4byte	$LVL18
	.4byte	0x5ac
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x9
	.byte	0xfe
	.byte	0
	.byte	0
	.uleb128 0x20
	.4byte	$LASF47
	.byte	0x4
	.byte	0x78
	.byte	0x5
	.4byte	0x48
	.4byte	$LFB160
	.4byte	$LFE160-$LFB160
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x625
	.uleb128 0x1f
	.ascii	"c\000"
	.byte	0x4
	.byte	0x78
	.byte	0xf
	.4byte	0x48
	.4byte	$LLST7
	.4byte	$LVUS7
	.uleb128 0x1b
	.4byte	$LASF48
	.byte	0x4
	.byte	0x78
	.byte	0x18
	.4byte	0x159
	.4byte	$LLST8
	.4byte	$LVUS8
	.uleb128 0x21
	.ascii	"ch\000"
	.byte	0x4
	.byte	0x7a
	.byte	0x10
	.4byte	0x25
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0x1d
	.4byte	$LVL15
	.4byte	0x625
	.4byte	0x60f
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0
	.uleb128 0x18
	.4byte	$LVL16
	.4byte	0x88d
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x91
	.sleb128 -16
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x56
	.uleb128 0x1
	.byte	0x31
	.byte	0
	.byte	0
	.uleb128 0x20
	.4byte	$LASF49
	.byte	0x4
	.byte	0x32
	.byte	0x5
	.4byte	0x48
	.4byte	$LFB155
	.4byte	$LFE155-$LFB155
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x660
	.uleb128 0x22
	.4byte	$LASF48
	.byte	0x4
	.byte	0x32
	.byte	0x12
	.4byte	0x159
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x14
	.ascii	"i\000"
	.byte	0x4
	.byte	0x34
	.byte	0xb
	.4byte	0x8d
	.4byte	$LLST6
	.4byte	$LVUS6
	.byte	0
	.uleb128 0x23
	.4byte	$LASF50
	.byte	0x7
	.byte	0x22
	.byte	0x6
	.4byte	$LFB129
	.4byte	$LFE129-$LFB129
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x68f
	.uleb128 0x17
	.4byte	$LVL40
	.4byte	0xa38
	.uleb128 0x18
	.4byte	$LVL41
	.4byte	0x9b8
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x1
	.byte	0x36
	.byte	0
	.byte	0
	.uleb128 0x24
	.4byte	$LASF51
	.byte	0x3
	.byte	0x57
	.byte	0x7
	.4byte	0xf4
	.4byte	$LFB115
	.4byte	$LFE115-$LFB115
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x6f0
	.uleb128 0x1f
	.ascii	"dst\000"
	.byte	0x3
	.byte	0x57
	.byte	0x14
	.4byte	0xf4
	.4byte	$LLST18
	.4byte	$LVUS18
	.uleb128 0x25
	.ascii	"b\000"
	.byte	0x3
	.byte	0x57
	.byte	0x1d
	.4byte	0x48
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x1f
	.ascii	"len\000"
	.byte	0x3
	.byte	0x57
	.byte	0x27
	.4byte	0x62
	.4byte	$LLST19
	.4byte	$LVUS19
	.uleb128 0x14
	.ascii	"p\000"
	.byte	0x3
	.byte	0x59
	.byte	0x8
	.4byte	0xbd
	.4byte	$LLST20
	.4byte	$LVUS20
	.byte	0
	.uleb128 0x24
	.4byte	$LASF52
	.byte	0x3
	.byte	0x4e
	.byte	0x7
	.4byte	0xf4
	.4byte	$LFB114
	.4byte	$LFE114-$LFB114
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x766
	.uleb128 0x1f
	.ascii	"dst\000"
	.byte	0x3
	.byte	0x4e
	.byte	0x14
	.4byte	0xf4
	.4byte	$LLST15
	.4byte	$LVUS15
	.uleb128 0x1f
	.ascii	"src\000"
	.byte	0x3
	.byte	0x4e
	.byte	0x25
	.4byte	0x766
	.4byte	$LLST16
	.4byte	$LVUS16
	.uleb128 0x1f
	.ascii	"len\000"
	.byte	0x3
	.byte	0x4e
	.byte	0x31
	.4byte	0x62
	.4byte	$LLST17
	.4byte	$LVUS17
	.uleb128 0x18
	.4byte	$LVL32
	.4byte	0x7e6
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x56
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x56
	.byte	0
	.byte	0
	.uleb128 0x7
	.byte	0x4
	.4byte	0x76c
	.uleb128 0x26
	.uleb128 0x24
	.4byte	$LASF53
	.byte	0x3
	.byte	0x38
	.byte	0x7
	.4byte	0xf4
	.4byte	$LFB113
	.4byte	$LFE113-$LFB113
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x7e6
	.uleb128 0x1f
	.ascii	"dst\000"
	.byte	0x3
	.byte	0x38
	.byte	0x15
	.4byte	0xf4
	.4byte	$LLST11
	.4byte	$LVUS11
	.uleb128 0x25
	.ascii	"src\000"
	.byte	0x3
	.byte	0x38
	.byte	0x26
	.4byte	0x766
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x1f
	.ascii	"len\000"
	.byte	0x3
	.byte	0x38
	.byte	0x32
	.4byte	0x62
	.4byte	$LLST12
	.4byte	$LVUS12
	.uleb128 0x14
	.ascii	"dir\000"
	.byte	0x3
	.byte	0x3a
	.byte	0x9
	.4byte	0x62
	.4byte	$LLST13
	.4byte	$LVUS13
	.uleb128 0x14
	.ascii	"pos\000"
	.byte	0x3
	.byte	0x3a
	.byte	0xe
	.4byte	0x62
	.4byte	$LLST14
	.4byte	$LVUS14
	.byte	0
	.uleb128 0x20
	.4byte	$LASF54
	.byte	0x3
	.byte	0x1f
	.byte	0x7
	.4byte	0xf4
	.4byte	$LFB111
	.4byte	$LFE111-$LFB111
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x845
	.uleb128 0x1f
	.ascii	"dst\000"
	.byte	0x3
	.byte	0x1f
	.byte	0x1f
	.4byte	0xf4
	.4byte	$LLST4
	.4byte	$LVUS4
	.uleb128 0x25
	.ascii	"src\000"
	.byte	0x3
	.byte	0x1f
	.byte	0x30
	.4byte	0x766
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x25
	.ascii	"len\000"
	.byte	0x3
	.byte	0x1f
	.byte	0x3c
	.4byte	0x62
	.uleb128 0x1
	.byte	0x56
	.uleb128 0x14
	.ascii	"pos\000"
	.byte	0x3
	.byte	0x21
	.byte	0x9
	.4byte	0x62
	.4byte	$LLST5
	.4byte	$LVUS5
	.byte	0
	.uleb128 0x24
	.4byte	$LASF55
	.byte	0x6
	.byte	0x11
	.byte	0x5
	.4byte	0x48
	.4byte	$LFB105
	.4byte	$LFE105-$LFB105
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x88d
	.uleb128 0x1b
	.4byte	$LASF56
	.byte	0x6
	.byte	0x11
	.byte	0xf
	.4byte	0x48
	.4byte	$LLST10
	.4byte	$LVUS10
	.uleb128 0x17
	.4byte	$LVL20
	.4byte	0xa38
	.uleb128 0x18
	.4byte	$LVL21
	.4byte	0x9b8
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2
	.byte	0x80
	.sleb128 0
	.byte	0
	.byte	0
	.uleb128 0x27
	.4byte	$LASF57
	.byte	0x2
	.2byte	0x571
	.byte	0x9
	.4byte	0x7a
	.4byte	$LFB102
	.4byte	$LFE102-$LFB102
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x91b
	.uleb128 0x28
	.ascii	"fd\000"
	.byte	0x2
	.2byte	0x571
	.byte	0x13
	.4byte	0x48
	.4byte	$LLST0
	.4byte	$LVUS0
	.uleb128 0x28
	.ascii	"buf\000"
	.byte	0x2
	.2byte	0x571
	.byte	0x23
	.4byte	0x766
	.4byte	$LLST1
	.4byte	$LVUS1
	.uleb128 0x29
	.4byte	$LASF58
	.byte	0x2
	.2byte	0x571
	.byte	0x2f
	.4byte	0x62
	.4byte	$LLST2
	.4byte	$LVUS2
	.uleb128 0x2a
	.ascii	"ret\000"
	.byte	0x2
	.2byte	0x573
	.byte	0xa
	.4byte	0x7a
	.4byte	$LLST3
	.4byte	$LVUS3
	.uleb128 0x18
	.4byte	$LVL3
	.4byte	0x91b
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x19
	.uleb128 0x1
	.byte	0x56
	.uleb128 0x3
	.byte	0xf3
	.uleb128 0x1
	.byte	0x56
	.byte	0
	.byte	0
	.uleb128 0x27
	.4byte	$LASF59
	.byte	0x2
	.2byte	0x56b
	.byte	0x9
	.4byte	0x7a
	.4byte	$LFB101
	.4byte	$LFE101-$LFB101
	.uleb128 0x1
	.byte	0x9c
	.4byte	0x9b8
	.uleb128 0x2b
	.ascii	"fd\000"
	.byte	0x2
	.2byte	0x56b
	.byte	0x17
	.4byte	0x48
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2b
	.ascii	"buf\000"
	.byte	0x2
	.2byte	0x56b
	.byte	0x27
	.4byte	0x766
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2c
	.4byte	$LASF58
	.byte	0x2
	.2byte	0x56b
	.byte	0x33
	.4byte	0x62
	.uleb128 0x1
	.byte	0x56
	.uleb128 0x2d
	.4byte	$LBB4
	.4byte	$LBE4-$LBB4
	.uleb128 0x2e
	.4byte	$LASF60
	.byte	0x2
	.2byte	0x56d
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x52
	.uleb128 0x2e
	.4byte	$LASF61
	.byte	0x2
	.2byte	0x56d
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2e
	.4byte	$LASF62
	.byte	0x2
	.2byte	0x56d
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2e
	.4byte	$LASF63
	.byte	0x2
	.2byte	0x56d
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x56
	.uleb128 0x2e
	.4byte	$LASF64
	.byte	0x2
	.2byte	0x56d
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x57
	.byte	0
	.byte	0
	.uleb128 0x27
	.4byte	$LASF65
	.byte	0x2
	.2byte	0x26d
	.byte	0x5
	.4byte	0x48
	.4byte	$LFB49
	.4byte	$LFE49-$LFB49
	.uleb128 0x1
	.byte	0x9c
	.4byte	0xa38
	.uleb128 0x2b
	.ascii	"pid\000"
	.byte	0x2
	.2byte	0x26d
	.byte	0x14
	.4byte	0x99
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2c
	.4byte	$LASF56
	.byte	0x2
	.2byte	0x26d
	.byte	0x1d
	.4byte	0x48
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2d
	.4byte	$LBB3
	.4byte	$LBE3-$LBB3
	.uleb128 0x2e
	.4byte	$LASF60
	.byte	0x2
	.2byte	0x26f
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x52
	.uleb128 0x2e
	.4byte	$LASF61
	.byte	0x2
	.2byte	0x26f
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x54
	.uleb128 0x2e
	.4byte	$LASF62
	.byte	0x2
	.2byte	0x26f
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x55
	.uleb128 0x2e
	.4byte	$LASF64
	.byte	0x2
	.2byte	0x26f
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x57
	.byte	0
	.byte	0
	.uleb128 0x27
	.4byte	$LASF66
	.byte	0x2
	.2byte	0x1e4
	.byte	0x7
	.4byte	0x99
	.4byte	$LFB36
	.4byte	$LFE36-$LFB36
	.uleb128 0x1
	.byte	0x9c
	.4byte	0xa7c
	.uleb128 0x2d
	.4byte	$LBB2
	.4byte	$LBE2-$LBB2
	.uleb128 0x2e
	.4byte	$LASF60
	.byte	0x2
	.2byte	0x1e6
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x52
	.uleb128 0x2e
	.4byte	$LASF64
	.byte	0x2
	.2byte	0x1e6
	.byte	0x9
	.4byte	0x86
	.uleb128 0x1
	.byte	0x57
	.byte	0
	.byte	0
	.uleb128 0x2f
	.4byte	$LASF71
	.byte	0x5
	.byte	0xb9
	.byte	0x59
	.4byte	$LFB0
	.4byte	$LFE0-$LFB0
	.uleb128 0x1
	.byte	0x9c
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
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x11
	.uleb128 0x1
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
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0xb
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
	.byte	0
	.byte	0
	.uleb128 0xc
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
	.uleb128 0xd
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
	.uleb128 0xe
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
	.uleb128 0x1c
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0xf
	.uleb128 0x13
	.byte	0x1
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
	.uleb128 0x10
	.uleb128 0x15
	.byte	0x1
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x12
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
	.uleb128 0x13
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
	.uleb128 0x14
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
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x15
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x55
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x16
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
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x17
	.uleb128 0x4109
	.byte	0
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x18
	.uleb128 0x4109
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x19
	.uleb128 0x410a
	.byte	0
	.uleb128 0x2
	.uleb128 0x18
	.uleb128 0x2111
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x1a
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
	.uleb128 0x2117
	.uleb128 0x19
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1b
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
	.uleb128 0x17
	.uleb128 0x2137
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x1c
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1d
	.uleb128 0x4109
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x31
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1e
	.uleb128 0x4109
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x1f
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
	.uleb128 0x20
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
	.uleb128 0x21
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
	.uleb128 0x22
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
	.uleb128 0x23
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
	.uleb128 0x87
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
	.uleb128 0x24
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
	.uleb128 0x25
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
	.uleb128 0x26
	.uleb128 0x26
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0x27
	.uleb128 0x2e
	.byte	0x1
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
	.uleb128 0x28
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
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
	.uleb128 0x29
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
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
	.uleb128 0x2a
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
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
	.uleb128 0x2b
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0x8
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x2c
	.uleb128 0x5
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x2d
	.uleb128 0xb
	.byte	0x1
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.byte	0
	.byte	0
	.uleb128 0x2e
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2
	.uleb128 0x18
	.byte	0
	.byte	0
	.uleb128 0x2f
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
	.uleb128 0x87
	.uleb128 0x19
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
$LVUS29:
	.uleb128 $LVU205
	.uleb128 $LVU207
	.uleb128 $LVU207
	.uleb128 $LVU230
$LLST29:
	.4byte	$LVL72
	.4byte	$LVL73
	.2byte	0x2
	.byte	0x30
	.byte	0x9f
	.4byte	$LVL73
	.4byte	$LVL84
	.2byte	0x1
	.byte	0x60
	.4byte	0
	.4byte	0
$LVUS30:
	.uleb128 $LVU214
	.uleb128 $LVU217
$LLST30:
	.4byte	$LVL76
	.4byte	$LVL77
	.2byte	0x1
	.byte	0x52
	.4byte	0
	.4byte	0
$LVUS31:
	.uleb128 $LVU215
	.uleb128 $LVU221
	.uleb128 $LVU221
	.uleb128 $LVU223
$LLST31:
	.4byte	$LVL76
	.4byte	$LVL80
	.2byte	0x1
	.byte	0x55
	.4byte	$LVL80
	.4byte	$LVL82-1
	.2byte	0x2
	.byte	0x90
	.uleb128 0x41
	.4byte	0
	.4byte	0
$LVUS32:
	.uleb128 $LVU220
	.uleb128 $LVU222
	.uleb128 $LVU222
	.uleb128 $LVU223
$LLST32:
	.4byte	$LVL79
	.4byte	$LVL81
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL81
	.4byte	$LVL82-1
	.2byte	0x6
	.byte	0x92
	.uleb128 0x41
	.sleb128 0
	.byte	0x31
	.byte	0x24
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS24:
	.uleb128 0
	.uleb128 $LVU176
	.uleb128 $LVU176
	.uleb128 0
$LLST24:
	.4byte	$LVL54
	.4byte	$LVL55-1
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL55-1
	.4byte	$LFE173
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS25:
	.uleb128 0
	.uleb128 $LVU176
	.uleb128 $LVU176
	.uleb128 $LVU199
	.uleb128 $LVU199
	.uleb128 0
$LLST25:
	.4byte	$LVL54
	.4byte	$LVL55-1
	.2byte	0x1
	.byte	0x55
	.4byte	$LVL55-1
	.4byte	$LVL69
	.2byte	0x1
	.byte	0x64
	.4byte	$LVL69
	.4byte	$LFE173
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS26:
	.uleb128 0
	.uleb128 $LVU176
	.uleb128 $LVU176
	.uleb128 $LVU200
	.uleb128 $LVU200
	.uleb128 0
$LLST26:
	.4byte	$LVL54
	.4byte	$LVL55-1
	.2byte	0x1
	.byte	0x56
	.4byte	$LVL55-1
	.4byte	$LVL70
	.2byte	0x1
	.byte	0x63
	.4byte	$LVL70
	.4byte	$LFE173
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x56
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS27:
	.uleb128 $LVU183
	.uleb128 $LVU185
	.uleb128 $LVU186
	.uleb128 $LVU201
$LLST27:
	.4byte	$LVL59
	.4byte	$LVL60
	.2byte	0x2
	.byte	0x30
	.byte	0x9f
	.4byte	$LVL62
	.4byte	$LVL71
	.2byte	0x1
	.byte	0x61
	.4byte	0
	.4byte	0
$LVUS28:
	.uleb128 $LVU186
	.uleb128 $LVU188
	.uleb128 $LVU192
	.uleb128 $LVU197
$LLST28:
	.4byte	$LVL62
	.4byte	$LVL64
	.2byte	0x1
	.byte	0x60
	.4byte	$LVL65
	.4byte	$LVL68
	.2byte	0x1
	.byte	0x60
	.4byte	0
	.4byte	0
$LVUS21:
	.uleb128 0
	.uleb128 $LVU154
	.uleb128 $LVU154
	.uleb128 $LVU170
	.uleb128 $LVU170
	.uleb128 0
$LLST21:
	.4byte	$LVL42
	.4byte	$LVL44
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL44
	.4byte	$LVL52
	.2byte	0x1
	.byte	0x61
	.4byte	$LVL52
	.4byte	$LFE172
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS22:
	.uleb128 $LVU152
	.uleb128 $LVU154
	.uleb128 $LVU154
	.uleb128 $LVU171
$LLST22:
	.4byte	$LVL43
	.4byte	$LVL44
	.2byte	0x2
	.byte	0x33
	.byte	0x9f
	.4byte	$LVL44
	.4byte	$LVL53
	.2byte	0x1
	.byte	0x60
	.4byte	0
	.4byte	0
$LVUS23:
	.uleb128 $LVU154
	.uleb128 $LVU155
	.uleb128 $LVU155
	.uleb128 $LVU156
	.uleb128 $LVU156
	.uleb128 $LVU158
	.uleb128 $LVU163
	.uleb128 $LVU166
	.uleb128 $LVU166
	.uleb128 $LVU167
	.uleb128 $LVU167
	.uleb128 $LVU168
$LLST23:
	.4byte	$LVL44
	.4byte	$LVL45
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL45
	.4byte	$LVL46-1
	.2byte	0x4
	.byte	0x74
	.sleb128 -87
	.byte	0x9f
	.4byte	$LVL46-1
	.4byte	$LVL47
	.2byte	0x22
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x22
	.byte	0x3f
	.byte	0x1a
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x1c
	.byte	0x9f
	.4byte	$LVL48
	.4byte	$LVL49
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL49
	.4byte	$LVL50-1
	.2byte	0x3
	.byte	0x74
	.sleb128 -48
	.byte	0x9f
	.4byte	$LVL50-1
	.4byte	$LVL51
	.2byte	0x22
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x22
	.byte	0x3f
	.byte	0x1a
	.byte	0x81
	.sleb128 0
	.byte	0x80
	.sleb128 0
	.byte	0x32
	.byte	0x24
	.byte	0x26
	.byte	0x4f
	.byte	0x26
	.byte	0x4c
	.byte	0x25
	.byte	0x1c
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS9:
	.uleb128 0
	.uleb128 $LVU88
	.uleb128 $LVU88
	.uleb128 0
$LLST9:
	.4byte	$LVL17
	.4byte	$LVL18-1
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL18-1
	.4byte	$LFE161
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS7:
	.uleb128 0
	.uleb128 $LVU77
	.uleb128 $LVU77
	.uleb128 0
$LLST7:
	.4byte	$LVL13
	.4byte	$LVL14
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL14
	.4byte	$LFE160
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS8:
	.uleb128 0
	.uleb128 $LVU78
	.uleb128 $LVU78
	.uleb128 0
$LLST8:
	.4byte	$LVL13
	.4byte	$LVL15-1
	.2byte	0x1
	.byte	0x55
	.4byte	$LVL15-1
	.4byte	$LFE160
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS6:
	.uleb128 $LVU61
	.uleb128 0
$LLST6:
	.4byte	$LVL12
	.4byte	$LFE155
	.2byte	0x1
	.byte	0x54
	.4byte	0
	.4byte	0
$LVUS18:
	.uleb128 0
	.uleb128 $LVU134
	.uleb128 $LVU134
	.uleb128 0
$LLST18:
	.4byte	$LVL33
	.4byte	$LVL35
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL35
	.4byte	$LFE115
	.2byte	0x1
	.byte	0x52
	.4byte	0
	.4byte	0
$LVUS19:
	.uleb128 0
	.uleb128 $LVU134
	.uleb128 $LVU134
	.uleb128 $LVU139
	.uleb128 $LVU139
	.uleb128 $LVU141
	.uleb128 $LVU141
	.uleb128 0
$LLST19:
	.4byte	$LVL33
	.4byte	$LVL35
	.2byte	0x1
	.byte	0x56
	.4byte	$LVL35
	.4byte	$LVL38
	.2byte	0x1
	.byte	0x57
	.4byte	$LVL38
	.4byte	$LVL39
	.2byte	0x1
	.byte	0x56
	.4byte	$LVL39
	.4byte	$LFE115
	.2byte	0x1
	.byte	0x57
	.4byte	0
	.4byte	0
$LVUS20:
	.uleb128 $LVU131
	.uleb128 $LVU134
	.uleb128 $LVU134
	.uleb128 $LVU136
	.uleb128 $LVU136
	.uleb128 $LVU138
	.uleb128 $LVU138
	.uleb128 0
$LLST20:
	.4byte	$LVL34
	.4byte	$LVL35
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL35
	.4byte	$LVL36
	.2byte	0x1
	.byte	0x53
	.4byte	$LVL36
	.4byte	$LVL37
	.2byte	0x3
	.byte	0x73
	.sleb128 1
	.byte	0x9f
	.4byte	$LVL37
	.4byte	$LFE115
	.2byte	0x1
	.byte	0x53
	.4byte	0
	.4byte	0
$LVUS15:
	.uleb128 0
	.uleb128 $LVU127
	.uleb128 $LVU127
	.uleb128 0
$LLST15:
	.4byte	$LVL31
	.4byte	$LVL32-1
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL32-1
	.4byte	$LFE114
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS16:
	.uleb128 0
	.uleb128 $LVU127
	.uleb128 $LVU127
	.uleb128 0
$LLST16:
	.4byte	$LVL31
	.4byte	$LVL32-1
	.2byte	0x1
	.byte	0x55
	.4byte	$LVL32-1
	.4byte	$LFE114
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS17:
	.uleb128 0
	.uleb128 $LVU127
	.uleb128 $LVU127
	.uleb128 0
$LLST17:
	.4byte	$LVL31
	.4byte	$LVL32-1
	.2byte	0x1
	.byte	0x56
	.4byte	$LVL32-1
	.4byte	$LFE114
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x56
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS11:
	.uleb128 0
	.uleb128 $LVU108
	.uleb128 $LVU108
	.uleb128 0
$LLST11:
	.4byte	$LVL23
	.4byte	$LVL25
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL25
	.4byte	$LFE113
	.2byte	0x1
	.byte	0x52
	.4byte	0
	.4byte	0
$LVUS12:
	.uleb128 0
	.uleb128 $LVU117
	.uleb128 $LVU117
	.uleb128 0
$LLST12:
	.4byte	$LVL23
	.4byte	$LVL28
	.2byte	0x1
	.byte	0x56
	.4byte	$LVL28
	.4byte	$LFE113
	.2byte	0x1
	.byte	0x56
	.4byte	0
	.4byte	0
$LVUS13:
	.uleb128 $LVU104
	.uleb128 $LVU109
	.uleb128 $LVU109
	.uleb128 $LVU120
	.uleb128 $LVU120
	.uleb128 $LVU122
$LLST13:
	.4byte	$LVL24
	.4byte	$LVL26
	.2byte	0x3
	.byte	0x9
	.byte	0xff
	.byte	0x9f
	.4byte	$LVL26
	.4byte	$LVL29
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL29
	.4byte	$LVL30
	.2byte	0x3
	.byte	0x9
	.byte	0xff
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS14:
	.uleb128 $LVU103
	.uleb128 $LVU109
	.uleb128 $LVU109
	.uleb128 $LVU120
	.uleb128 $LVU120
	.uleb128 $LVU122
$LLST14:
	.4byte	$LVL24
	.4byte	$LVL26
	.2byte	0x1
	.byte	0x56
	.4byte	$LVL26
	.4byte	$LVL29
	.2byte	0x1
	.byte	0x53
	.4byte	$LVL29
	.4byte	$LVL30
	.2byte	0x1
	.byte	0x56
	.4byte	0
	.4byte	0
$LVUS4:
	.uleb128 0
	.uleb128 $LVU56
	.uleb128 $LVU56
	.uleb128 0
$LLST4:
	.4byte	$LVL8
	.4byte	$LVL11
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL11
	.4byte	$LFE111
	.2byte	0x1
	.byte	0x52
	.4byte	0
	.4byte	0
$LVUS5:
	.uleb128 $LVU47
	.uleb128 $LVU50
	.uleb128 $LVU50
	.uleb128 0
$LLST5:
	.4byte	$LVL9
	.4byte	$LVL10
	.2byte	0x2
	.byte	0x30
	.byte	0x9f
	.4byte	$LVL10
	.4byte	$LFE111
	.2byte	0x1
	.byte	0x53
	.4byte	0
	.4byte	0
$LVUS10:
	.uleb128 0
	.uleb128 $LVU96
	.uleb128 $LVU96
	.uleb128 $LVU98
	.uleb128 $LVU98
	.uleb128 0
$LLST10:
	.4byte	$LVL19
	.4byte	$LVL20-1
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL20-1
	.4byte	$LVL22
	.2byte	0x1
	.byte	0x60
	.4byte	$LVL22
	.4byte	$LFE105
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS0:
	.uleb128 0
	.uleb128 $LVU33
	.uleb128 $LVU33
	.uleb128 0
$LLST0:
	.4byte	$LVL2
	.4byte	$LVL3-1
	.2byte	0x1
	.byte	0x54
	.4byte	$LVL3-1
	.4byte	$LFE102
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x54
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS1:
	.uleb128 0
	.uleb128 $LVU33
	.uleb128 $LVU33
	.uleb128 0
$LLST1:
	.4byte	$LVL2
	.4byte	$LVL3-1
	.2byte	0x1
	.byte	0x55
	.4byte	$LVL3-1
	.4byte	$LFE102
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS2:
	.uleb128 0
	.uleb128 $LVU33
	.uleb128 $LVU33
	.uleb128 0
$LLST2:
	.4byte	$LVL2
	.4byte	$LVL3-1
	.2byte	0x1
	.byte	0x56
	.4byte	$LVL3-1
	.4byte	$LFE102
	.2byte	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x56
	.byte	0x9f
	.4byte	0
	.4byte	0
$LVUS3:
	.uleb128 $LVU33
	.uleb128 $LVU35
	.uleb128 $LVU36
	.uleb128 $LVU38
	.uleb128 $LVU38
	.uleb128 $LVU41
	.uleb128 $LVU41
	.uleb128 0
$LLST3:
	.4byte	$LVL3
	.4byte	$LVL4
	.2byte	0x1
	.byte	0x52
	.4byte	$LVL5
	.4byte	$LVL6
	.2byte	0x1
	.byte	0x52
	.4byte	$LVL6
	.4byte	$LVL7
	.2byte	0x4
	.byte	0x72
	.sleb128 0
	.byte	0x1f
	.byte	0x9f
	.4byte	$LVL7
	.4byte	$LFE102
	.2byte	0x3
	.byte	0x9
	.byte	0xff
	.byte	0x9f
	.4byte	0
	.4byte	0
	.section	.debug_aranges,"",@progbits
	.4byte	0x44
	.2byte	0x2
	.4byte	$Ldebug_info0
	.byte	0x4
	.byte	0
	.2byte	0
	.2byte	0
	.4byte	$Ltext0
	.4byte	$Letext0-$Ltext0
	.4byte	$LFB105
	.4byte	$LFE105-$LFB105
	.4byte	$LFB113
	.4byte	$LFE113-$LFB113
	.4byte	$LFB114
	.4byte	$LFE114-$LFB114
	.4byte	$LFB115
	.4byte	$LFE115-$LFB115
	.4byte	$LFB129
	.4byte	$LFE129-$LFB129
	.4byte	0
	.4byte	0
	.section	.debug_ranges,"",@progbits
$Ldebug_ranges0:
	.4byte	$LBB5
	.4byte	$LBE5
	.4byte	$LBB6
	.4byte	$LBE6
	.4byte	0
	.4byte	0
	.4byte	$LBB7
	.4byte	$LBE7
	.4byte	$LBB8
	.4byte	$LBE8
	.4byte	0
	.4byte	0
	.4byte	$LBB9
	.4byte	$LBE9
	.4byte	$LBB10
	.4byte	$LBE10
	.4byte	0
	.4byte	0
	.4byte	$Ltext0
	.4byte	$Letext0
	.4byte	$LFB105
	.4byte	$LFE105
	.4byte	$LFB113
	.4byte	$LFE113
	.4byte	$LFB114
	.4byte	$LFE114
	.4byte	$LFB115
	.4byte	$LFE115
	.4byte	$LFB129
	.4byte	$LFE129
	.4byte	0
	.4byte	0
	.section	.debug_line,"",@progbits
$Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
$LASF62:
	.ascii	"_arg2\000"
$LASF63:
	.ascii	"_arg3\000"
$LASF64:
	.ascii	"_arg4\000"
$LASF57:
	.ascii	"write\000"
$LASF30:
	.ascii	"isdigit\000"
$LASF14:
	.ascii	"environ\000"
$LASF3:
	.ascii	"short int\000"
$LASF8:
	.ascii	"size_t\000"
$LASF11:
	.ascii	"intptr_t\000"
$LASF46:
	.ascii	"putchar\000"
$LASF32:
	.ascii	"isalnum\000"
$LASF34:
	.ascii	"isspace\000"
$LASF39:
	.ascii	"main\000"
$LASF52:
	.ascii	"memcpy\000"
$LASF69:
	.ascii	"/home/boricj/Documents/ghidra-delinker-extension/src/tes"
	.ascii	"t/resources/ascii-table/reference/elf_linux_freestanding"
	.ascii	"\000"
$LASF9:
	.ascii	"ssize_t\000"
$LASF22:
	.ascii	"matches\000"
$LASF65:
	.ascii	"sys_kill\000"
$LASF60:
	.ascii	"_num\000"
$LASF66:
	.ascii	"sys_getpid\000"
$LASF20:
	.ascii	"stderr\000"
$LASF6:
	.ascii	"long long int\000"
$LASF41:
	.ascii	"properties\000"
$LASF42:
	.ascii	"num_ascii_properties\000"
$LASF51:
	.ascii	"memset\000"
$LASF70:
	.ascii	"itoa_buffer\000"
$LASF10:
	.ascii	"long int\000"
$LASF26:
	.ascii	"s_ascii_properties\000"
$LASF31:
	.ascii	"isalpha\000"
$LASF21:
	.ascii	"dummy\000"
$LASF37:
	.ascii	"isgraph\000"
$LASF49:
	.ascii	"fileno\000"
$LASF0:
	.ascii	"unsigned char\000"
$LASF15:
	.ascii	"_auxv\000"
$LASF28:
	.ascii	"islower\000"
$LASF53:
	.ascii	"memmove\000"
$LASF50:
	.ascii	"abort\000"
$LASF1:
	.ascii	"signed char\000"
$LASF5:
	.ascii	"long long unsigned int\000"
$LASF4:
	.ascii	"unsigned int\000"
$LASF59:
	.ascii	"sys_write\000"
$LASF48:
	.ascii	"stream\000"
$LASF71:
	.ascii	"__start\000"
$LASF16:
	.ascii	"errno\000"
$LASF13:
	.ascii	"char\000"
$LASF56:
	.ascii	"signal\000"
$LASF54:
	.ascii	"_nolibc_memcpy_up\000"
$LASF47:
	.ascii	"fputc\000"
$LASF2:
	.ascii	"short unsigned int\000"
$LASF36:
	.ascii	"isprint\000"
$LASF68:
	.ascii	"/home/boricj/Documents/ghidra-delinker-extension/src/tes"
	.ascii	"t/resources/ascii-table/src/main.c\000"
$LASF29:
	.ascii	"isupper\000"
$LASF25:
	.ascii	"NUM_ASCII_PROPERTIES\000"
$LASF44:
	.ascii	"print_number\000"
$LASF27:
	.ascii	"COLUMNS\000"
$LASF7:
	.ascii	"long unsigned int\000"
$LASF24:
	.ascii	"ascii_property\000"
$LASF38:
	.ascii	"character\000"
$LASF58:
	.ascii	"count\000"
$LASF18:
	.ascii	"stdin\000"
$LASF35:
	.ascii	"iscntrl\000"
$LASF45:
	.ascii	"digit\000"
$LASF23:
	.ascii	"flag\000"
$LASF17:
	.ascii	"FILE\000"
$LASF67:
	.ascii	"GNU C17 12.2.0 -G 4 -meb -march=mips3 -mno-abicalls -mlo"
	.ascii	"ng-calls -mno-check-zero-division -mfpxx -mllsc -mno-lxc"
	.ascii	"1-sxc1 -mips3 -mno-shared -mabi=32 -gdwarf-4 -Og -ffrees"
	.ascii	"tanding -fno-pic -fno-plt\000"
$LASF55:
	.ascii	"raise\000"
$LASF33:
	.ascii	"ispunct\000"
$LASF12:
	.ascii	"pid_t\000"
$LASF43:
	.ascii	"property\000"
$LASF40:
	.ascii	"print_ascii_entry\000"
$LASF19:
	.ascii	"stdout\000"
$LASF61:
	.ascii	"_arg1\000"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
