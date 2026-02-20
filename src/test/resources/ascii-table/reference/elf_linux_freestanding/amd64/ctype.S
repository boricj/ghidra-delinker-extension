	.file	"ctype.c"
	.text
.Ltext0:
	.file 1 "/home/boricj/Documents/ghidra-delinker-extension/src/test/resources/ascii-table/src/ctype.c"
	.globl	isalnum
	.type	isalnum, @function
isalnum:
.LVL0:
.LFB0:
	.loc 1 87 1 view -0
	.cfi_startproc
	.loc 1 88 2 view .LVU1
	.loc 1 88 23 is_stmt 0 view .LVU2
	cmpl	$-1, %edi
	je	.L3
	.loc 1 88 40 discriminator 1 view .LVU3
	movzbl	%dil, %edi
.LVL1:
	.loc 1 88 39 discriminator 1 view .LVU4
	movzbl	_ctype_+1(%rdi), %eax
	.loc 1 88 23 discriminator 1 view .LVU5
	andl	$7, %eax
	ret
.LVL2:
.L3:
	.loc 1 88 23 discriminator 2 view .LVU6
	movl	$0, %eax
	.loc 1 89 1 view .LVU7
	ret
	.cfi_endproc
.LFE0:
	.size	isalnum, .-isalnum
	.globl	isalpha
	.type	isalpha, @function
isalpha:
.LVL3:
.LFB1:
	.loc 1 92 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 93 2 view .LVU9
	.loc 1 93 23 is_stmt 0 view .LVU10
	cmpl	$-1, %edi
	je	.L6
	.loc 1 93 40 discriminator 1 view .LVU11
	movzbl	%dil, %edi
.LVL4:
	.loc 1 93 39 discriminator 1 view .LVU12
	movzbl	_ctype_+1(%rdi), %eax
	.loc 1 93 23 discriminator 1 view .LVU13
	andl	$3, %eax
	ret
.LVL5:
.L6:
	.loc 1 93 23 discriminator 2 view .LVU14
	movl	$0, %eax
	.loc 1 94 1 view .LVU15
	ret
	.cfi_endproc
.LFE1:
	.size	isalpha, .-isalpha
	.globl	iscntrl
	.type	iscntrl, @function
iscntrl:
.LVL6:
.LFB2:
	.loc 1 97 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 98 2 view .LVU17
	.loc 1 98 23 is_stmt 0 view .LVU18
	cmpl	$-1, %edi
	je	.L9
	.loc 1 98 40 discriminator 1 view .LVU19
	movzbl	%dil, %edi
.LVL7:
	.loc 1 98 39 discriminator 1 view .LVU20
	movzbl	_ctype_+1(%rdi), %eax
	.loc 1 98 23 discriminator 1 view .LVU21
	andl	$32, %eax
	ret
.LVL8:
.L9:
	.loc 1 98 23 discriminator 2 view .LVU22
	movl	$0, %eax
	.loc 1 99 1 view .LVU23
	ret
	.cfi_endproc
.LFE2:
	.size	iscntrl, .-iscntrl
	.globl	isdigit
	.type	isdigit, @function
isdigit:
.LVL9:
.LFB3:
	.loc 1 102 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 103 2 view .LVU25
	.loc 1 103 23 is_stmt 0 view .LVU26
	cmpl	$-1, %edi
	je	.L12
	.loc 1 103 40 discriminator 1 view .LVU27
	movzbl	%dil, %edi
.LVL10:
	.loc 1 103 39 discriminator 1 view .LVU28
	movzbl	_ctype_+1(%rdi), %eax
	.loc 1 103 23 discriminator 1 view .LVU29
	andl	$4, %eax
	ret
.LVL11:
.L12:
	.loc 1 103 23 discriminator 2 view .LVU30
	movl	$0, %eax
	.loc 1 104 1 view .LVU31
	ret
	.cfi_endproc
.LFE3:
	.size	isdigit, .-isdigit
	.globl	isgraph
	.type	isgraph, @function
isgraph:
.LVL12:
.LFB4:
	.loc 1 107 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 108 2 view .LVU33
	.loc 1 108 23 is_stmt 0 view .LVU34
	cmpl	$-1, %edi
	je	.L15
	.loc 1 108 40 discriminator 1 view .LVU35
	movzbl	%dil, %edi
.LVL13:
	.loc 1 108 39 discriminator 1 view .LVU36
	movzbl	_ctype_+1(%rdi), %eax
	.loc 1 108 23 discriminator 1 view .LVU37
	andl	$23, %eax
	ret
.LVL14:
.L15:
	.loc 1 108 23 discriminator 2 view .LVU38
	movl	$0, %eax
	.loc 1 109 1 view .LVU39
	ret
	.cfi_endproc
.LFE4:
	.size	isgraph, .-isgraph
	.globl	islower
	.type	islower, @function
islower:
.LVL15:
.LFB5:
	.loc 1 112 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 113 2 view .LVU41
	.loc 1 113 23 is_stmt 0 view .LVU42
	cmpl	$-1, %edi
	je	.L18
	.loc 1 113 40 discriminator 1 view .LVU43
	movzbl	%dil, %edi
.LVL16:
	.loc 1 113 39 discriminator 1 view .LVU44
	movzbl	_ctype_+1(%rdi), %eax
	.loc 1 113 23 discriminator 1 view .LVU45
	andl	$2, %eax
	ret
.LVL17:
.L18:
	.loc 1 113 23 discriminator 2 view .LVU46
	movl	$0, %eax
	.loc 1 114 1 view .LVU47
	ret
	.cfi_endproc
.LFE5:
	.size	islower, .-islower
	.globl	isprint
	.type	isprint, @function
isprint:
.LVL18:
.LFB6:
	.loc 1 117 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 118 2 view .LVU49
	.loc 1 118 23 is_stmt 0 view .LVU50
	cmpl	$-1, %edi
	je	.L21
	.loc 1 118 40 discriminator 1 view .LVU51
	movzbl	%dil, %edi
.LVL19:
	.loc 1 118 39 discriminator 1 view .LVU52
	movsbl	_ctype_+1(%rdi), %eax
	.loc 1 118 23 discriminator 1 view .LVU53
	andl	$151, %eax
	ret
.LVL20:
.L21:
	.loc 1 118 23 discriminator 2 view .LVU54
	movl	$0, %eax
	.loc 1 119 1 view .LVU55
	ret
	.cfi_endproc
.LFE6:
	.size	isprint, .-isprint
	.globl	ispunct
	.type	ispunct, @function
ispunct:
.LVL21:
.LFB7:
	.loc 1 122 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 123 2 view .LVU57
	.loc 1 123 23 is_stmt 0 view .LVU58
	cmpl	$-1, %edi
	je	.L24
	.loc 1 123 40 discriminator 1 view .LVU59
	movzbl	%dil, %edi
.LVL22:
	.loc 1 123 39 discriminator 1 view .LVU60
	movzbl	_ctype_+1(%rdi), %eax
	.loc 1 123 23 discriminator 1 view .LVU61
	andl	$16, %eax
	ret
.LVL23:
.L24:
	.loc 1 123 23 discriminator 2 view .LVU62
	movl	$0, %eax
	.loc 1 124 1 view .LVU63
	ret
	.cfi_endproc
.LFE7:
	.size	ispunct, .-ispunct
	.globl	isspace
	.type	isspace, @function
isspace:
.LVL24:
.LFB8:
	.loc 1 127 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 128 2 view .LVU65
	.loc 1 128 23 is_stmt 0 view .LVU66
	cmpl	$-1, %edi
	je	.L27
	.loc 1 128 40 discriminator 1 view .LVU67
	movzbl	%dil, %edi
.LVL25:
	.loc 1 128 39 discriminator 1 view .LVU68
	movzbl	_ctype_+1(%rdi), %eax
	.loc 1 128 23 discriminator 1 view .LVU69
	andl	$8, %eax
	ret
.LVL26:
.L27:
	.loc 1 128 23 discriminator 2 view .LVU70
	movl	$0, %eax
	.loc 1 129 1 view .LVU71
	ret
	.cfi_endproc
.LFE8:
	.size	isspace, .-isspace
	.globl	isupper
	.type	isupper, @function
isupper:
.LVL27:
.LFB9:
	.loc 1 132 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 133 2 view .LVU73
	.loc 1 133 23 is_stmt 0 view .LVU74
	cmpl	$-1, %edi
	je	.L30
	.loc 1 133 40 discriminator 1 view .LVU75
	movzbl	%dil, %edi
.LVL28:
	.loc 1 133 39 discriminator 1 view .LVU76
	movzbl	_ctype_+1(%rdi), %eax
	.loc 1 133 23 discriminator 1 view .LVU77
	andl	$1, %eax
	ret
.LVL29:
.L30:
	.loc 1 133 23 discriminator 2 view .LVU78
	movl	$0, %eax
	.loc 1 134 1 view .LVU79
	ret
	.cfi_endproc
.LFE9:
	.size	isupper, .-isupper
	.globl	isxdigit
	.type	isxdigit, @function
isxdigit:
.LVL30:
.LFB10:
	.loc 1 137 1 is_stmt 1 view -0
	.cfi_startproc
	.loc 1 138 2 view .LVU81
	.loc 1 138 23 is_stmt 0 view .LVU82
	cmpl	$-1, %edi
	je	.L33
	.loc 1 138 40 discriminator 1 view .LVU83
	movzbl	%dil, %edi
.LVL31:
	.loc 1 138 39 discriminator 1 view .LVU84
	movzbl	_ctype_+1(%rdi), %eax
	.loc 1 138 23 discriminator 1 view .LVU85
	andl	$68, %eax
	ret
.LVL32:
.L33:
	.loc 1 138 23 discriminator 2 view .LVU86
	movl	$0, %eax
	.loc 1 139 1 view .LVU87
	ret
	.cfi_endproc
.LFE10:
	.size	isxdigit, .-isxdigit
	.globl	_ctype_
	.section	.rodata
	.align 32
	.type	_ctype_, @object
	.size	_ctype_, 257
_ctype_:
	.string	""
	.string	"         (((((                  \210\020\020\020\020\020\020\020\020\020\020\020\020\020\020\020\004\004\004\004\004\004\004\004\004\004\020\020\020\020\020\020\020AAAAAA\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\001\020\020\020\020\020\020BBBBBB\002\002\002\002\002\002\002\002\002\002\002\002\002\002\002\002\002\002\002\002\020\020\020\020 "
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.string	""
	.text
.Letext0:
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x2be
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.long	.LASF12
	.byte	0xc
	.long	.LASF13
	.long	.LASF14
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.long	0x51
	.long	0x3e
	.uleb128 0x3
	.long	0x43
	.value	0x100
	.byte	0
	.uleb128 0x4
	.long	0x2d
	.uleb128 0x5
	.byte	0x8
	.byte	0x7
	.long	.LASF0
	.uleb128 0x5
	.byte	0x1
	.byte	0x6
	.long	.LASF1
	.uleb128 0x4
	.long	0x4a
	.uleb128 0x6
	.long	.LASF15
	.byte	0x1
	.byte	0x31
	.byte	0xc
	.long	0x3e
	.uleb128 0x9
	.byte	0x3
	.quad	_ctype_
	.uleb128 0x7
	.long	.LASF2
	.byte	0x1
	.byte	0x88
	.byte	0x5
	.long	0xa2
	.quad	.LFB10
	.quad	.LFE10-.LFB10
	.uleb128 0x1
	.byte	0x9c
	.long	0xa2
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x88
	.byte	0x12
	.long	0xa2
	.long	.LLST10
	.long	.LVUS10
	.byte	0
	.uleb128 0x9
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x7
	.long	.LASF3
	.byte	0x1
	.byte	0x83
	.byte	0x5
	.long	0xa2
	.quad	.LFB9
	.quad	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.long	0xdf
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x83
	.byte	0x11
	.long	0xa2
	.long	.LLST9
	.long	.LVUS9
	.byte	0
	.uleb128 0x7
	.long	.LASF4
	.byte	0x1
	.byte	0x7e
	.byte	0x5
	.long	0xa2
	.quad	.LFB8
	.quad	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.long	0x115
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x7e
	.byte	0x11
	.long	0xa2
	.long	.LLST8
	.long	.LVUS8
	.byte	0
	.uleb128 0x7
	.long	.LASF5
	.byte	0x1
	.byte	0x79
	.byte	0x5
	.long	0xa2
	.quad	.LFB7
	.quad	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.long	0x14b
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x79
	.byte	0x11
	.long	0xa2
	.long	.LLST7
	.long	.LVUS7
	.byte	0
	.uleb128 0x7
	.long	.LASF6
	.byte	0x1
	.byte	0x74
	.byte	0x5
	.long	0xa2
	.quad	.LFB6
	.quad	.LFE6-.LFB6
	.uleb128 0x1
	.byte	0x9c
	.long	0x181
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x74
	.byte	0x11
	.long	0xa2
	.long	.LLST6
	.long	.LVUS6
	.byte	0
	.uleb128 0x7
	.long	.LASF7
	.byte	0x1
	.byte	0x6f
	.byte	0x5
	.long	0xa2
	.quad	.LFB5
	.quad	.LFE5-.LFB5
	.uleb128 0x1
	.byte	0x9c
	.long	0x1b7
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x6f
	.byte	0x11
	.long	0xa2
	.long	.LLST5
	.long	.LVUS5
	.byte	0
	.uleb128 0x7
	.long	.LASF8
	.byte	0x1
	.byte	0x6a
	.byte	0x5
	.long	0xa2
	.quad	.LFB4
	.quad	.LFE4-.LFB4
	.uleb128 0x1
	.byte	0x9c
	.long	0x1ed
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x6a
	.byte	0x11
	.long	0xa2
	.long	.LLST4
	.long	.LVUS4
	.byte	0
	.uleb128 0x7
	.long	.LASF9
	.byte	0x1
	.byte	0x65
	.byte	0x5
	.long	0xa2
	.quad	.LFB3
	.quad	.LFE3-.LFB3
	.uleb128 0x1
	.byte	0x9c
	.long	0x223
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x65
	.byte	0x11
	.long	0xa2
	.long	.LLST3
	.long	.LVUS3
	.byte	0
	.uleb128 0x7
	.long	.LASF10
	.byte	0x1
	.byte	0x60
	.byte	0x5
	.long	0xa2
	.quad	.LFB2
	.quad	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.long	0x259
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x60
	.byte	0x11
	.long	0xa2
	.long	.LLST2
	.long	.LVUS2
	.byte	0
	.uleb128 0x7
	.long	.LASF11
	.byte	0x1
	.byte	0x5b
	.byte	0x5
	.long	0xa2
	.quad	.LFB1
	.quad	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.long	0x28f
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x5b
	.byte	0x11
	.long	0xa2
	.long	.LLST1
	.long	.LVUS1
	.byte	0
	.uleb128 0xa
	.long	.LASF16
	.byte	0x1
	.byte	0x56
	.byte	0x5
	.long	0xa2
	.quad	.LFB0
	.quad	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x56
	.byte	0x11
	.long	0xa2
	.long	.LLST0
	.long	.LVUS0
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
	.uleb128 0x7
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
	.uleb128 0x7
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_loc,"",@progbits
.Ldebug_loc0:
.LVUS10:
	.uleb128 0
	.uleb128 .LVU84
	.uleb128 .LVU84
	.uleb128 .LVU86
	.uleb128 .LVU86
	.uleb128 0
.LLST10:
	.quad	.LVL30-.Ltext0
	.quad	.LVL31-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL31-.Ltext0
	.quad	.LVL32-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL32-.Ltext0
	.quad	.LFE10-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS9:
	.uleb128 0
	.uleb128 .LVU76
	.uleb128 .LVU76
	.uleb128 .LVU78
	.uleb128 .LVU78
	.uleb128 0
.LLST9:
	.quad	.LVL27-.Ltext0
	.quad	.LVL28-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL28-.Ltext0
	.quad	.LVL29-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL29-.Ltext0
	.quad	.LFE9-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS8:
	.uleb128 0
	.uleb128 .LVU68
	.uleb128 .LVU68
	.uleb128 .LVU70
	.uleb128 .LVU70
	.uleb128 0
.LLST8:
	.quad	.LVL24-.Ltext0
	.quad	.LVL25-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL25-.Ltext0
	.quad	.LVL26-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL26-.Ltext0
	.quad	.LFE8-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS7:
	.uleb128 0
	.uleb128 .LVU60
	.uleb128 .LVU60
	.uleb128 .LVU62
	.uleb128 .LVU62
	.uleb128 0
.LLST7:
	.quad	.LVL21-.Ltext0
	.quad	.LVL22-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL22-.Ltext0
	.quad	.LVL23-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL23-.Ltext0
	.quad	.LFE7-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS6:
	.uleb128 0
	.uleb128 .LVU52
	.uleb128 .LVU52
	.uleb128 .LVU54
	.uleb128 .LVU54
	.uleb128 0
.LLST6:
	.quad	.LVL18-.Ltext0
	.quad	.LVL19-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL19-.Ltext0
	.quad	.LVL20-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL20-.Ltext0
	.quad	.LFE6-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS5:
	.uleb128 0
	.uleb128 .LVU44
	.uleb128 .LVU44
	.uleb128 .LVU46
	.uleb128 .LVU46
	.uleb128 0
.LLST5:
	.quad	.LVL15-.Ltext0
	.quad	.LVL16-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL16-.Ltext0
	.quad	.LVL17-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL17-.Ltext0
	.quad	.LFE5-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS4:
	.uleb128 0
	.uleb128 .LVU36
	.uleb128 .LVU36
	.uleb128 .LVU38
	.uleb128 .LVU38
	.uleb128 0
.LLST4:
	.quad	.LVL12-.Ltext0
	.quad	.LVL13-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL13-.Ltext0
	.quad	.LVL14-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL14-.Ltext0
	.quad	.LFE4-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS3:
	.uleb128 0
	.uleb128 .LVU28
	.uleb128 .LVU28
	.uleb128 .LVU30
	.uleb128 .LVU30
	.uleb128 0
.LLST3:
	.quad	.LVL9-.Ltext0
	.quad	.LVL10-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL10-.Ltext0
	.quad	.LVL11-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL11-.Ltext0
	.quad	.LFE3-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS2:
	.uleb128 0
	.uleb128 .LVU20
	.uleb128 .LVU20
	.uleb128 .LVU22
	.uleb128 .LVU22
	.uleb128 0
.LLST2:
	.quad	.LVL6-.Ltext0
	.quad	.LVL7-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL7-.Ltext0
	.quad	.LVL8-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL8-.Ltext0
	.quad	.LFE2-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS1:
	.uleb128 0
	.uleb128 .LVU12
	.uleb128 .LVU12
	.uleb128 .LVU14
	.uleb128 .LVU14
	.uleb128 0
.LLST1:
	.quad	.LVL3-.Ltext0
	.quad	.LVL4-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL4-.Ltext0
	.quad	.LVL5-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL5-.Ltext0
	.quad	.LFE1-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
.LVUS0:
	.uleb128 0
	.uleb128 .LVU4
	.uleb128 .LVU4
	.uleb128 .LVU6
	.uleb128 .LVU6
	.uleb128 0
.LLST0:
	.quad	.LVL0-.Ltext0
	.quad	.LVL1-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	.LVL1-.Ltext0
	.quad	.LVL2-.Ltext0
	.value	0x4
	.byte	0xf3
	.uleb128 0x1
	.byte	0x55
	.byte	0x9f
	.quad	.LVL2-.Ltext0
	.quad	.LFE0-.Ltext0
	.value	0x1
	.byte	0x55
	.quad	0
	.quad	0
	.section	.debug_aranges,"",@progbits
	.long	0x2c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x8
	.byte	0
	.value	0
	.value	0
	.quad	.Ltext0
	.quad	.Letext0-.Ltext0
	.quad	0
	.quad	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF7:
	.string	"islower"
.LASF13:
	.string	"/home/boricj/Documents/ghidra-delinker-extension/src/test/resources/ascii-table/src/ctype.c"
.LASF6:
	.string	"isprint"
.LASF0:
	.string	"long unsigned int"
.LASF11:
	.string	"isalpha"
.LASF8:
	.string	"isgraph"
.LASF10:
	.string	"iscntrl"
.LASF12:
	.string	"GNU C17 14.2.0 -mtune=generic -march=x86-64 -gdwarf-4 -Og -ffreestanding -fno-pic -fno-plt -fasynchronous-unwind-tables"
.LASF16:
	.string	"isalnum"
.LASF5:
	.string	"ispunct"
.LASF14:
	.string	"/home/boricj/Documents/ghidra-delinker-extension/src/test/resources/ascii-table/reference/elf_linux_freestanding"
.LASF9:
	.string	"isdigit"
.LASF15:
	.string	"_ctype_"
.LASF2:
	.string	"isxdigit"
.LASF4:
	.string	"isspace"
.LASF1:
	.string	"char"
.LASF3:
	.string	"isupper"
	.ident	"GCC: (Debian 14.2.0-19) 14.2.0"
	.section	.note.GNU-stack,"",@progbits
