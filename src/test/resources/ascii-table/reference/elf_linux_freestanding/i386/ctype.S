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
	.loc 1 87 1 is_stmt 0 view .LVU1
	movl	4(%esp), %eax
	.loc 1 88 2 is_stmt 1 view .LVU2
	.loc 1 88 23 is_stmt 0 view .LVU3
	cmpl	$-1, %eax
	je	.L3
	.loc 1 88 40 discriminator 1 view .LVU4
	movzbl	%al, %eax
	.loc 1 88 39 discriminator 1 view .LVU5
	movzbl	_ctype_+1(%eax), %eax
	.loc 1 88 23 discriminator 1 view .LVU6
	andl	$7, %eax
	ret
.LVL1:
.L3:
	.loc 1 88 23 view .LVU7
	movl	$0, %eax
.LVL2:
	.loc 1 89 1 view .LVU8
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
	.loc 1 92 1 is_stmt 0 view .LVU10
	movl	4(%esp), %eax
	.loc 1 93 2 is_stmt 1 view .LVU11
	.loc 1 93 23 is_stmt 0 view .LVU12
	cmpl	$-1, %eax
	je	.L6
	.loc 1 93 40 discriminator 1 view .LVU13
	movzbl	%al, %eax
	.loc 1 93 39 discriminator 1 view .LVU14
	movzbl	_ctype_+1(%eax), %eax
	.loc 1 93 23 discriminator 1 view .LVU15
	andl	$3, %eax
	ret
.LVL4:
.L6:
	.loc 1 93 23 view .LVU16
	movl	$0, %eax
.LVL5:
	.loc 1 94 1 view .LVU17
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
	.loc 1 97 1 is_stmt 0 view .LVU19
	movl	4(%esp), %eax
	.loc 1 98 2 is_stmt 1 view .LVU20
	.loc 1 98 23 is_stmt 0 view .LVU21
	cmpl	$-1, %eax
	je	.L9
	.loc 1 98 40 discriminator 1 view .LVU22
	movzbl	%al, %eax
	.loc 1 98 39 discriminator 1 view .LVU23
	movzbl	_ctype_+1(%eax), %eax
	.loc 1 98 23 discriminator 1 view .LVU24
	andl	$32, %eax
	ret
.LVL7:
.L9:
	.loc 1 98 23 view .LVU25
	movl	$0, %eax
.LVL8:
	.loc 1 99 1 view .LVU26
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
	.loc 1 102 1 is_stmt 0 view .LVU28
	movl	4(%esp), %eax
	.loc 1 103 2 is_stmt 1 view .LVU29
	.loc 1 103 23 is_stmt 0 view .LVU30
	cmpl	$-1, %eax
	je	.L12
	.loc 1 103 40 discriminator 1 view .LVU31
	movzbl	%al, %eax
	.loc 1 103 39 discriminator 1 view .LVU32
	movzbl	_ctype_+1(%eax), %eax
	.loc 1 103 23 discriminator 1 view .LVU33
	andl	$4, %eax
	ret
.LVL10:
.L12:
	.loc 1 103 23 view .LVU34
	movl	$0, %eax
.LVL11:
	.loc 1 104 1 view .LVU35
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
	.loc 1 107 1 is_stmt 0 view .LVU37
	movl	4(%esp), %eax
	.loc 1 108 2 is_stmt 1 view .LVU38
	.loc 1 108 23 is_stmt 0 view .LVU39
	cmpl	$-1, %eax
	je	.L15
	.loc 1 108 40 discriminator 1 view .LVU40
	movzbl	%al, %eax
	.loc 1 108 39 discriminator 1 view .LVU41
	movzbl	_ctype_+1(%eax), %eax
	.loc 1 108 23 discriminator 1 view .LVU42
	andl	$23, %eax
	ret
.LVL13:
.L15:
	.loc 1 108 23 view .LVU43
	movl	$0, %eax
.LVL14:
	.loc 1 109 1 view .LVU44
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
	.loc 1 112 1 is_stmt 0 view .LVU46
	movl	4(%esp), %eax
	.loc 1 113 2 is_stmt 1 view .LVU47
	.loc 1 113 23 is_stmt 0 view .LVU48
	cmpl	$-1, %eax
	je	.L18
	.loc 1 113 40 discriminator 1 view .LVU49
	movzbl	%al, %eax
	.loc 1 113 39 discriminator 1 view .LVU50
	movzbl	_ctype_+1(%eax), %eax
	.loc 1 113 23 discriminator 1 view .LVU51
	andl	$2, %eax
	ret
.LVL16:
.L18:
	.loc 1 113 23 view .LVU52
	movl	$0, %eax
.LVL17:
	.loc 1 114 1 view .LVU53
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
	.loc 1 117 1 is_stmt 0 view .LVU55
	movl	4(%esp), %eax
	.loc 1 118 2 is_stmt 1 view .LVU56
	.loc 1 118 23 is_stmt 0 view .LVU57
	cmpl	$-1, %eax
	je	.L21
	.loc 1 118 40 discriminator 1 view .LVU58
	movzbl	%al, %eax
	.loc 1 118 39 discriminator 1 view .LVU59
	movsbl	_ctype_+1(%eax), %eax
	.loc 1 118 23 discriminator 1 view .LVU60
	andl	$151, %eax
	ret
.LVL19:
.L21:
	.loc 1 118 23 view .LVU61
	movl	$0, %eax
.LVL20:
	.loc 1 119 1 view .LVU62
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
	.loc 1 122 1 is_stmt 0 view .LVU64
	movl	4(%esp), %eax
	.loc 1 123 2 is_stmt 1 view .LVU65
	.loc 1 123 23 is_stmt 0 view .LVU66
	cmpl	$-1, %eax
	je	.L24
	.loc 1 123 40 discriminator 1 view .LVU67
	movzbl	%al, %eax
	.loc 1 123 39 discriminator 1 view .LVU68
	movzbl	_ctype_+1(%eax), %eax
	.loc 1 123 23 discriminator 1 view .LVU69
	andl	$16, %eax
	ret
.LVL22:
.L24:
	.loc 1 123 23 view .LVU70
	movl	$0, %eax
.LVL23:
	.loc 1 124 1 view .LVU71
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
	.loc 1 127 1 is_stmt 0 view .LVU73
	movl	4(%esp), %eax
	.loc 1 128 2 is_stmt 1 view .LVU74
	.loc 1 128 23 is_stmt 0 view .LVU75
	cmpl	$-1, %eax
	je	.L27
	.loc 1 128 40 discriminator 1 view .LVU76
	movzbl	%al, %eax
	.loc 1 128 39 discriminator 1 view .LVU77
	movzbl	_ctype_+1(%eax), %eax
	.loc 1 128 23 discriminator 1 view .LVU78
	andl	$8, %eax
	ret
.LVL25:
.L27:
	.loc 1 128 23 view .LVU79
	movl	$0, %eax
.LVL26:
	.loc 1 129 1 view .LVU80
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
	.loc 1 132 1 is_stmt 0 view .LVU82
	movl	4(%esp), %eax
	.loc 1 133 2 is_stmt 1 view .LVU83
	.loc 1 133 23 is_stmt 0 view .LVU84
	cmpl	$-1, %eax
	je	.L30
	.loc 1 133 40 discriminator 1 view .LVU85
	movzbl	%al, %eax
	.loc 1 133 39 discriminator 1 view .LVU86
	movzbl	_ctype_+1(%eax), %eax
	.loc 1 133 23 discriminator 1 view .LVU87
	andl	$1, %eax
	ret
.LVL28:
.L30:
	.loc 1 133 23 view .LVU88
	movl	$0, %eax
.LVL29:
	.loc 1 134 1 view .LVU89
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
	.loc 1 137 1 is_stmt 0 view .LVU91
	movl	4(%esp), %eax
	.loc 1 138 2 is_stmt 1 view .LVU92
	.loc 1 138 23 is_stmt 0 view .LVU93
	cmpl	$-1, %eax
	je	.L33
	.loc 1 138 40 discriminator 1 view .LVU94
	movzbl	%al, %eax
	.loc 1 138 39 discriminator 1 view .LVU95
	movzbl	_ctype_+1(%eax), %eax
	.loc 1 138 23 discriminator 1 view .LVU96
	andl	$68, %eax
	ret
.LVL31:
.L33:
	.loc 1 138 23 view .LVU97
	movl	$0, %eax
.LVL32:
	.loc 1 139 1 view .LVU98
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
	.long	0x25a
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.long	.LASF12
	.byte	0xc
	.long	.LASF13
	.long	.LASF14
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	.Ldebug_line0
	.uleb128 0x2
	.long	0x49
	.long	0x36
	.uleb128 0x3
	.long	0x3b
	.value	0x100
	.byte	0
	.uleb128 0x4
	.long	0x25
	.uleb128 0x5
	.byte	0x4
	.byte	0x7
	.long	.LASF0
	.uleb128 0x5
	.byte	0x1
	.byte	0x6
	.long	.LASF1
	.uleb128 0x4
	.long	0x42
	.uleb128 0x6
	.long	.LASF15
	.byte	0x1
	.byte	0x31
	.byte	0xc
	.long	0x36
	.uleb128 0x5
	.byte	0x3
	.long	_ctype_
	.uleb128 0x7
	.long	.LASF2
	.byte	0x1
	.byte	0x88
	.byte	0x5
	.long	0x8e
	.long	.LFB10
	.long	.LFE10-.LFB10
	.uleb128 0x1
	.byte	0x9c
	.long	0x8e
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x88
	.byte	0x12
	.long	0x8e
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
	.long	0x8e
	.long	.LFB9
	.long	.LFE9-.LFB9
	.uleb128 0x1
	.byte	0x9c
	.long	0xc3
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x83
	.byte	0x11
	.long	0x8e
	.long	.LLST9
	.long	.LVUS9
	.byte	0
	.uleb128 0x7
	.long	.LASF4
	.byte	0x1
	.byte	0x7e
	.byte	0x5
	.long	0x8e
	.long	.LFB8
	.long	.LFE8-.LFB8
	.uleb128 0x1
	.byte	0x9c
	.long	0xf1
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x7e
	.byte	0x11
	.long	0x8e
	.long	.LLST8
	.long	.LVUS8
	.byte	0
	.uleb128 0x7
	.long	.LASF5
	.byte	0x1
	.byte	0x79
	.byte	0x5
	.long	0x8e
	.long	.LFB7
	.long	.LFE7-.LFB7
	.uleb128 0x1
	.byte	0x9c
	.long	0x11f
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x79
	.byte	0x11
	.long	0x8e
	.long	.LLST7
	.long	.LVUS7
	.byte	0
	.uleb128 0x7
	.long	.LASF6
	.byte	0x1
	.byte	0x74
	.byte	0x5
	.long	0x8e
	.long	.LFB6
	.long	.LFE6-.LFB6
	.uleb128 0x1
	.byte	0x9c
	.long	0x14d
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x74
	.byte	0x11
	.long	0x8e
	.long	.LLST6
	.long	.LVUS6
	.byte	0
	.uleb128 0x7
	.long	.LASF7
	.byte	0x1
	.byte	0x6f
	.byte	0x5
	.long	0x8e
	.long	.LFB5
	.long	.LFE5-.LFB5
	.uleb128 0x1
	.byte	0x9c
	.long	0x17b
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x6f
	.byte	0x11
	.long	0x8e
	.long	.LLST5
	.long	.LVUS5
	.byte	0
	.uleb128 0x7
	.long	.LASF8
	.byte	0x1
	.byte	0x6a
	.byte	0x5
	.long	0x8e
	.long	.LFB4
	.long	.LFE4-.LFB4
	.uleb128 0x1
	.byte	0x9c
	.long	0x1a9
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x6a
	.byte	0x11
	.long	0x8e
	.long	.LLST4
	.long	.LVUS4
	.byte	0
	.uleb128 0x7
	.long	.LASF9
	.byte	0x1
	.byte	0x65
	.byte	0x5
	.long	0x8e
	.long	.LFB3
	.long	.LFE3-.LFB3
	.uleb128 0x1
	.byte	0x9c
	.long	0x1d7
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x65
	.byte	0x11
	.long	0x8e
	.long	.LLST3
	.long	.LVUS3
	.byte	0
	.uleb128 0x7
	.long	.LASF10
	.byte	0x1
	.byte	0x60
	.byte	0x5
	.long	0x8e
	.long	.LFB2
	.long	.LFE2-.LFB2
	.uleb128 0x1
	.byte	0x9c
	.long	0x205
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x60
	.byte	0x11
	.long	0x8e
	.long	.LLST2
	.long	.LVUS2
	.byte	0
	.uleb128 0x7
	.long	.LASF11
	.byte	0x1
	.byte	0x5b
	.byte	0x5
	.long	0x8e
	.long	.LFB1
	.long	.LFE1-.LFB1
	.uleb128 0x1
	.byte	0x9c
	.long	0x233
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x5b
	.byte	0x11
	.long	0x8e
	.long	.LLST1
	.long	.LVUS1
	.byte	0
	.uleb128 0xa
	.long	.LASF16
	.byte	0x1
	.byte	0x56
	.byte	0x5
	.long	0x8e
	.long	.LFB0
	.long	.LFE0-.LFB0
	.uleb128 0x1
	.byte	0x9c
	.uleb128 0x8
	.string	"_c"
	.byte	0x1
	.byte	0x56
	.byte	0x11
	.long	0x8e
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
.Ldebug_loc0:
.LVUS10:
	.uleb128 0
	.uleb128 .LVU97
	.uleb128 .LVU97
	.uleb128 .LVU98
	.uleb128 .LVU98
	.uleb128 0
.LLST10:
	.long	.LVL30-.Ltext0
	.long	.LVL31-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL31-.Ltext0
	.long	.LVL32-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL32-.Ltext0
	.long	.LFE10-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LVUS9:
	.uleb128 0
	.uleb128 .LVU88
	.uleb128 .LVU88
	.uleb128 .LVU89
	.uleb128 .LVU89
	.uleb128 0
.LLST9:
	.long	.LVL27-.Ltext0
	.long	.LVL28-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL28-.Ltext0
	.long	.LVL29-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL29-.Ltext0
	.long	.LFE9-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LVUS8:
	.uleb128 0
	.uleb128 .LVU79
	.uleb128 .LVU79
	.uleb128 .LVU80
	.uleb128 .LVU80
	.uleb128 0
.LLST8:
	.long	.LVL24-.Ltext0
	.long	.LVL25-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL25-.Ltext0
	.long	.LVL26-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL26-.Ltext0
	.long	.LFE8-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LVUS7:
	.uleb128 0
	.uleb128 .LVU70
	.uleb128 .LVU70
	.uleb128 .LVU71
	.uleb128 .LVU71
	.uleb128 0
.LLST7:
	.long	.LVL21-.Ltext0
	.long	.LVL22-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL22-.Ltext0
	.long	.LVL23-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL23-.Ltext0
	.long	.LFE7-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LVUS6:
	.uleb128 0
	.uleb128 .LVU61
	.uleb128 .LVU61
	.uleb128 .LVU62
	.uleb128 .LVU62
	.uleb128 0
.LLST6:
	.long	.LVL18-.Ltext0
	.long	.LVL19-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL19-.Ltext0
	.long	.LVL20-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL20-.Ltext0
	.long	.LFE6-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LVUS5:
	.uleb128 0
	.uleb128 .LVU52
	.uleb128 .LVU52
	.uleb128 .LVU53
	.uleb128 .LVU53
	.uleb128 0
.LLST5:
	.long	.LVL15-.Ltext0
	.long	.LVL16-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL16-.Ltext0
	.long	.LVL17-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL17-.Ltext0
	.long	.LFE5-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LVUS4:
	.uleb128 0
	.uleb128 .LVU43
	.uleb128 .LVU43
	.uleb128 .LVU44
	.uleb128 .LVU44
	.uleb128 0
.LLST4:
	.long	.LVL12-.Ltext0
	.long	.LVL13-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL13-.Ltext0
	.long	.LVL14-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL14-.Ltext0
	.long	.LFE4-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LVUS3:
	.uleb128 0
	.uleb128 .LVU34
	.uleb128 .LVU34
	.uleb128 .LVU35
	.uleb128 .LVU35
	.uleb128 0
.LLST3:
	.long	.LVL9-.Ltext0
	.long	.LVL10-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL10-.Ltext0
	.long	.LVL11-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL11-.Ltext0
	.long	.LFE3-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LVUS2:
	.uleb128 0
	.uleb128 .LVU25
	.uleb128 .LVU25
	.uleb128 .LVU26
	.uleb128 .LVU26
	.uleb128 0
.LLST2:
	.long	.LVL6-.Ltext0
	.long	.LVL7-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL7-.Ltext0
	.long	.LVL8-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL8-.Ltext0
	.long	.LFE2-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LVUS1:
	.uleb128 0
	.uleb128 .LVU16
	.uleb128 .LVU16
	.uleb128 .LVU17
	.uleb128 .LVU17
	.uleb128 0
.LLST1:
	.long	.LVL3-.Ltext0
	.long	.LVL4-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL4-.Ltext0
	.long	.LVL5-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL5-.Ltext0
	.long	.LFE1-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
.LVUS0:
	.uleb128 0
	.uleb128 .LVU7
	.uleb128 .LVU7
	.uleb128 .LVU8
	.uleb128 .LVU8
	.uleb128 0
.LLST0:
	.long	.LVL0-.Ltext0
	.long	.LVL1-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	.LVL1-.Ltext0
	.long	.LVL2-.Ltext0
	.value	0x1
	.byte	0x50
	.long	.LVL2-.Ltext0
	.long	.LFE0-.Ltext0
	.value	0x2
	.byte	0x91
	.sleb128 0
	.long	0
	.long	0
	.section	.debug_aranges,"",@progbits
	.long	0x1c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x4
	.byte	0
	.value	0
	.value	0
	.long	.Ltext0
	.long	.Letext0-.Ltext0
	.long	0
	.long	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF13:
	.string	"/home/boricj/Documents/ghidra-delinker-extension/src/test/resources/ascii-table/src/ctype.c"
.LASF0:
	.string	"unsigned int"
.LASF15:
	.string	"_ctype_"
.LASF6:
	.string	"isprint"
.LASF12:
	.string	"GNU C17 12.2.0 -mtune=generic -march=i686 -gdwarf-4 -Og -ffreestanding -fno-pic -fno-plt -fasynchronous-unwind-tables"
.LASF8:
	.string	"isgraph"
.LASF7:
	.string	"islower"
.LASF16:
	.string	"isalnum"
.LASF5:
	.string	"ispunct"
.LASF10:
	.string	"iscntrl"
.LASF9:
	.string	"isdigit"
.LASF14:
	.string	"/home/boricj/Documents/ghidra-delinker-extension/src/test/resources/ascii-table/reference/elf_linux_freestanding"
.LASF2:
	.string	"isxdigit"
.LASF4:
	.string	"isspace"
.LASF11:
	.string	"isalpha"
.LASF1:
	.string	"char"
.LASF3:
	.string	"isupper"
	.ident	"GCC: (Debian 12.2.0-14) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
