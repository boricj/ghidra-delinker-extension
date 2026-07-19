	.file	"digits.c"
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
	.4byte	0x1b
	.4byte	0
	.4byte	0
	.4byte	0x4
	.4byte	0x4
	.4byte	0x8
	.4byte	0x8
	.4byte	0x10
	.4byte	0x60
	.4byte	0x95
	.4byte	0x5
	.4byte	0x12
	.4byte	0x12
	.4byte	0x5
	.4byte	0x1
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x1000020
	.4byte	0
	.4byte	0x32000000
	.4byte	0x1
	.4byte	0x5
	.4byte	0x6000000
	.4byte	0x4
	.4byte	0x20
	.4byte	0
	.4byte	0x12000000
	.4byte	0
	.4byte	0x2
	.4byte	0x3
	.4byte	0xa
	.4byte	0
	.4byte	0x32000000
	.4byte	0x4
	.string	""
	.string	"int"
	.string	"unsigned int"
	.string	"s_digits"
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing/src/digits.c"
	.section	.text
.Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "src/digits.c"
	.global	s_digits
	.section	.rodata
	.align 4
	.type	s_digits, @object
	.size	s_digits, 40
s_digits:
	.word	0
	.word	1
	.word	2
	.word	3
	.word	4
	.word	5
	.word	6
	.word	7
	.word	8
	.word	9
	.section	.text
.Letext0:
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x54
	.2byte	0x4
	.4byte	@.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	@.LASF1
	.byte	0xc
	.4byte	@.LASF2
	.4byte	@.LASF3
	.4byte	@.Ldebug_line0
	.uleb128 0x2
	.4byte	0x40
	.4byte	0x2d
	.uleb128 0x3
	.4byte	0x32
	.byte	0x9
	.byte	0
	.uleb128 0x4
	.4byte	0x1d
	.uleb128 0x5
	.byte	0x4
	.byte	0x7
	.4byte	@.LASF0
	.uleb128 0x6
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x4
	.4byte	0x39
	.uleb128 0x7
	.4byte	@.LASF4
	.byte	0x1
	.byte	0x1
	.byte	0xb
	.4byte	0x2d
	.uleb128 0x5
	.byte	0x3
	.4byte	@s_digits
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
	.uleb128 0xb
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
	.uleb128 0x7
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
	.byte	0
	.section	.debug_aranges,"",@progbits
	.4byte	0x14
	.2byte	0x2
	.4byte	@.Ldebug_info0
	.byte	0x4
	.byte	0
	.2byte	0
	.2byte	0
	.4byte	0
	.4byte	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF3:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing"
.LASF1:
	.string	"GNU C17 12.2.0 -gdwarf-4 -gctf"
.LASF5:
	.string	"void"
.LASF0:
	.string	"unsigned int"
.LASF2:
	.string	"src/digits.c"
.LASF4:
	.string	"s_digits"
.LASF6:
	.string	"unknown"
	.ident	"GCC: (Debian 12.2.0-13) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
