	.file	"digits.c"
	.section	.ctf,"",@progbits
.Lctf0:
	.value	0xdff2
	.byte	0x4
	.byte	0x2
	.long	0
	.long	0
	.long	0x20
	.long	0
	.long	0
	.long	0x4
	.long	0x4
	.long	0x8
	.long	0x8
	.long	0x10
	.long	0x60
	.long	0x9a
	.long	0x5
	.long	0x17
	.long	0x17
	.long	0x5
	.long	0x1
	.long	0x6000000
	.long	0x4
	.long	0x1000020
	.long	0
	.long	0x32000000
	.long	0x1
	.long	0x5
	.long	0x6000000
	.long	0x8
	.long	0x40
	.long	0
	.long	0x12000000
	.long	0
	.long	0x2
	.long	0x3
	.long	0xa
	.long	0
	.long	0x32000000
	.long	0x4
	.string	""
	.string	"int"
	.string	"long unsigned int"
	.string	"s_digits"
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing/src/digits.c"
	.text
.Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "src/digits.c"
	.globl	s_digits
	.section	.rodata
	.align 32
	.type	s_digits, @object
	.size	s_digits, 40
s_digits:
	.long	0
	.long	1
	.long	2
	.long	3
	.long	4
	.long	5
	.long	6
	.long	7
	.long	8
	.long	9
	.text
.Letext0:
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.long	0x58
	.value	0x4
	.long	.Ldebug_abbrev0
	.byte	0x8
	.uleb128 0x1
	.long	.LASF1
	.byte	0xc
	.long	.LASF2
	.long	.LASF3
	.long	.Ldebug_line0
	.uleb128 0x2
	.long	0x40
	.long	0x2d
	.uleb128 0x3
	.long	0x32
	.byte	0x9
	.byte	0
	.uleb128 0x4
	.long	0x1d
	.uleb128 0x5
	.byte	0x8
	.byte	0x7
	.long	.LASF0
	.uleb128 0x6
	.byte	0x4
	.byte	0x5
	.string	"int"
	.uleb128 0x4
	.long	0x39
	.uleb128 0x7
	.long	.LASF4
	.byte	0x1
	.byte	0x1
	.byte	0xb
	.long	0x2d
	.uleb128 0x9
	.byte	0x3
	.quad	s_digits
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
	.long	0x1c
	.value	0x2
	.long	.Ldebug_info0
	.byte	0x8
	.byte	0
	.value	0
	.value	0
	.quad	0
	.quad	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF3:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing"
.LASF1:
	.string	"GNU C17 12.2.0 -mtune=generic -march=x86-64 -gdwarf-4 -gctf -ffreestanding -fno-builtin -fno-pic -fno-asynchronous-unwind-tables -fno-unwind-tables"
.LASF4:
	.string	"s_digits"
.LASF5:
	.string	"void"
.LASF2:
	.string	"src/digits.c"
.LASF0:
	.string	"long unsigned int"
.LASF6:
	.string	"unknown"
	.ident	"GCC: (Debian 12.2.0-14+deb12u1) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
