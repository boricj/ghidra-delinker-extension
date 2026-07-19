	.file	"digits.c"
	.option nopic
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
	.4byte	0x20
	.4byte	0
	.4byte	0
	.4byte	0x4
	.4byte	0x4
	.4byte	0x8
	.4byte	0x8
	.4byte	0x10
	.4byte	0x60
	.4byte	0x9a
	.4byte	0x5
	.4byte	0x17
	.4byte	0x17
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
	.4byte	0x8
	.4byte	0x40
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
	.string	"long unsigned int"
	.string	"s_digits"
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing/src/digits.c"
	.text
.Ltext0:
	.cfi_sections	.debug_frame
	.file 1 "src/digits.c"
	.globl	s_digits
	.section	.rodata
	.align	3
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
	.text
.Letext0:
	.section	.debug_info,"",@progbits
.Ldebug_info0:
	.4byte	0x58
	.2byte	0x4
	.4byte	.Ldebug_abbrev0
	.byte	0x8
	.byte	0x1
	.4byte	.LASF1
	.byte	0xc
	.4byte	.LASF2
	.4byte	.LASF3
	.4byte	.Ldebug_line0
	.byte	0x2
	.4byte	0x40
	.4byte	0x2d
	.byte	0x3
	.4byte	0x32
	.byte	0x9
	.byte	0
	.byte	0x4
	.4byte	0x1d
	.byte	0x5
	.byte	0x8
	.byte	0x7
	.4byte	.LASF0
	.byte	0x6
	.byte	0x4
	.byte	0x5
	.string	"int"
	.byte	0x4
	.4byte	0x39
	.byte	0x7
	.4byte	.LASF4
	.byte	0x1
	.byte	0x1
	.byte	0xb
	.4byte	0x2d
	.byte	0x9
	.byte	0x3
	.8byte	s_digits
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
	.byte	0x10
	.byte	0x17
	.byte	0
	.byte	0
	.byte	0x2
	.byte	0x1
	.byte	0x1
	.byte	0x49
	.byte	0x13
	.byte	0x1
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x3
	.byte	0x21
	.byte	0
	.byte	0x49
	.byte	0x13
	.byte	0x2f
	.byte	0xb
	.byte	0
	.byte	0
	.byte	0x4
	.byte	0x26
	.byte	0
	.byte	0x49
	.byte	0x13
	.byte	0
	.byte	0
	.byte	0x5
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
	.byte	0x6
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
	.byte	0x7
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
	.byte	0x3f
	.byte	0x19
	.byte	0x2
	.byte	0x18
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",@progbits
	.4byte	0x1c
	.2byte	0x2
	.4byte	.Ldebug_info0
	.byte	0x8
	.byte	0
	.2byte	0
	.2byte	0
	.8byte	0
	.8byte	0
	.section	.debug_line,"",@progbits
.Ldebug_line0:
	.section	.debug_str,"MS",@progbits,1
.LASF3:
	.string	"/mnt/c/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/integer-parsing"
.LASF4:
	.string	"s_digits"
.LASF1:
	.string	"GNU C17 12.2.0 -mabi=lp64d -misa-spec=20191213 -march=rv64imafdc_zicsr_zifencei -gdwarf-4 -gctf -ffreestanding -fno-builtin -fno-pic -fno-asynchronous-unwind-tables -fno-unwind-tables"
.LASF2:
	.string	"src/digits.c"
.LASF5:
	.string	"void"
.LASF0:
	.string	"long unsigned int"
.LASF6:
	.string	"unknown"
	.ident	"GCC: (Debian 12.2.0-13) 12.2.0"
	.section	.note.GNU-stack,"",@progbits
