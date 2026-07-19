#!/usr/bin/env python3

import argparse
import os

parser = argparse.ArgumentParser(
	prog='configure.py',
	description='Sets up a cross-compiling Ninja build of ascii-table',
)
parser.add_argument('srcpath', help='Path to source code directory')
parser.add_argument('--with-ctype', help='Use bundled ctype.h', action='store_true')
args = parser.parse_args()

filenames = [
	'main',
]

if args.with_ctype:
	filenames.append('ctype')

outputdir = os.getcwd()
srcdir = os.path.realpath(args.srcpath)

architectures = {
	'aarch64': {
		'AS': 'aarch64-linux-gnu-gcc',
		'CC': 'aarch64-linux-gnu-gcc',
		'LD': 'aarch64-linux-gnu-gcc',
		'AFLAGS': '',
		'CFLAGS': '',
		'LDFLAGS': '',
	},
	'amd64': {
		'AS': 'x86_64-linux-gnu-gcc',
		'CC': 'x86_64-linux-gnu-gcc',
		'LD': 'x86_64-linux-gnu-gcc',
		'AFLAGS': '',
		'CFLAGS': '',
		'LDFLAGS': '',
	},
	'arm': {
		'AS': 'arm-linux-gnueabihf-gcc',
		'CC': 'arm-linux-gnueabihf-gcc',
		'LD': 'arm-linux-gnueabihf-gcc',
		'AFLAGS': '',
		'CFLAGS': '',
		'LDFLAGS': '',
	},
	'i386': {
		'AS': 'i686-linux-gnu-gcc',
		'CC': 'i686-linux-gnu-gcc',
		'LD': 'i686-linux-gnu-gcc',
		'AFLAGS': '',
		'CFLAGS': '',
		'LDFLAGS': '',
	},
	'mips': {
		'AS': 'mips-linux-gnu-gcc',
		'CC': 'mips-linux-gnu-gcc',
		'LD': 'mips-linux-gnu-gcc',
		'AFLAGS': '',
		'CFLAGS': '-mno-check-zero-division',
		'LDFLAGS': '',
	},
	'mipsel': {
		'AS': 'mipsel-linux-gnu-gcc',
		'CC': 'mipsel-linux-gnu-gcc',
		'LD': 'mipsel-linux-gnu-gcc',
		'AFLAGS': '',
		'CFLAGS': '-mno-check-zero-division',
		'LDFLAGS': '',
	},
	'mips64': {
		'AS': 'mips64-linux-gnuabi64-gcc',
		'CC': 'mips64-linux-gnuabi64-gcc',
		'LD': 'mips64-linux-gnuabi64-gcc',
		'AFLAGS': '',
		'CFLAGS': '-mno-check-zero-division',
		'LDFLAGS': '',
	},
	'mips64el': {
		'AS': 'mips64el-linux-gnuabi64-gcc',
		'CC': 'mips64el-linux-gnuabi64-gcc',
		'LD': 'mips64el-linux-gnuabi64-gcc',
		'AFLAGS': '',
		'CFLAGS': '-mno-check-zero-division',
		'LDFLAGS': '',
	},
	'riscv64': {
		'AS': 'riscv64-linux-gnu-gcc',
		'CC': 'riscv64-linux-gnu-gcc',
		'LD': 'riscv64-linux-gnu-gcc',
		'AFLAGS': '',
		'CFLAGS': '',
		'LDFLAGS': '',
	},
	's390x': {
		'AS': 's390x-linux-gnu-gcc',
		'CC': 's390x-linux-gnu-gcc',
		'LD': 's390x-linux-gnu-gcc',
		'AFLAGS': '',
		'CFLAGS': '',
		'LDFLAGS': '',
	},
}

with open('build.ninja', 'w') as fp:
	for ARCH, architecture in architectures.items():
		locals().update(architecture)

		fp.write(f"{ARCH}_AFLAGS = {os.environ.get('AFLAGS', '')} {os.environ.get(f'{ARCH}_AFLAGS', '')} {AFLAGS}\n")
		fp.write(f"{ARCH}_CFLAGS = {os.environ.get('CFLAGS', '')} {os.environ.get(f'{ARCH}_CFLAGS', '')} {CFLAGS}\n")
		fp.write(f"{ARCH}_LDFLAGS = {os.environ.get('LDFLAGS', '')} {os.environ.get(f'{ARCH}_LDFLAGS', '')} {LDFLAGS}\n")
		fp.write('\n')

		fp.write(f"rule {ARCH}_CC\n")
		fp.write(f"  command = {CC} -S $in -o $out ${ARCH}_CFLAGS\n")
		fp.write(f"rule {ARCH}_CC_combine\n")
		fp.write(f"  command = {CC} -r $in -o $out ${ARCH}_CFLAGS\n")
		fp.write(f"rule {ARCH}_AS\n")
		fp.write(f"  command = {AS} -c $in -o $out ${ARCH}_AFLAGS\n")
		fp.write(f"rule {ARCH}_LD\n")
		fp.write(f"  command = {LD} $in -o $out ${ARCH}_LDFLAGS\n")
		fp.write('\n')

		object_files = []
		for filename in filenames:
			fp.write(f"build {outputdir}/{ARCH}/{filename}.S: {ARCH}_CC {srcdir}/src/{filename}.c\n")
			fp.write(f"build {outputdir}/{ARCH}/{filename}.o: {ARCH}_AS {outputdir}/{ARCH}/{filename}.S\n")
			object_files.append(f"{outputdir}/{ARCH}/{filename}.o")

		fp.write(f"build {outputdir}/{ARCH}/ascii-table.o: {ARCH}_CC_combine {' '.join(object_files)}\n")
		fp.write(f"build {outputdir}/{ARCH}/ascii-table.elf: {ARCH}_LD {outputdir}/{ARCH}/ascii-table.o\n")
		fp.write(f"build {ARCH}: phony {outputdir}/{ARCH}/ascii-table.elf\n")
		fp.write(f"default {ARCH}")
		fp.write('\n')
