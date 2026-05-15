	.386p
	ifdef ??version
	if ??version GT 500H
	.mmx
	endif
	endif
	model flat
	ifndef	??version
	?debug	macro
	endm
	endif
	?debug	S "src/main.c"
	?debug	T "src/main.c"
_TEXT	segment dword public use32 'CODE'
_TEXT	ends
_DATA	segment dword public use32 'DATA'
_DATA	ends
_BSS	segment dword public use32 'BSS'
_BSS	ends
$$BSYMS	segment byte public use32 'DEBSYM'
$$BSYMS	ends
$$BTYPES	segment byte public use32 'DEBTYP'
$$BTYPES	ends
$$BNAMES	segment byte public use32 'DEBNAM'
$$BNAMES	ends
$$BROWSE	segment byte public use32 'DEBSYM'
$$BROWSE	ends
$$BROWFILE	segment byte public use32 'DEBSYM'
$$BROWFILE	ends
DGROUP	group	_BSS,_DATA
_DATA	segment dword public use32 'DATA'
	align	4
_s_snapshot_1	label	byte
	dd	0
	dd	384
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	align	4
_s_snapshot_2	label	byte
	dd	_s_heap+32
	dd	-32
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	dd	_s_heap+64
	dd	-32
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	db	2
	dd	_s_heap+96
	dd	-32
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	dd	_s_heap+128
	dd	-32
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	db	4
	dd	_s_heap+192
	dd	-64
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	dd	_s_heap+256
	dd	-64
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	db	6
	dd	_s_heap+320
	dd	-64
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	dd	0
	dd	-64
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	db	8
	align	4
_s_snapshot_3	label	byte
	dd	_s_heap+32
	dd	-32
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	dd	_s_heap+64
	dd	32
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	dd	_s_heap+96
	dd	-32
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	db	3
	dd	_s_heap+128
	dd	32
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	dd	_s_heap+192
	dd	-64
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	dd	_s_heap+256
	dd	64
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	dd	_s_heap+320
	dd	-64
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	db	7
	dd	0
	dd	64
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	align	4
_s_snapshot_4	label	byte
	dd	_s_heap+32
	dd	-32
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	db	1
	dd	_s_heap+128
	dd	96
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	16	dup(?)
	dd	_s_heap+192
	dd	-64
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	db	5
	dd	0
	dd	192
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	align	4
_s_snapshot_5	label	byte
	dd	0
	dd	384
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	align	4
_s_heap_ranges	label	byte
	dd	_s_snapshot_1
	dd	_s_snapshot_1+384
	dd	_s_snapshot_2
	dd	_s_snapshot_2+384
	dd	_s_snapshot_3
	dd	_s_snapshot_3+384
	dd	_s_snapshot_4
	dd	_s_snapshot_4+384
	dd	_s_snapshot_5
	dd	_s_snapshot_5+384
_DATA	ends
_TEXT	segment dword public use32 'CODE'
_allocate_and_fill	proc	near
?live1@0:
 ;	
 ;	static void* allocate_and_fill(void *heap, size_t size, unsigned char pattern) {
 ;	
	?debug L 207
	push ebp
	mov ebp,esp
	push ecx
 ;	
 ;	    void *ptr = freelist_alloc(heap, size - sizeof(chunk_header));
 ;	
	?debug L 208
@1:
	mov eax,dword ptr [ebp+12]
	sub eax,8
	push eax
	push dword ptr [ebp+8]
	call _freelist_alloc
	add esp,8
	mov dword ptr [ebp-4],eax
 ;	
 ;	
 ;	    if (ptr == NULL) {
 ;	
	?debug L 210
	cmp dword ptr [ebp-4],0
	jne       short @2
 ;	
 ;	        return NULL;
 ;	
	?debug L 211
	xor eax,eax
@5:
	pop ecx
	pop ebp
	ret 
 ;	
 ;	    }
 ;	
 ;	    memset(ptr, pattern, size - sizeof(chunk_header));
 ;	
	?debug L 214
@2:
	mov edx,dword ptr [ebp+12]
	sub edx,8
	push edx
	xor ecx,ecx
	mov cl,byte ptr [ebp+16]
	push ecx
	push dword ptr [ebp-4]
	call _memset
	add esp,12
 ;	
 ;	    return ptr;
 ;	
	?debug L 215
	mov eax,dword ptr [ebp-4]
 ;	
 ;	}
 ;	
	?debug L 216
@4:
@3:
	pop ecx
	pop ebp
	ret 
	?debug L 0
_allocate_and_fill	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	db	2
	db	0
	db	0
	db	0
	dw	46
	dw	516
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch1
	dd	?patch2
	dd	?patch3
	df	_allocate_and_fill
	dw	0
	dw	4096
	dw	0
	dw	1
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	8
	dw	0
	dw	1027
	dw	0
	dw	2
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	12
	dw	0
	dw	117
	dw	0
	dw	3
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	16
	dw	0
	dw	32
	dw	0
	dw	4
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65532
	dw	65535
	dw	1027
	dw	0
	dw	5
	dw	0
	dw	0
	dw	0
	dw	8
	dw	530
	dd	@5-_allocate_and_fill
	dw	3
?patch1	equ	@4-_allocate_and_fill+3
?patch2	equ	0
?patch3	equ	@4-_allocate_and_fill
	dw	2
	dw	6
	dw	4
	dw	531
	dw	0
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_main	proc	near
?live1@128:
 ;	
 ;	int main(void) {
 ;	
	?debug L 218
	push ebp
	mov ebp,esp
	add esp,-44
 ;	
 ;	    void *heap = (void *) s_heap.bytes;
 ;	
	?debug L 219
@6:
	mov dword ptr [ebp-4],offset _s_heap
 ;	
 ;	    void *allocations[8];
 ;	    size_t i;
 ;	    int ret;
 ;	
 ;	    /* Check initial heap state. */
 ;	    freelist_init(heap, 384);
 ;	
	?debug L 225
	push 384
	push dword ptr [ebp-4]
	call _freelist_init
	add esp,8
 ;	
 ;	
 ;	    ret = memcmp(heap, s_heap_ranges[0].start, s_heap_ranges[0].end - s_heap_ranges[0].start);
 ;	
	?debug L 227
	mov eax,offset _s_heap_ranges
	mov edx,dword ptr [_s_heap_ranges+4]
	sub edx,dword ptr [eax]
	push edx
	mov ecx,offset _s_heap_ranges
	push dword ptr [ecx]
	push dword ptr [ebp-4]
	call _memcmp
	add esp,12
	mov dword ptr [ebp-12],eax
 ;	
 ;	    if (ret != 0) {
 ;	
	?debug L 228
	cmp dword ptr [ebp-12],0
	je        short @7
 ;	
 ;	        return ret;
 ;	
	?debug L 229
	mov eax,dword ptr [ebp-12]
	jmp @8
 ;	
 ;	    }
 ;	
 ;	    /* Check full heap state. */
 ;	    for (i = 0; i < 8; i++) {
 ;	
	?debug L 233
@7:
	xor edx,edx
	mov dword ptr [ebp-8],edx
 ;	
 ;	        allocations[i] = allocate_and_fill(heap, i < 4 ? 32 : 64, i + 1);
 ;	
	?debug L 234
@9:
	mov cl,byte ptr [ebp-8]
	inc ecx
	push ecx
	cmp dword ptr [ebp-8],4
	jae       short @11
	mov eax,32
	jmp short @12
@11:
	mov eax,64
@12:
	push eax
	push dword ptr [ebp-4]
	call _allocate_and_fill
	add esp,12
	mov edx,dword ptr [ebp-8]
	mov dword ptr [ebp+4*edx-44],eax
	inc dword ptr [ebp-8]
	cmp dword ptr [ebp-8],8
	jb        short @9
 ;	
 ;	    }
 ;	
 ;	    ret = memcmp(heap, s_heap_ranges[1].start, s_heap_ranges[1].end - s_heap_ranges[1].start);
 ;	
	?debug L 237
	mov ecx,offset _s_heap_ranges+8
	mov eax,dword ptr [_s_heap_ranges+12]
	sub eax,dword ptr [ecx]
	push eax
	mov edx,offset _s_heap_ranges+8
	push dword ptr [edx]
	push dword ptr [ebp-4]
	call _memcmp
	add esp,12
	mov dword ptr [ebp-12],eax
 ;	
 ;	    if (ret != 0) {
 ;	
	?debug L 238
	cmp dword ptr [ebp-12],0
	je        short @14
 ;	
 ;	        return ret;
 ;	
	?debug L 239
	mov eax,dword ptr [ebp-12]
	jmp @8
 ;	
 ;	    }
 ;	
 ;	    /* Check heap with free chunks. */
 ;	    for (i = 1; i < 8; i += 2) {
 ;	
	?debug L 243
@14:
	mov dword ptr [ebp-8],1
 ;	
 ;	        freelist_free(heap, allocations[i]);
 ;	
	?debug L 244
@15:
	mov edx,dword ptr [ebp-8]
	push dword ptr [ebp+4*edx-44]
	push dword ptr [ebp-4]
	call _freelist_free
	add esp,8
	add dword ptr [ebp-8],2
	cmp dword ptr [ebp-8],8
	jb        short @15
 ;	
 ;	    }
 ;	
 ;	    ret = memcmp(heap, s_heap_ranges[2].start, s_heap_ranges[2].end - s_heap_ranges[2].start);
 ;	
	?debug L 247
	mov ecx,offset _s_heap_ranges+16
	mov eax,dword ptr [_s_heap_ranges+20]
	sub eax,dword ptr [ecx]
	push eax
	mov edx,offset _s_heap_ranges+16
	push dword ptr [edx]
	push dword ptr [ebp-4]
	call _memcmp
	add esp,12
	mov dword ptr [ebp-12],eax
 ;	
 ;	    if (ret != 0) {
 ;	
	?debug L 248
	cmp dword ptr [ebp-12],0
	je        short @18
 ;	
 ;	        return ret;
 ;	
	?debug L 249
	mov eax,dword ptr [ebp-12]
	jmp @8
 ;	
 ;	    }
 ;	
 ;	    /* Check free chunk coalescing. */
 ;	    for (i = 2; i < 8; i += 4) {
 ;	
	?debug L 253
@18:
	mov dword ptr [ebp-8],2
 ;	
 ;	        freelist_free(heap, allocations[i]);
 ;	
	?debug L 254
@19:
	mov edx,dword ptr [ebp-8]
	push dword ptr [ebp+4*edx-44]
	push dword ptr [ebp-4]
	call _freelist_free
	add esp,8
	add dword ptr [ebp-8],4
	cmp dword ptr [ebp-8],8
	jb        short @19
 ;	
 ;	    }
 ;	
 ;	    ret = memcmp(heap, s_heap_ranges[3].start, s_heap_ranges[3].end - s_heap_ranges[3].start);
 ;	
	?debug L 257
	mov ecx,offset _s_heap_ranges+24
	mov eax,dword ptr [_s_heap_ranges+28]
	sub eax,dword ptr [ecx]
	push eax
	mov edx,offset _s_heap_ranges+24
	push dword ptr [edx]
	push dword ptr [ebp-4]
	call _memcmp
	add esp,12
	mov dword ptr [ebp-12],eax
 ;	
 ;	    if (ret != 0) {
 ;	
	?debug L 258
	cmp dword ptr [ebp-12],0
	je        short @22
 ;	
 ;	        return ret;
 ;	
	?debug L 259
	mov eax,dword ptr [ebp-12]
	jmp short @8
 ;	
 ;	    }
 ;	
 ;	    /* Check final empty heap state. */
 ;	    for (i = 0; i < 8; i += 4) {
 ;	
	?debug L 263
@22:
	xor edx,edx
	mov dword ptr [ebp-8],edx
 ;	
 ;	        freelist_free(heap, allocations[i]);
 ;	
	?debug L 264
@23:
	mov ecx,dword ptr [ebp-8]
	push dword ptr [ebp+4*ecx-44]
	push dword ptr [ebp-4]
	call _freelist_free
	add esp,8
	add dword ptr [ebp-8],4
	cmp dword ptr [ebp-8],8
	jb        short @23
 ;	
 ;	    }
 ;	    
 ;	    ret = memcmp(heap, s_heap_ranges[4].start, s_heap_ranges[4].end - s_heap_ranges[4].start);
 ;	
	?debug L 267
	mov eax,offset _s_heap_ranges+32
	mov edx,dword ptr [_s_heap_ranges+36]
	sub edx,dword ptr [eax]
	push edx
	mov ecx,offset _s_heap_ranges+32
	push dword ptr [ecx]
	push dword ptr [ebp-4]
	call _memcmp
	add esp,12
	mov dword ptr [ebp-12],eax
 ;	
 ;	    if (ret == 0) {
 ;	
	?debug L 268
	cmp dword ptr [ebp-12],0
	jne       short @26
 ;	
 ;	        puts("All tests passed.");
 ;	
	?debug L 269
	push offset s@
	call _puts
	pop ecx
 ;	
 ;	    }
 ;	
 ;	    return ret;
 ;	
	?debug L 272
@26:
	mov eax,dword ptr [ebp-12]
 ;	
 ;	}
 ;	
	?debug L 273
@27:
@8:
	mov esp,ebp
	pop ebp
	ret 
	?debug L 0
_main	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	52
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch4
	dd	?patch5
	dd	?patch6
	df	_main
	dw	0
	dw	4098
	dw	0
	dw	6
	dw	0
	dw	0
	dw	0
	db	5
	db	95
	db	109
	db	97
	db	105
	db	110
	dw	18
	dw	512
	dw	65524
	dw	65535
	dw	116
	dw	0
	dw	7
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65528
	dw	65535
	dw	117
	dw	0
	dw	8
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65492
	dw	65535
	dw	4100
	dw	0
	dw	9
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65532
	dw	65535
	dw	1027
	dw	0
	dw	10
	dw	0
	dw	0
	dw	0
?patch4	equ	@27-_main+4
?patch5	equ	0
?patch6	equ	@27-_main
	dw	2
	dw	6
	dw	4
	dw	531
	dw	0
$$BSYMS	ends
_BSS	segment dword public use32 'BSS'
	align	4
_s_heap	label	byte
	db	384	dup(?)
_BSS	ends
_DATA	segment dword public use32 'DATA'
s@	label	byte
	;	s@+0:
	db	"All tests passed.",0
	align	4
_DATA	ends
_TEXT	segment dword public use32 'CODE'
_TEXT	ends
	public	_s_heap
	public	_s_snapshot_1
	public	_s_snapshot_2
	public	_s_snapshot_3
	public	_s_snapshot_4
	public	_s_snapshot_5
	public	_s_heap_ranges
 extrn _freelist_alloc:near
 extrn _memset:near
	public	_main
 extrn _freelist_init:near
 extrn _memcmp:near
 extrn _freelist_free:near
 extrn _puts:near
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	22
	dw	514
	df	_s_heap
	dw	0
	dw	4101
	dw	0
	dw	61
	dw	0
	dw	0
	dw	0
	dw	22
	dw	514
	df	_s_snapshot_1
	dw	0
	dw	4104
	dw	0
	dw	62
	dw	0
	dw	0
	dw	0
	dw	22
	dw	514
	df	_s_snapshot_2
	dw	0
	dw	4113
	dw	0
	dw	63
	dw	0
	dw	0
	dw	0
	dw	22
	dw	514
	df	_s_snapshot_3
	dw	0
	dw	4122
	dw	0
	dw	64
	dw	0
	dw	0
	dw	0
	dw	22
	dw	514
	df	_s_snapshot_4
	dw	0
	dw	4125
	dw	0
	dw	65
	dw	0
	dw	0
	dw	0
	dw	22
	dw	514
	df	_s_snapshot_5
	dw	0
	dw	4134
	dw	0
	dw	66
	dw	0
	dw	0
	dw	0
	dw	22
	dw	514
	df	_s_heap_ranges
	dw	0
	dw	4137
	dw	0
	dw	67
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	117
	dw	0
	dw	0
	dw	68
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	116
	dw	0
	dw	0
	dw	69
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	33
	dw	0
	dw	0
	dw	70
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	33
	dw	0
	dw	0
	dw	71
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	33
	dw	0
	dw	0
	dw	72
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4107
	dw	0
	dw	1
	dw	73
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4107
	dw	0
	dw	0
	dw	74
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	18
	dw	0
	dw	0
	dw	75
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4115
	dw	0
	dw	1
	dw	76
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4118
	dw	0
	dw	1
	dw	77
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4127
	dw	0
	dw	1
	dw	78
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4130
	dw	0
	dw	1
	dw	79
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4106
	dw	0
	dw	1
	dw	80
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4105
	dw	0
	dw	1
	dw	81
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4114
	dw	0
	dw	1
	dw	82
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4123
	dw	0
	dw	1
	dw	83
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4126
	dw	0
	dw	1
	dw	84
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4135
	dw	0
	dw	1
	dw	85
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4139
	dw	0
	dw	1
	dw	86
	dw	0
	dw	0
	dw	0
	dw	?patch7
	dw	1
	db	3
	db	0
	db	0
	db	24
	db	9
	db	66
	db	67
	db	67
	db	51
	db	50
	db	32
	db	53
	db	46
	db	54
?patch7	equ	16
$$BSYMS	ends
$$BTYPES	segment byte public use32 'DEBTYP'
	db 2,0,0,0,14,0,8,0,3,4,0,0,0,0,3,0
	db 1,16,0,0,16,0,1,2,3,0,3,4,0,0,117,0
	db 0,0,32,0,0,0,14,0,8,0,116,0,0,0,0,0
	db 0,0,3,16,0,0,4,0,1,2,0,0,18,0,3,0
	db 3,4,0,0,17,0,0,0,0,0,0,0,32,0,8,0
	db 20,0,6,0,2,0,7,16,0,0,0,0,0,0,0,0
	db 0,0,0,0,128,1,18,0,3,0,32,0,0,0,17,0
	db 0,0,0,0,0,0,128,1,128,1,40,0,4,2,6,4
	db 3,4,0,0,0,0,11,0,0,0,0,0,0,0,0,0
	db 242,241,6,4,6,16,0,0,0,0,12,0,0,0,0,0
	db 0,0,0,0,8,0,1,0,1,0,9,16,0,0,28,0
	db 5,0,1,0,16,16,0,0,0,0,0,0,0,0,0,0
	db 0,0,0,0,0,0,13,0,0,0,128,1,28,0,5,0
	db 2,0,15,16,0,0,0,0,0,0,0,0,0,0,0,0
	db 0,0,0,0,14,0,0,0,128,1,28,0,5,0,2,0
	db 13,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	db 0,0,15,0,0,0,8,0,8,0,2,0,10,0,11,16
	db 0,0,40,0,4,2,6,4,12,16,0,0,0,0,16,0
	db 0,0,0,0,0,0,0,0,242,241,6,4,116,0,0,0
	db 0,0,17,0,0,0,0,0,0,0,4,0,18,0,3,0
	db 32,0,0,0,17,0,0,0,0,0,0,0,120,1,120,1
	db 40,0,4,2,6,4,11,16,0,0,0,0,18,0,0,0
	db 0,0,0,0,0,0,242,241,6,4,14,16,0,0,0,0
	db 19,0,0,0,0,0,0,0,8,0,20,0,4,2,6,4
	db 10,16,0,0,0,0,20,0,0,0,0,0,0,0,0,0
	db 8,0,1,0,1,0,18,16,0,0,28,0,5,0,8,0
	db 25,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	db 0,0,21,0,0,0,128,1,28,0,5,0,2,0,21,16
	db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	db 22,0,0,0,32,0,18,0,3,0,32,0,0,0,17,0
	db 0,0,0,0,0,0,24,0,24,0,40,0,4,2,6,4
	db 11,16,0,0,0,0,23,0,0,0,0,0,0,0,0,0
	db 242,241,6,4,20,16,0,0,0,0,24,0,0,0,0,0
	db 0,0,8,0,28,0,5,0,2,0,24,16,0,0,0,0
	db 0,0,0,0,0,0,0,0,0,0,0,0,25,0,0,0
	db 64,0,18,0,3,0,32,0,0,0,17,0,0,0,0,0
	db 0,0,56,0,56,0,40,0,4,2,6,4,11,16,0,0
	db 0,0,26,0,0,0,0,0,0,0,0,0,242,241,6,4
	db 23,16,0,0,0,0,27,0,0,0,0,0,0,0,8,0
	db 160,0,4,2,6,4,19,16,0,0,0,0,28,0,0,0
	db 0,0,0,0,0,0,242,241,6,4,19,16,0,0,0,0
	db 29,0,0,0,0,0,0,0,32,0,242,241,6,4,19,16
	db 0,0,0,0,30,0,0,0,0,0,0,0,64,0,242,241
	db 6,4,19,16,0,0,0,0,31,0,0,0,0,0,0,0
	db 96,0,242,241,6,4,22,16,0,0,0,0,32,0,0,0
	db 0,0,0,0,128,0,242,241,6,4,22,16,0,0,0,0
	db 33,0,0,0,0,0,0,0,192,0,242,241,6,4,22,16
	db 0,0,0,0,34,0,0,0,0,0,0,0,0,1,242,241
	db 6,4,22,16,0,0,0,0,35,0,0,0,0,0,0,0
	db 64,1,8,0,1,0,1,0,27,16,0,0,28,0,5,0
	db 8,0,28,16,0,0,0,0,0,0,0,0,0,0,0,0
	db 0,0,0,0,36,0,0,0,128,1,160,0,4,2,6,4
	db 19,16,0,0,0,0,37,0,0,0,0,0,0,0,0,0
	db 242,241,6,4,19,16,0,0,0,0,38,0,0,0,0,0
	db 0,0,32,0,242,241,6,4,19,16,0,0,0,0,39,0
	db 0,0,0,0,0,0,64,0,242,241,6,4,19,16,0,0
	db 0,0,40,0,0,0,0,0,0,0,96,0,242,241,6,4
	db 22,16,0,0,0,0,41,0,0,0,0,0,0,0,128,0
	db 242,241,6,4,22,16,0,0,0,0,42,0,0,0,0,0
	db 0,0,192,0,242,241,6,4,22,16,0,0,0,0,43,0
	db 0,0,0,0,0,0,0,1,242,241,6,4,22,16,0,0
	db 0,0,44,0,0,0,0,0,0,0,64,1,8,0,1,0
	db 1,0,30,16,0,0,28,0,5,0,4,0,37,16,0,0
	db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,45,0
	db 0,0,128,1,28,0,5,0,2,0,33,16,0,0,0,0
	db 0,0,0,0,0,0,0,0,0,0,0,0,46,0,0,0
	db 96,0,18,0,3,0,32,0,0,0,17,0,0,0,0,0
	db 0,0,88,0,88,0,40,0,4,2,6,4,11,16,0,0
	db 0,0,47,0,0,0,0,0,0,0,0,0,242,241,6,4
	db 32,16,0,0,0,0,48,0,0,0,0,0,0,0,8,0
	db 28,0,5,0,2,0,36,16,0,0,0,0,0,0,0,0
	db 0,0,0,0,0,0,0,0,49,0,0,0,192,0,18,0
	db 3,0,32,0,0,0,17,0,0,0,0,0,0,0,184,0
	db 184,0,40,0,4,2,6,4,11,16,0,0,0,0,50,0
	db 0,0,0,0,0,0,0,0,242,241,6,4,35,16,0,0
	db 0,0,51,0,0,0,0,0,0,0,8,0,80,0,4,2
	db 6,4,19,16,0,0,0,0,52,0,0,0,0,0,0,0
	db 0,0,242,241,6,4,31,16,0,0,0,0,53,0,0,0
	db 0,0,0,0,32,0,242,241,6,4,22,16,0,0,0,0
	db 54,0,0,0,0,0,0,0,128,0,242,241,6,4,34,16
	db 0,0,0,0,55,0,0,0,0,0,0,0,192,0,8,0
	db 1,0,1,0,39,16,0,0,28,0,5,0,1,0,40,16
	db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	db 56,0,0,0,128,1,20,0,4,2,6,4,10,16,0,0
	db 0,0,57,0,0,0,0,0,0,0,0,0,8,0,1,0
	db 1,0,42,16,0,0,18,0,3,0,43,16,0,0,17,0
	db 0,0,0,0,0,0,40,0,5,0,28,0,5,0,2,0
	db 46,16,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	db 0,0,58,0,0,0,8,0,8,0,2,0,10,0,45,16
	db 0,0,8,0,1,0,1,0,32,0,0,0,40,0,4,2
	db 6,4,44,16,0,0,0,0,59,0,0,0,0,0,0,0
	db 0,0,242,241,6,4,44,16,0,0,0,0,60,0,0,0
	db 0,0,0,0,4,0,14,0,8,0,3,4,0,0,0,0
	db 2,0,48,16,0,0,12,0,1,2,2,0,3,4,0,0
	db 117,0,0,0,14,0,8,0,3,4,0,0,0,0,3,0
	db 50,16,0,0,16,0,1,2,3,0,3,4,0,0,116,0
	db 0,0,117,0,0,0,14,0,8,0,3,0,0,0,0,0
	db 2,0,52,16,0,0,12,0,1,2,2,0,3,4,0,0
	db 117,0,0,0,14,0,8,0,116,0,0,0,0,0,3,0
	db 56,16,0,0,8,0,2,0,10,0,55,16,0,0,8,0
	db 1,0,1,0,3,0,0,0,16,0,1,2,3,0,54,16
	db 0,0,54,16,0,0,117,0,0,0,14,0,8,0,3,0
	db 0,0,0,0,2,0,58,16,0,0,12,0,1,2,2,0
	db 3,4,0,0,3,4,0,0,14,0,8,0,116,0,0,0
	db 0,0,1,0,62,16,0,0,8,0,2,0,10,0,61,16
	db 0,0,8,0,1,0,1,0,16,0,0,0,8,0,1,2
	db 1,0,60,16,0,0
$$BTYPES	ends
$$BNAMES	segment byte public use32 'DEBNAM'
	db	17,'allocate_and_fill'
	db	4,'heap'
	db	4,'size'
	db	7,'pattern'
	db	3,'ptr'
	db	4,'main'
	db	3,'ret'
	db	1,'i'
	db	11,'allocations'
	db	4,'heap'
	db	6,'align_'
	db	5,'bytes'
	db	15,'heap_snapshot_1'
	db	9,'chunk_384'
	db	12,'chunk_header'
	db	4,'next'
	db	6,'length'
	db	6,'header'
	db	4,'data'
	db	7,'block_1'
	db	15,'heap_snapshot_2'
	db	8,'chunk_32'
	db	6,'header'
	db	4,'data'
	db	8,'chunk_64'
	db	6,'header'
	db	4,'data'
	db	7,'block_1'
	db	7,'block_2'
	db	7,'block_3'
	db	7,'block_4'
	db	7,'block_5'
	db	7,'block_6'
	db	7,'block_7'
	db	7,'block_8'
	db	15,'heap_snapshot_3'
	db	7,'block_1'
	db	7,'block_2'
	db	7,'block_3'
	db	7,'block_4'
	db	7,'block_5'
	db	7,'block_6'
	db	7,'block_7'
	db	7,'block_8'
	db	15,'heap_snapshot_4'
	db	8,'chunk_96'
	db	6,'header'
	db	4,'data'
	db	9,'chunk_192'
	db	6,'header'
	db	4,'data'
	db	7,'block_1'
	db	7,'block_2'
	db	7,'block_3'
	db	7,'block_4'
	db	15,'heap_snapshot_5'
	db	7,'block_1'
	db	10,'heap_range'
	db	5,'start'
	db	3,'end'
	db	6,'s_heap'
	db	12,'s_snapshot_1'
	db	12,'s_snapshot_2'
	db	12,'s_snapshot_3'
	db	12,'s_snapshot_4'
	db	12,'s_snapshot_5'
	db	13,'s_heap_ranges'
	db	6,'size_t'
	db	9,'ptrdiff_t'
	db	7,'wchar_t'
	db	6,'wint_t'
	db	8,'wctype_t'
	db	12,'chunk_header'
	db	12,'chunk_header'
	db	6,'fpos_t'
	db	8,'chunk_32'
	db	8,'chunk_64'
	db	8,'chunk_96'
	db	9,'chunk_192'
	db	9,'chunk_384'
	db	15,'heap_snapshot_1'
	db	15,'heap_snapshot_2'
	db	15,'heap_snapshot_3'
	db	15,'heap_snapshot_4'
	db	15,'heap_snapshot_5'
	db	10,'heap_range'
$$BNAMES	ends
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\mem.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_loc.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\oldstl/locale.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_str.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\string.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_nfile.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\stdio.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_null.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_defs.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_stddef.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\stddef.h" 11329 14336
	?debug	D "C:/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/include\allocator.h" 23686 26776
	?debug	D "src/main.c" 23691 45399
	end
