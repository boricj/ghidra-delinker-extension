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
	?debug	S "src/openbsd_ctype.c"
	?debug	T "src/openbsd_ctype.c"
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
__openbsd_ctype_	label	byte
	db	0
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	40
	db	40
	db	40
	db	40
	db	40
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	32
	db	136
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
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
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	65
	db	65
	db	65
	db	65
	db	65
	db	65
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
	db	16
	db	16
	db	16
	db	16
	db	16
	db	16
	db	66
	db	66
	db	66
	db	66
	db	66
	db	66
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
	db	16
	db	16
	db	16
	db	16
	db	32
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
	db	0
_DATA	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_isalnum	proc	near
?live1@0:
 ;	
 ;	int openbsd_isalnum(int _c)
 ;	
	?debug L 86
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & (_U|_L|_N)));
 ;	
	?debug L 88
@1:
	cmp dword ptr [ebp+8],-1
	jne       short @2
	xor eax,eax
	jmp short @4
@2:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,7
 ;	
 ;	}
 ;	
	?debug L 89
@5:
@4:
	pop ebp
	ret 
	?debug L 0
_openbsd_isalnum	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	db	2
	db	0
	db	0
	db	0
	dw	63
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch1
	dd	?patch2
	dd	?patch3
	df	_openbsd_isalnum
	dw	0
	dw	4096
	dw	0
	dw	1
	dw	0
	dw	0
	dw	0
	db	16
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	97
	db	108
	db	110
	db	117
	db	109
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	2
	dw	0
	dw	0
	dw	0
?patch1	equ	@5-_openbsd_isalnum+2
?patch2	equ	0
?patch3	equ	@5-_openbsd_isalnum
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_isalpha	proc	near
?live1@64:
 ;	
 ;	int openbsd_isalpha(int _c)
 ;	
	?debug L 91
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & (_U|_L)));
 ;	
	?debug L 93
@6:
	cmp dword ptr [ebp+8],-1
	jne       short @7
	xor eax,eax
	jmp short @9
@7:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,3
 ;	
 ;	}
 ;	
	?debug L 94
@10:
@9:
	pop ebp
	ret 
	?debug L 0
_openbsd_isalpha	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	63
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
	df	_openbsd_isalpha
	dw	0
	dw	4098
	dw	0
	dw	3
	dw	0
	dw	0
	dw	0
	db	16
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	97
	db	108
	db	112
	db	104
	db	97
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	4
	dw	0
	dw	0
	dw	0
?patch4	equ	@10-_openbsd_isalpha+2
?patch5	equ	0
?patch6	equ	@10-_openbsd_isalpha
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_iscntrl	proc	near
?live1@128:
 ;	
 ;	int openbsd_iscntrl(int _c)
 ;	
	?debug L 96
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & _C));
 ;	
	?debug L 98
@11:
	cmp dword ptr [ebp+8],-1
	jne       short @12
	xor eax,eax
	jmp short @14
@12:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,32
 ;	
 ;	}
 ;	
	?debug L 99
@15:
@14:
	pop ebp
	ret 
	?debug L 0
_openbsd_iscntrl	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	63
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch7
	dd	?patch8
	dd	?patch9
	df	_openbsd_iscntrl
	dw	0
	dw	4100
	dw	0
	dw	5
	dw	0
	dw	0
	dw	0
	db	16
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	99
	db	110
	db	116
	db	114
	db	108
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	6
	dw	0
	dw	0
	dw	0
?patch7	equ	@15-_openbsd_iscntrl+2
?patch8	equ	0
?patch9	equ	@15-_openbsd_iscntrl
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_isdigit	proc	near
?live1@192:
 ;	
 ;	int openbsd_isdigit(int _c)
 ;	
	?debug L 101
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & _N));
 ;	
	?debug L 103
@16:
	cmp dword ptr [ebp+8],-1
	jne       short @17
	xor eax,eax
	jmp short @19
@17:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,4
 ;	
 ;	}
 ;	
	?debug L 104
@20:
@19:
	pop ebp
	ret 
	?debug L 0
_openbsd_isdigit	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	63
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch10
	dd	?patch11
	dd	?patch12
	df	_openbsd_isdigit
	dw	0
	dw	4102
	dw	0
	dw	7
	dw	0
	dw	0
	dw	0
	db	16
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	100
	db	105
	db	103
	db	105
	db	116
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	8
	dw	0
	dw	0
	dw	0
?patch10	equ	@20-_openbsd_isdigit+2
?patch11	equ	0
?patch12	equ	@20-_openbsd_isdigit
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_isgraph	proc	near
?live1@256:
 ;	
 ;	int openbsd_isgraph(int _c)
 ;	
	?debug L 106
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & (_P|_U|_L|_N)));
 ;	
	?debug L 108
@21:
	cmp dword ptr [ebp+8],-1
	jne       short @22
	xor eax,eax
	jmp short @24
@22:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,23
 ;	
 ;	}
 ;	
	?debug L 109
@25:
@24:
	pop ebp
	ret 
	?debug L 0
_openbsd_isgraph	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	63
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch13
	dd	?patch14
	dd	?patch15
	df	_openbsd_isgraph
	dw	0
	dw	4104
	dw	0
	dw	9
	dw	0
	dw	0
	dw	0
	db	16
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	103
	db	114
	db	97
	db	112
	db	104
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	10
	dw	0
	dw	0
	dw	0
?patch13	equ	@25-_openbsd_isgraph+2
?patch14	equ	0
?patch15	equ	@25-_openbsd_isgraph
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_islower	proc	near
?live1@320:
 ;	
 ;	int openbsd_islower(int _c)
 ;	
	?debug L 111
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & _L));
 ;	
	?debug L 113
@26:
	cmp dword ptr [ebp+8],-1
	jne       short @27
	xor eax,eax
	jmp short @29
@27:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,2
 ;	
 ;	}
 ;	
	?debug L 114
@30:
@29:
	pop ebp
	ret 
	?debug L 0
_openbsd_islower	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	63
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch16
	dd	?patch17
	dd	?patch18
	df	_openbsd_islower
	dw	0
	dw	4106
	dw	0
	dw	11
	dw	0
	dw	0
	dw	0
	db	16
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	108
	db	111
	db	119
	db	101
	db	114
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	12
	dw	0
	dw	0
	dw	0
?patch16	equ	@30-_openbsd_islower+2
?patch17	equ	0
?patch18	equ	@30-_openbsd_islower
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_isprint	proc	near
?live1@384:
 ;	
 ;	int openbsd_isprint(int _c)
 ;	
	?debug L 116
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & (_P|_U|_L|_N|_B)));
 ;	
	?debug L 118
@31:
	cmp dword ptr [ebp+8],-1
	jne       short @32
	xor eax,eax
	jmp short @34
@32:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,151
 ;	
 ;	}
 ;	
	?debug L 119
@35:
@34:
	pop ebp
	ret 
	?debug L 0
_openbsd_isprint	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	63
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch19
	dd	?patch20
	dd	?patch21
	df	_openbsd_isprint
	dw	0
	dw	4108
	dw	0
	dw	13
	dw	0
	dw	0
	dw	0
	db	16
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	112
	db	114
	db	105
	db	110
	db	116
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	14
	dw	0
	dw	0
	dw	0
?patch19	equ	@35-_openbsd_isprint+2
?patch20	equ	0
?patch21	equ	@35-_openbsd_isprint
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_ispunct	proc	near
?live1@448:
 ;	
 ;	int openbsd_ispunct(int _c)
 ;	
	?debug L 121
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & _P));
 ;	
	?debug L 123
@36:
	cmp dword ptr [ebp+8],-1
	jne       short @37
	xor eax,eax
	jmp short @39
@37:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,16
 ;	
 ;	}
 ;	
	?debug L 124
@40:
@39:
	pop ebp
	ret 
	?debug L 0
_openbsd_ispunct	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	63
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch22
	dd	?patch23
	dd	?patch24
	df	_openbsd_ispunct
	dw	0
	dw	4110
	dw	0
	dw	15
	dw	0
	dw	0
	dw	0
	db	16
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	112
	db	117
	db	110
	db	99
	db	116
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	16
	dw	0
	dw	0
	dw	0
?patch22	equ	@40-_openbsd_ispunct+2
?patch23	equ	0
?patch24	equ	@40-_openbsd_ispunct
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_isspace	proc	near
?live1@512:
 ;	
 ;	int openbsd_isspace(int _c)
 ;	
	?debug L 126
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & _S));
 ;	
	?debug L 128
@41:
	cmp dword ptr [ebp+8],-1
	jne       short @42
	xor eax,eax
	jmp short @44
@42:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,8
 ;	
 ;	}
 ;	
	?debug L 129
@45:
@44:
	pop ebp
	ret 
	?debug L 0
_openbsd_isspace	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	63
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch25
	dd	?patch26
	dd	?patch27
	df	_openbsd_isspace
	dw	0
	dw	4112
	dw	0
	dw	17
	dw	0
	dw	0
	dw	0
	db	16
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	115
	db	112
	db	97
	db	99
	db	101
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	18
	dw	0
	dw	0
	dw	0
?patch25	equ	@45-_openbsd_isspace+2
?patch26	equ	0
?patch27	equ	@45-_openbsd_isspace
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_isupper	proc	near
?live1@576:
 ;	
 ;	int openbsd_isupper(int _c)
 ;	
	?debug L 131
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & _U));
 ;	
	?debug L 133
@46:
	cmp dword ptr [ebp+8],-1
	jne       short @47
	xor eax,eax
	jmp short @49
@47:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,1
 ;	
 ;	}
 ;	
	?debug L 134
@50:
@49:
	pop ebp
	ret 
	?debug L 0
_openbsd_isupper	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	63
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch28
	dd	?patch29
	dd	?patch30
	df	_openbsd_isupper
	dw	0
	dw	4114
	dw	0
	dw	19
	dw	0
	dw	0
	dw	0
	db	16
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	117
	db	112
	db	112
	db	101
	db	114
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	20
	dw	0
	dw	0
	dw	0
?patch28	equ	@50-_openbsd_isupper+2
?patch29	equ	0
?patch30	equ	@50-_openbsd_isupper
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_openbsd_isxdigit	proc	near
?live1@640:
 ;	
 ;	int openbsd_isxdigit(int _c)
 ;	
	?debug L 136
	push ebp
	mov ebp,esp
 ;	
 ;	{
 ;		return (_c == -1 ? 0 : ((_openbsd_ctype_ + 1)[(unsigned char)_c] & (_N|_X)));
 ;	
	?debug L 138
@51:
	cmp dword ptr [ebp+8],-1
	jne       short @52
	xor eax,eax
	jmp short @54
@52:
	xor edx,edx
	mov dl,byte ptr [ebp+8]
	movsx eax,byte ptr [edx+__openbsd_ctype_+1]
	and eax,68
 ;	
 ;	}
 ;	
	?debug L 139
@55:
@54:
	pop ebp
	ret 
	?debug L 0
_openbsd_isxdigit	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	64
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch31
	dd	?patch32
	dd	?patch33
	df	_openbsd_isxdigit
	dw	0
	dw	4116
	dw	0
	dw	21
	dw	0
	dw	0
	dw	0
	db	17
	db	95
	db	111
	db	112
	db	101
	db	110
	db	98
	db	115
	db	100
	db	95
	db	105
	db	115
	db	120
	db	100
	db	105
	db	103
	db	105
	db	116
	dw	18
	dw	512
	dw	8
	dw	0
	dw	116
	dw	0
	dw	22
	dw	0
	dw	0
	dw	0
?patch31	equ	@55-_openbsd_isxdigit+2
?patch32	equ	0
?patch33	equ	@55-_openbsd_isxdigit
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_TEXT	ends
	public	__openbsd_ctype_
	public	_openbsd_isalnum
	public	_openbsd_isalpha
	public	_openbsd_iscntrl
	public	_openbsd_isdigit
	public	_openbsd_isgraph
	public	_openbsd_islower
	public	_openbsd_isprint
	public	_openbsd_ispunct
	public	_openbsd_isspace
	public	_openbsd_isupper
	public	_openbsd_isxdigit
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	22
	dw	514
	df	__openbsd_ctype_
	dw	0
	dw	4118
	dw	0
	dw	23
	dw	0
	dw	0
	dw	0
	dw	?patch34
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
?patch34	equ	16
$$BSYMS	ends
$$BTYPES	segment byte public use32 'DEBTYP'
	db 2,0,0,0,14,0,8,0,116,0,0,0,0,0,1,0
	db 1,16,0,0,8,0,1,2,1,0,116,0,0,0,14,0
	db 8,0,116,0,0,0,0,0,1,0,3,16,0,0,8,0
	db 1,2,1,0,116,0,0,0,14,0,8,0,116,0,0,0
	db 0,0,1,0,5,16,0,0,8,0,1,2,1,0,116,0
	db 0,0,14,0,8,0,116,0,0,0,0,0,1,0,7,16
	db 0,0,8,0,1,2,1,0,116,0,0,0,14,0,8,0
	db 116,0,0,0,0,0,1,0,9,16,0,0,8,0,1,2
	db 1,0,116,0,0,0,14,0,8,0,116,0,0,0,0,0
	db 1,0,11,16,0,0,8,0,1,2,1,0,116,0,0,0
	db 14,0,8,0,116,0,0,0,0,0,1,0,13,16,0,0
	db 8,0,1,2,1,0,116,0,0,0,14,0,8,0,116,0
	db 0,0,0,0,1,0,15,16,0,0,8,0,1,2,1,0
	db 116,0,0,0,14,0,8,0,116,0,0,0,0,0,1,0
	db 17,16,0,0,8,0,1,2,1,0,116,0,0,0,14,0
	db 8,0,116,0,0,0,0,0,1,0,19,16,0,0,8,0
	db 1,2,1,0,116,0,0,0,14,0,8,0,116,0,0,0
	db 0,0,1,0,21,16,0,0,8,0,1,2,1,0,116,0
	db 0,0,8,0,1,0,1,0,23,16,0,0,18,0,3,0
	db 16,0,0,0,17,0,0,0,0,0,0,0,1,1,1,1
$$BTYPES	ends
$$BNAMES	segment byte public use32 'DEBNAM'
	db	15,'openbsd_isalnum'
	db	2,'_c'
	db	15,'openbsd_isalpha'
	db	2,'_c'
	db	15,'openbsd_iscntrl'
	db	2,'_c'
	db	15,'openbsd_isdigit'
	db	2,'_c'
	db	15,'openbsd_isgraph'
	db	2,'_c'
	db	15,'openbsd_islower'
	db	2,'_c'
	db	15,'openbsd_isprint'
	db	2,'_c'
	db	15,'openbsd_ispunct'
	db	2,'_c'
	db	15,'openbsd_isspace'
	db	2,'_c'
	db	15,'openbsd_isupper'
	db	2,'_c'
	db	16,'openbsd_isxdigit'
	db	2,'_c'
	db	15,'_openbsd_ctype_'
$$BNAMES	ends
	?debug	D "src/openbsd_ctype.c" 23691 36615
	end
