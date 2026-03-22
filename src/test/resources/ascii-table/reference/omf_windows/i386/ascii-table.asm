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
	?debug	S ".\ascii-table.c"
	?debug	T ".\ascii-table.c"
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
_NUM_ASCII_PROPERTIES	label	dword
	dd	10
	align	4
_s_ascii_properties	label	byte
	dd	_isgraph
	db	103
	db	3	dup(?)
	dd	_isprint
	db	112
	db	3	dup(?)
	dd	_iscntrl
	db	99
	db	3	dup(?)
	dd	_isspace
	db	115
	db	3	dup(?)
	dd	_ispunct
	db	33
	db	3	dup(?)
	dd	_isalnum
	db	65
	db	3	dup(?)
	dd	_isalpha
	db	97
	db	3	dup(?)
	dd	_isdigit
	db	100
	db	3	dup(?)
	dd	_isupper
	db	85
	db	3	dup(?)
	dd	_islower
	db	108
	db	3	dup(?)
	align	4
_COLUMNS	label	dword
	dd	4
_DATA	ends
_TEXT	segment dword public use32 'CODE'
_print_number	proc	near
?live1@0:
 ;	
 ;	void print_number(int num) {
 ;	
	?debug L 25
	push ebp
	mov ebp,esp
	push ebx
	push esi
	push edi
	mov esi,dword ptr [ebp+8]
	mov edi,offset __streams
 ;	
 ;	    int n;
 ;	
 ;	    for (n = 3; n >= 0; n--) {
 ;	
	?debug L 28
?live1@16: ; ESI = num, EDI = &_streams
@1:
	mov ebx,3
 ;	
 ;	        int digit = (num >> (4 * n)) % 16;
 ;	
	?debug L 29
?live1@32: ; EBX = n, ESI = num, EDI = &_streams
@2:
@4:
	mov ecx,ebx
	shl ecx,2
	mov eax,esi
	sar eax,cl
	and eax,-2147483633
	jns       short @5
	dec eax
	or eax,-16
	inc eax
 ;	
 ;	
 ;	        if (digit < 10)
 ;	
	?debug L 31
?live1@48: ; EAX = digit, EBX = n, ESI = num, EDI = &_streams
@5:
	cmp eax,10
	jge       short @6
 ;	
 ;	            putchar('0' + digit);
 ;	
	?debug L 32
	inc dword ptr [edi+32]
	jns       short @7
	lea edx,dword ptr [edi+24]
	mov ecx,dword ptr [edx]
	inc dword ptr [edx]
	add al,48
	mov byte ptr [ecx],al
	jmp short @9
@7:
	lea edx,dword ptr [edi+24]
	push edx
	add al,48
	push eax
	call __fputc
	add esp,8
	jmp short @9
 ;	
 ;	        else
 ;	            putchar('a' + digit - 10);
 ;	
	?debug L 34
@6:
	inc dword ptr [edi+32]
	jns       short @10
	lea edx,dword ptr [edi+24]
	mov ecx,dword ptr [edx]
	inc dword ptr [edx]
	add al,97
	sub al,10
	mov byte ptr [ecx],al
	jmp short @11
@10:
	lea edx,dword ptr [edi+24]
	push edx
	add al,87
	push eax
	call __fputc
	add esp,8
@11:
@9:
@12:
	dec ebx
	test ebx,ebx
	jge       short @2
 ;	
 ;	    }
 ;	}
 ;	
	?debug L 36
?live1@96: ; 
@14:
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret 
	?debug L 0
_print_number	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	db	2
	db	0
	db	0
	db	0
	dw	60
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
	df	_print_number
	dw	0
	dw	4096
	dw	0
	dw	1
	dw	0
	dw	0
	dw	0
	db	13
	db	95
	db	112
	db	114
	db	105
	db	110
	db	116
	db	95
	db	110
	db	117
	db	109
	db	98
	db	101
	db	114
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
	dw	?patch4
	dw	529
	dw	?patch5
	dd	?live1@16-_print_number
	dd	?live1@96-?live1@16
	dw	23
?patch5	equ	1
?patch4	equ	14
	dw	16
	dw	2
	dw	116
	dw	0
	dw	20
	dw	3
	dw	0
	dw	0
	dw	0
	dw	?patch6
	dw	529
	dw	?patch7
	dd	?live1@32-_print_number
	dd	?live1@96-?live1@32
	dw	20
?patch7	equ	1
?patch6	equ	14
	dw	24
	dw	519
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch8
	df	@4
	dw	0
	dw	0
	dw	16
	dw	2
	dw	116
	dw	0
	dw	17
	dw	4
	dw	0
	dw	0
	dw	0
	dw	?patch9
	dw	529
	dw	?patch10
	dd	?live1@48-_print_number
	dd	?live1@96-?live1@48
	dw	17
?patch10	equ	1
?patch9	equ	14
?patch8	equ	@12-@4
	dw	2
	dw	6
?patch1	equ	@14-_print_number+5
?patch2	equ	0
?patch3	equ	@14-_print_number
	dw	2
	dw	6
	dw	8
	dw	531
	dw	7
	dw	65524
	dw	65535
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_print_ascii_entry	proc	near
?live1@128:
 ;	
 ;	void print_ascii_entry(char character, const ascii_property properties[], int num_ascii_properties) {
 ;	
	?debug L 38
	push ebp
	mov ebp,esp
	push ebx
	push esi
	push edi
	mov edi,offset __streams
 ;	
 ;	    int k;
 ;	
 ;	    print_number(character);
 ;	
	?debug L 41
?live1@144: ; EDI = &_streams
@15:
	movsx eax,byte ptr [ebp+8]
	push eax
	call _print_number
	pop ecx
 ;	
 ;	    putchar(' ');
 ;	
	?debug L 42
	inc dword ptr [edi+32]
	jns       short @16
	lea edx,dword ptr [edi+24]
	mov ecx,dword ptr [edx]
	inc dword ptr [edx]
	mov byte ptr [ecx],32
	jmp short @17
@16:
	lea eax,dword ptr [edi+24]
	push eax
	push 32
	call __fputc
	add esp,8
 ;	
 ;	
 ;	    if (isgraph(character))
 ;	
	?debug L 44
@17:
	movsx edx,byte ptr [ebp+8]
	push edx
	call _isgraph
	pop ecx
	test eax,eax
	je        short @18
 ;	
 ;	        putchar(character);
 ;	
	?debug L 45
	inc dword ptr [edi+32]
	jns       short @19
	lea ecx,dword ptr [edi+24]
	mov eax,dword ptr [ecx]
	inc dword ptr [ecx]
	mov dl,byte ptr [ebp+8]
	mov byte ptr [eax],dl
	jmp short @21
@19:
	lea ecx,dword ptr [edi+24]
	push ecx
	mov al,byte ptr [ebp+8]
	push eax
	call __fputc
	add esp,8
	jmp short @21
 ;	
 ;	    else
 ;	        putchar(' ');
 ;	
	?debug L 47
@18:
	inc dword ptr [edi+32]
	jns       short @22
	lea edx,dword ptr [edi+24]
	mov ecx,dword ptr [edx]
	inc dword ptr [edx]
	mov byte ptr [ecx],32
	jmp short @23
@22:
	lea eax,dword ptr [edi+24]
	push eax
	push 32
	call __fputc
	add esp,8
 ;	
 ;	    putchar(' ');
 ;	
	?debug L 48
@23:
@21:
	inc dword ptr [edi+32]
	jns       short @24
	lea edx,dword ptr [edi+24]
	mov ecx,dword ptr [edx]
	inc dword ptr [edx]
	mov byte ptr [ecx],32
	jmp short @25
@24:
	lea eax,dword ptr [edi+24]
	push eax
	push 32
	call __fputc
	add esp,8
 ;	
 ;	
 ;	    for (k = 0; k < num_ascii_properties; k++) {
 ;	
	?debug L 50
@25:
	xor ebx,ebx
	cmp ebx,dword ptr [ebp+16]
	jge       short @27
 ;	
 ;	        const ascii_property *property = &properties[k];
 ;	
	?debug L 51
?live1@256: ; EBX = k, EDI = &_streams
@26:
@28:
	mov esi,ebx
	shl esi,3
	add esi,dword ptr [ebp+12]
 ;	
 ;	
 ;	        if (property->matches(character))
 ;	
	?debug L 53
?live1@272: ; EBX = k, ESI = property, EDI = &_streams
	movsx eax,byte ptr [ebp+8]
	push eax
	call dword ptr [esi]
	pop ecx
	test eax,eax
	je        short @29
 ;	
 ;	            putchar(property->flag);
 ;	
	?debug L 54
	inc dword ptr [edi+32]
	jns       short @30
	lea edx,dword ptr [edi+24]
	mov ecx,dword ptr [edx]
	inc dword ptr [edx]
	mov al,byte ptr [esi+4]
	mov byte ptr [ecx],al
	jmp short @32
@30:
	lea edx,dword ptr [edi+24]
	push edx
	mov cl,byte ptr [esi+4]
	push ecx
	call __fputc
	add esp,8
	jmp short @32
 ;	
 ;	        else
 ;	            putchar(' ');
 ;	
	?debug L 56
?live1@304: ; EBX = k, EDI = &_streams
@29:
	inc dword ptr [edi+32]
	jns       short @33
	lea eax,dword ptr [edi+24]
	mov edx,dword ptr [eax]
	inc dword ptr [eax]
	mov byte ptr [edx],32
	jmp short @34
@33:
	lea ecx,dword ptr [edi+24]
	push ecx
	push 32
	call __fputc
	add esp,8
@34:
@32:
@35:
	inc ebx
	cmp ebx,dword ptr [ebp+16]
	jl        short @26
 ;	
 ;	    }
 ;	}
 ;	
	?debug L 58
?live1@320: ; 
@27:
@37:
	pop edi
	pop esi
	pop ebx
	pop ebp
	ret 
	?debug L 0
_print_ascii_entry	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	65
	dw	517
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch11
	dd	?patch12
	dd	?patch13
	df	_print_ascii_entry
	dw	0
	dw	4098
	dw	0
	dw	8
	dw	0
	dw	0
	dw	0
	db	18
	db	95
	db	112
	db	114
	db	105
	db	110
	db	116
	db	95
	db	97
	db	115
	db	99
	db	105
	db	105
	db	95
	db	101
	db	110
	db	116
	db	114
	db	121
	dw	18
	dw	512
	dw	8
	dw	0
	dw	16
	dw	0
	dw	9
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	12
	dw	0
	dw	4099
	dw	0
	dw	10
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	16
	dw	0
	dw	116
	dw	0
	dw	11
	dw	0
	dw	0
	dw	0
	dw	16
	dw	2
	dw	116
	dw	0
	dw	20
	dw	12
	dw	0
	dw	0
	dw	0
	dw	?patch14
	dw	529
	dw	?patch15
	dd	?live1@256-_print_ascii_entry
	dd	?live1@320-?live1@256
	dw	20
?patch15	equ	1
?patch14	equ	14
	dw	24
	dw	519
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch16
	df	@28
	dw	0
	dw	0
	dw	16
	dw	2
	dw	4107
	dw	0
	dw	23
	dw	13
	dw	0
	dw	0
	dw	0
	dw	?patch17
	dw	529
	dw	?patch18
	dd	?live1@272-_print_ascii_entry
	dd	?live1@304-?live1@272
	dw	23
?patch18	equ	1
?patch17	equ	14
?patch16	equ	@35-@28
	dw	2
	dw	6
?patch11	equ	@37-_print_ascii_entry+5
?patch12	equ	0
?patch13	equ	@37-_print_ascii_entry
	dw	2
	dw	6
	dw	8
	dw	531
	dw	7
	dw	65524
	dw	65535
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_main	proc	near
?live1@352:
 ;	
 ;	int main() {
 ;	
	?debug L 60
	push ebp
	mov ebp,esp
	push ebx
	push esi
	push edi
	mov edi,offset _COLUMNS
 ;	
 ;	    int i;
 ;	
 ;	    for (i = 0; i < 128; i++) {
 ;	
	?debug L 63
?live1@368: ; EDI = &_COLUMNS
@38:
	xor ebx,ebx
 ;	
 ;	        int x = i % COLUMNS;
 ;	
	?debug L 64
?live1@384: ; EBX = i, EDI = &_COLUMNS
@39:
@41:
	mov eax,ebx
	cdq
	idiv dword ptr [edi]
	mov ecx,edx
 ;	
 ;	        int y = i / COLUMNS;
 ;	
	?debug L 65
?live1@400: ; EBX = i, ECX = x, EDI = &_COLUMNS
	mov eax,ebx
	cdq
	idiv dword ptr [edi]
	mov esi,eax
 ;	
 ;	        int character = x * 128 / COLUMNS + y;
 ;	
	?debug L 66
?live1@416: ; EBX = i, ECX = x, ESI = y, EDI = &_COLUMNS
	mov eax,ecx
	shl eax,7
	cdq
	idiv dword ptr [edi]
	add eax,esi
 ;	
 ;	
 ;	        print_ascii_entry(character, s_ascii_properties, NUM_ASCII_PROPERTIES);
 ;	
	?debug L 68
?live1@432: ; EBX = i, EAX = character, EDI = &_COLUMNS
	push dword ptr [_NUM_ASCII_PROPERTIES]
	push offset _s_ascii_properties
	push eax
	call _print_ascii_entry
	add esp,12
 ;	
 ;	
 ;	        putchar(i % COLUMNS == COLUMNS - 1 ? '\n' : '\t');
 ;	
	?debug L 70
?live1@448: ; EBX = i, EDI = &_COLUMNS
	inc dword ptr [__streams+32]
	jns       short @42
	mov eax,ebx
	cdq
	idiv dword ptr [edi]
	mov ecx,dword ptr [edi]
	dec ecx
	cmp edx,ecx
	jne       short @44
	mov al,10
	jmp short @45
@44:
	mov al,9
@45:
	mov edx,offset __streams+24
	mov ecx,dword ptr [edx]
	inc dword ptr [edx]
	mov byte ptr [ecx],al
	jmp short @43
@42:
	push offset __streams+24
	mov eax,ebx
	cdq
	idiv dword ptr [edi]
	mov ecx,dword ptr [edi]
	dec ecx
	cmp edx,ecx
	jne       short @46
	mov al,10
	jmp short @47
@46:
	mov al,9
@47:
	push eax
	call __fputc
	add esp,8
@43:
@48:
	inc ebx
	cmp ebx,128
	jl        short @39
 ;	
 ;	    }
 ;	
 ;	    return 0;
 ;	
	?debug L 73
?live1@464: ; 
	xor eax,eax
 ;	
 ;	}
 ;	
	?debug L 74
@51:
@50:
	pop edi
	pop esi
	pop ebx
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
	dd	?patch19
	dd	?patch20
	dd	?patch21
	df	_main
	dw	0
	dw	4108
	dw	0
	dw	14
	dw	0
	dw	0
	dw	0
	db	5
	db	95
	db	109
	db	97
	db	105
	db	110
	dw	16
	dw	2
	dw	116
	dw	0
	dw	20
	dw	15
	dw	0
	dw	0
	dw	0
	dw	?patch22
	dw	529
	dw	?patch23
	dd	?live1@384-_main
	dd	?live1@464-?live1@384
	dw	20
?patch23	equ	1
?patch22	equ	14
	dw	24
	dw	519
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch24
	df	@41
	dw	0
	dw	0
	dw	16
	dw	2
	dw	116
	dw	0
	dw	17
	dw	16
	dw	0
	dw	0
	dw	0
	dw	?patch25
	dw	529
	dw	?patch26
	dd	?live1@432-_main
	dd	?live1@448-?live1@432
	dw	17
?patch26	equ	1
?patch25	equ	14
	dw	16
	dw	2
	dw	116
	dw	0
	dw	23
	dw	17
	dw	0
	dw	0
	dw	0
	dw	?patch27
	dw	529
	dw	?patch28
	dd	?live1@416-_main
	dd	?live1@432-?live1@416
	dw	23
?patch28	equ	1
?patch27	equ	14
	dw	16
	dw	2
	dw	116
	dw	0
	dw	18
	dw	18
	dw	0
	dw	0
	dw	0
	dw	?patch29
	dw	529
	dw	?patch30
	dd	?live1@400-_main
	dd	?live1@432-?live1@400
	dw	18
?patch30	equ	1
?patch29	equ	14
?patch24	equ	@48-@41
	dw	2
	dw	6
?patch19	equ	@51-_main+5
?patch20	equ	0
?patch21	equ	@51-_main
	dw	2
	dw	6
	dw	8
	dw	531
	dw	7
	dw	65524
	dw	65535
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_TEXT	ends
 extrn __streams:byte
	public	_NUM_ASCII_PROPERTIES
	public	_s_ascii_properties
 extrn _isgraph:near
 extrn _isprint:near
 extrn _iscntrl:near
 extrn _isspace:near
 extrn _ispunct:near
 extrn _isalnum:near
 extrn _isalpha:near
 extrn _isdigit:near
 extrn _isupper:near
 extrn _islower:near
	public	_COLUMNS
	public	_print_number
 extrn __fputc:near
	public	_print_ascii_entry
	public	_main
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	22
	dw	514
	df	_NUM_ASCII_PROPERTIES
	dw	0
	dw	4113
	dw	0
	dw	29
	dw	0
	dw	0
	dw	0
	dw	22
	dw	514
	df	_s_ascii_properties
	dw	0
	dw	4114
	dw	0
	dw	30
	dw	0
	dw	0
	dw	0
	dw	22
	dw	514
	df	_COLUMNS
	dw	0
	dw	116
	dw	0
	dw	31
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	117
	dw	0
	dw	0
	dw	32
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	116
	dw	0
	dw	0
	dw	33
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	33
	dw	0
	dw	0
	dw	34
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	33
	dw	0
	dw	0
	dw	35
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	33
	dw	0
	dw	0
	dw	36
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	18
	dw	0
	dw	0
	dw	37
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4111
	dw	0
	dw	0
	dw	38
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4101
	dw	0
	dw	0
	dw	39
	dw	0
	dw	0
	dw	0
	dw	?patch31
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
?patch31	equ	16
$$BSYMS	ends
$$BTYPES	segment byte public use32 'DEBTYP'
	db 2,0,0,0,14,0,8,0,3,0,0,0,0,0,1,0
	db 1,16,0,0,8,0,1,2,1,0,116,0,0,0,14,0
	db 8,0,3,0,0,0,0,0,3,0,10,16,0,0,8,0
	db 2,0,10,4,4,16,0,0,8,0,1,0,1,0,5,16
	db 0,0,28,0,5,0,2,0,9,16,0,0,0,0,0,0
	db 0,0,0,0,0,0,0,0,0,0,5,0,0,0,8,0
	db 8,0,2,0,10,0,7,16,0,0,14,0,8,0,116,0
	db 0,0,0,0,1,0,8,16,0,0,8,0,1,2,1,0
	db 116,0,0,0,40,0,4,2,6,4,6,16,0,0,0,0
	db 6,0,0,0,0,0,0,0,0,0,242,241,6,4,16,0
	db 0,0,0,0,7,0,0,0,0,0,0,0,4,0,16,0
	db 1,2,3,0,16,0,0,0,3,16,0,0,116,0,0,0
	db 8,0,2,0,10,0,4,16,0,0,14,0,8,0,116,0
	db 0,0,0,0,0,0,13,16,0,0,4,0,1,2,0,0
	db 18,0,3,0,15,16,0,0,17,0,0,0,0,0,0,0
	db 0,0,0,0,28,0,5,0,9,0,16,16,0,0,0,0
	db 0,0,0,0,0,0,0,0,0,0,0,0,19,0,0,0
	db 24,0,180,0,4,2,6,4,32,4,0,0,0,0,20,0
	db 0,0,0,0,0,0,0,0,242,241,6,4,32,4,0,0
	db 0,0,21,0,0,0,0,0,0,0,4,0,242,241,6,4
	db 116,0,0,0,0,0,22,0,0,0,0,0,0,0,8,0
	db 242,241,6,4,116,0,0,0,0,0,23,0,0,0,0,0
	db 0,0,12,0,242,241,6,4,33,0,0,0,0,0,24,0
	db 0,0,0,0,0,0,16,0,242,241,6,4,33,0,0,0
	db 0,0,25,0,0,0,0,0,0,0,18,0,242,241,6,4
	db 33,0,0,0,0,0,26,0,0,0,0,0,0,0,20,0
	db 242,241,6,4,16,0,0,0,0,0,27,0,0,0,0,0
	db 0,0,22,0,242,241,6,4,32,0,0,0,0,0,28,0
	db 0,0,0,0,0,0,23,0,8,0,1,0,1,0,116,0
	db 0,0,8,0,1,0,1,0,19,16,0,0,18,0,3,0
	db 5,16,0,0,17,0,0,0,0,0,0,0,80,0,10,0
	db 14,0,8,0,116,0,0,0,0,0,1,0,21,16,0,0
	db 8,0,1,2,1,0,116,0,0,0,14,0,8,0,116,0
	db 0,0,0,0,1,0,23,16,0,0,8,0,1,2,1,0
	db 116,0,0,0,14,0,8,0,116,0,0,0,0,0,1,0
	db 25,16,0,0,8,0,1,2,1,0,116,0,0,0,14,0
	db 8,0,116,0,0,0,0,0,1,0,27,16,0,0,8,0
	db 1,2,1,0,116,0,0,0,14,0,8,0,116,0,0,0
	db 0,0,1,0,29,16,0,0,8,0,1,2,1,0,116,0
	db 0,0,14,0,8,0,116,0,0,0,0,0,1,0,31,16
	db 0,0,8,0,1,2,1,0,116,0,0,0,14,0,8,0
	db 116,0,0,0,0,0,1,0,33,16,0,0,8,0,1,2
	db 1,0,116,0,0,0,14,0,8,0,116,0,0,0,0,0
	db 1,0,35,16,0,0,8,0,1,2,1,0,116,0,0,0
	db 14,0,8,0,116,0,0,0,0,0,1,0,37,16,0,0
	db 8,0,1,2,1,0,116,0,0,0,14,0,8,0,116,0
	db 0,0,0,0,1,0,39,16,0,0,8,0,1,2,1,0
	db 116,0,0,0,14,0,8,0,116,0,0,0,0,0,2,0
	db 42,16,0,0,8,0,2,0,10,0,15,16,0,0,12,0
	db 1,2,2,0,16,0,0,0,41,16,0,0
$$BTYPES	ends
$$BNAMES	segment byte public use32 'DEBNAM'
	db	12,'print_number'
	db	3,'num'
	db	1,'n'
	db	5,'digit'
	db	14,'ascii_property'
	db	7,'matches'
	db	4,'flag'
	db	17,'print_ascii_entry'
	db	9,'character'
	db	10,'properties'
	db	20,'num_ascii_properties'
	db	1,'k'
	db	8,'property'
	db	4,'main'
	db	1,'i'
	db	9,'character'
	db	1,'y'
	db	1,'x'
	db	4,'FILE'
	db	4,'curp'
	db	6,'buffer'
	db	5,'level'
	db	5,'bsize'
	db	6,'istemp'
	db	5,'flags'
	db	4,'hold'
	db	2,'fd'
	db	5,'token'
	db	20,'NUM_ASCII_PROPERTIES'
	db	18,'s_ascii_properties'
	db	7,'COLUMNS'
	db	6,'size_t'
	db	9,'ptrdiff_t'
	db	7,'wchar_t'
	db	6,'wint_t'
	db	8,'wctype_t'
	db	6,'fpos_t'
	db	4,'FILE'
	db	14,'ascii_property'
$$BNAMES	ends
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_nfile.h" 11329 12288
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\stdio.h" 11329 12288
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\mbctype.h" 11329 12288
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_null.h" 11329 12288
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_defs.h" 11329 12288
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_stddef.h" 11329 12288
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\ctype.h" 11329 12288
	?debug	D ".\ascii-table.c" 22789 31770
	end
