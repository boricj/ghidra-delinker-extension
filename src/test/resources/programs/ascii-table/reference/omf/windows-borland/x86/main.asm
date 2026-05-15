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
_NUM_ASCII_PROPERTIES	label	dword
	dd	10
	align	4
_s_ascii_properties	label	byte
	dd	_openbsd_isgraph
	db	103
	db	3	dup(?)
	dd	_openbsd_isprint
	db	112
	db	3	dup(?)
	dd	_openbsd_iscntrl
	db	99
	db	3	dup(?)
	dd	_openbsd_isspace
	db	115
	db	3	dup(?)
	dd	_openbsd_ispunct
	db	33
	db	3	dup(?)
	dd	_openbsd_isalnum
	db	65
	db	3	dup(?)
	dd	_openbsd_isalpha
	db	97
	db	3	dup(?)
	dd	_openbsd_isdigit
	db	100
	db	3	dup(?)
	dd	_openbsd_isupper
	db	85
	db	3	dup(?)
	dd	_openbsd_islower
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
	?debug L 26
	push ebp
	mov ebp,esp
	add esp,-8
 ;	
 ;	    int n;
 ;	
 ;	    for (n = 3; n >= 0; n--) {
 ;	
	?debug L 29
@1:
	mov dword ptr [ebp-4],3
 ;	
 ;	        int digit = (num >> (4 * n)) % 16;
 ;	
	?debug L 30
@2:
@4:
	mov ecx,dword ptr [ebp-4]
	shl ecx,2
	mov eax,dword ptr [ebp+8]
	sar eax,cl
	and eax,-2147483633
	jns       short @5
	dec eax
	or eax,-16
	inc eax
@5:
	mov dword ptr [ebp-8],eax
 ;	
 ;	
 ;	        if (digit < 10)
 ;	
	?debug L 32
	cmp dword ptr [ebp-8],10
	jge       short @6
 ;	
 ;	            putchar('0' + digit);
 ;	
	?debug L 33
	inc dword ptr [__streams+32]
	jns       short @7
	mov edx,offset __streams+24
	mov eax,dword ptr [edx]
	inc dword ptr [edx]
	mov dl,byte ptr [ebp-8]
	add dl,48
	mov byte ptr [eax],dl
	jmp short @9
@7:
	push offset __streams+24
	mov cl,byte ptr [ebp-8]
	add cl,48
	push ecx
	call __fputc
	add esp,8
	jmp short @9
 ;	
 ;	        else
 ;	            putchar('a' + digit - 10);
 ;	
	?debug L 35
@6:
	inc dword ptr [__streams+32]
	jns       short @10
	mov eax,offset __streams+24
	mov edx,dword ptr [eax]
	inc dword ptr [eax]
	mov cl,byte ptr [ebp-8]
	add cl,97
	sub cl,10
	mov byte ptr [edx],cl
	jmp short @11
@10:
	push offset __streams+24
	mov al,byte ptr [ebp-8]
	add al,87
	push eax
	call __fputc
	add esp,8
@11:
@9:
@12:
	dec dword ptr [ebp-4]
	cmp dword ptr [ebp-4],0
	jge       @2
 ;	
 ;	    }
 ;	}
 ;	
	?debug L 37
@14:
	pop ecx
	pop ecx
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
	dw	18
	dw	512
	dw	65532
	dw	65535
	dw	116
	dw	0
	dw	3
	dw	0
	dw	0
	dw	0
	dw	24
	dw	519
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch4
	df	@4
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65528
	dw	65535
	dw	116
	dw	0
	dw	4
	dw	0
	dw	0
	dw	0
?patch4	equ	@12-@4
	dw	2
	dw	6
?patch1	equ	@14-_print_number+4
?patch2	equ	0
?patch3	equ	@14-_print_number
	dw	2
	dw	6
	dw	4
	dw	531
	dw	0
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_print_ascii_entry	proc	near
?live1@128:
 ;	
 ;	void print_ascii_entry(char character, const ascii_property properties[], int num_ascii_properties) {
 ;	
	?debug L 39
	push ebp
	mov ebp,esp
	add esp,-8
 ;	
 ;	    int k;
 ;	
 ;	    print_number(character);
 ;	
	?debug L 42
@15:
	movsx eax,byte ptr [ebp+8]
	push eax
	call _print_number
	pop ecx
 ;	
 ;	    putchar(' ');
 ;	
	?debug L 43
	inc dword ptr [__streams+32]
	jns       short @16
	mov edx,offset __streams+24
	mov ecx,dword ptr [edx]
	inc dword ptr [edx]
	mov byte ptr [ecx],32
	jmp short @17
@16:
	push offset __streams+24
	push 32
	call __fputc
	add esp,8
 ;	
 ;	
 ;	    if (openbsd_isgraph(character))
 ;	
	?debug L 45
@17:
	movsx eax,byte ptr [ebp+8]
	push eax
	call _openbsd_isgraph
	pop ecx
	test eax,eax
	je        short @18
 ;	
 ;	        putchar(character);
 ;	
	?debug L 46
	inc dword ptr [__streams+32]
	jns       short @19
	mov edx,offset __streams+24
	mov ecx,dword ptr [edx]
	inc dword ptr [edx]
	mov al,byte ptr [ebp+8]
	mov byte ptr [ecx],al
	jmp short @21
@19:
	push offset __streams+24
	mov dl,byte ptr [ebp+8]
	push edx
	call __fputc
	add esp,8
	jmp short @21
 ;	
 ;	    else
 ;	        putchar(' ');
 ;	
	?debug L 48
@18:
	inc dword ptr [__streams+32]
	jns       short @22
	mov ecx,offset __streams+24
	mov eax,dword ptr [ecx]
	inc dword ptr [ecx]
	mov byte ptr [eax],32
	jmp short @23
@22:
	push offset __streams+24
	push 32
	call __fputc
	add esp,8
 ;	
 ;	    putchar(' ');
 ;	
	?debug L 49
@23:
@21:
	inc dword ptr [__streams+32]
	jns       short @24
	mov edx,offset __streams+24
	mov ecx,dword ptr [edx]
	inc dword ptr [edx]
	mov byte ptr [ecx],32
	jmp short @25
@24:
	push offset __streams+24
	push 32
	call __fputc
	add esp,8
 ;	
 ;	
 ;	    for (k = 0; k < num_ascii_properties; k++) {
 ;	
	?debug L 51
@25:
	xor eax,eax
	mov dword ptr [ebp-4],eax
	mov edx,dword ptr [ebp-4]
	cmp edx,dword ptr [ebp+16]
	jge       short @27
 ;	
 ;	        const ascii_property *property = &properties[k];
 ;	
	?debug L 52
@26:
@28:
	mov ecx,dword ptr [ebp-4]
	shl ecx,3
	add ecx,dword ptr [ebp+12]
	mov dword ptr [ebp-8],ecx
 ;	
 ;	
 ;	        if (property->matches(character))
 ;	
	?debug L 54
	movsx eax,byte ptr [ebp+8]
	push eax
	mov edx,dword ptr [ebp-8]
	call dword ptr [edx]
	pop ecx
	test eax,eax
	je        short @29
 ;	
 ;	            putchar(property->flag);
 ;	
	?debug L 55
	inc dword ptr [__streams+32]
	jns       short @30
	mov ecx,offset __streams+24
	mov eax,dword ptr [ecx]
	inc dword ptr [ecx]
	mov edx,dword ptr [ebp-8]
	mov cl,byte ptr [edx+4]
	mov byte ptr [eax],cl
	jmp short @32
@30:
	push offset __streams+24
	mov eax,dword ptr [ebp-8]
	mov dl,byte ptr [eax+4]
	push edx
	call __fputc
	add esp,8
	jmp short @32
 ;	
 ;	        else
 ;	            putchar(' ');
 ;	
	?debug L 57
@29:
	inc dword ptr [__streams+32]
	jns       short @33
	mov ecx,offset __streams+24
	mov eax,dword ptr [ecx]
	inc dword ptr [ecx]
	mov byte ptr [eax],32
	jmp short @34
@33:
	push offset __streams+24
	push 32
	call __fputc
	add esp,8
@34:
@32:
@35:
	inc dword ptr [ebp-4]
	mov edx,dword ptr [ebp-4]
	cmp edx,dword ptr [ebp+16]
	jl        short @26
 ;	
 ;	    }
 ;	}
 ;	
	?debug L 59
@27:
@37:
	pop ecx
	pop ecx
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
	dd	?patch5
	dd	?patch6
	dd	?patch7
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
	dw	18
	dw	512
	dw	65532
	dw	65535
	dw	116
	dw	0
	dw	12
	dw	0
	dw	0
	dw	0
	dw	24
	dw	519
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch8
	df	@28
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65528
	dw	65535
	dw	4107
	dw	0
	dw	13
	dw	0
	dw	0
	dw	0
?patch8	equ	@35-@28
	dw	2
	dw	6
?patch5	equ	@37-_print_ascii_entry+4
?patch6	equ	0
?patch7	equ	@37-_print_ascii_entry
	dw	2
	dw	6
	dw	4
	dw	531
	dw	0
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_main	proc	near
?live1@352:
 ;	
 ;	int main() {
 ;	
	?debug L 61
	push ebp
	mov ebp,esp
	add esp,-16
 ;	
 ;	    int i;
 ;	
 ;	    for (i = 0; i < 128; i++) {
 ;	
	?debug L 64
@38:
	xor eax,eax
	mov dword ptr [ebp-4],eax
 ;	
 ;	        int x = i % COLUMNS;
 ;	
	?debug L 65
@39:
@41:
	mov eax,dword ptr [ebp-4]
	cdq
	idiv dword ptr [_COLUMNS]
	mov dword ptr [ebp-8],edx
 ;	
 ;	        int y = i / COLUMNS;
 ;	
	?debug L 66
	mov eax,dword ptr [ebp-4]
	cdq
	idiv dword ptr [_COLUMNS]
	mov dword ptr [ebp-12],eax
 ;	
 ;	        int character = x * 128 / COLUMNS + y;
 ;	
	?debug L 67
	mov eax,dword ptr [ebp-8]
	shl eax,7
	cdq
	idiv dword ptr [_COLUMNS]
	add eax,dword ptr [ebp-12]
	mov dword ptr [ebp-16],eax
 ;	
 ;	
 ;	        print_ascii_entry(character, s_ascii_properties, NUM_ASCII_PROPERTIES);
 ;	
	?debug L 69
	push dword ptr [_NUM_ASCII_PROPERTIES]
	push offset _s_ascii_properties
	mov cl,byte ptr [ebp-16]
	push ecx
	call _print_ascii_entry
	add esp,12
 ;	
 ;	
 ;	        putchar(i % COLUMNS == COLUMNS - 1 ? '\n' : '\t');
 ;	
	?debug L 71
	inc dword ptr [__streams+32]
	jns       short @42
	mov eax,dword ptr [ebp-4]
	cdq
	idiv dword ptr [_COLUMNS]
	mov ecx,dword ptr [_COLUMNS]
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
	mov eax,dword ptr [ebp-4]
	cdq
	idiv dword ptr [_COLUMNS]
	mov ecx,dword ptr [_COLUMNS]
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
	inc dword ptr [ebp-4]
	cmp dword ptr [ebp-4],128
	jl        @39
 ;	
 ;	    }
 ;	
 ;	    return 0;
 ;	
	?debug L 74
	xor eax,eax
 ;	
 ;	}
 ;	
	?debug L 75
@51:
@50:
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
	dd	?patch9
	dd	?patch10
	dd	?patch11
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
	dw	18
	dw	512
	dw	65532
	dw	65535
	dw	116
	dw	0
	dw	15
	dw	0
	dw	0
	dw	0
	dw	24
	dw	519
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch12
	df	@41
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65520
	dw	65535
	dw	116
	dw	0
	dw	16
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65524
	dw	65535
	dw	116
	dw	0
	dw	17
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65528
	dw	65535
	dw	116
	dw	0
	dw	18
	dw	0
	dw	0
	dw	0
?patch12	equ	@48-@41
	dw	2
	dw	6
?patch9	equ	@51-_main+4
?patch10	equ	0
?patch11	equ	@51-_main
	dw	2
	dw	6
	dw	4
	dw	531
	dw	0
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_TEXT	ends
 extrn __streams:byte
	public	_NUM_ASCII_PROPERTIES
	public	_s_ascii_properties
 extrn _openbsd_isgraph:near
 extrn _openbsd_isprint:near
 extrn _openbsd_iscntrl:near
 extrn _openbsd_isspace:near
 extrn _openbsd_ispunct:near
 extrn _openbsd_isalnum:near
 extrn _openbsd_isalpha:near
 extrn _openbsd_isdigit:near
 extrn _openbsd_isupper:near
 extrn _openbsd_islower:near
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
	dw	?patch13
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
?patch13	equ	16
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
	?debug	D "C:/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/ascii-table/include\openbsd_ctype.h" 23691 36627
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_nfile.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_null.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_defs.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_stddef.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\stdio.h" 11329 14336
	?debug	D "src/main.c" 23691 36900
	end
