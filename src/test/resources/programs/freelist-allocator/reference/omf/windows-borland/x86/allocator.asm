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
	?debug	S "src/allocator.c"
	?debug	T "src/allocator.c"
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
_TEXT	segment dword public use32 'CODE'
_align_up	proc	near
?live1@0:
 ;	
 ;	static size_t align_up(size_t value) {
 ;	
	?debug L 5
	push ebp
	mov ebp,esp
	push ecx
 ;	
 ;	    size_t m = ALIGNMENT - 1u;
 ;	
	?debug L 6
@1:
	mov dword ptr [ebp-4],3
 ;	
 ;	    return (value + m) & ~m;
 ;	
	?debug L 7
	mov eax,dword ptr [ebp+8]
	add eax,dword ptr [ebp-4]
	mov edx,dword ptr [ebp-4]
	not edx
	and eax,edx
 ;	
 ;	}
 ;	
	?debug L 8
@3:
@2:
	pop ecx
	pop ebp
	ret 
	?debug L 0
_align_up	endp
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
	df	_align_up
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
	dw	117
	dw	0
	dw	2
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65532
	dw	65535
	dw	117
	dw	0
	dw	3
	dw	0
	dw	0
	dw	0
?patch1	equ	@3-_align_up+3
?patch2	equ	0
?patch3	equ	@3-_align_up
	dw	2
	dw	6
	dw	4
	dw	531
	dw	0
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_chunk_length	proc	near
?live1@80:
 ;	
 ;	static size_t chunk_length(const chunk_header *chunk) {
 ;	
	?debug L 10
	push ebp
	mov ebp,esp
 ;	
 ;	    return (size_t) (chunk->length > 0 ? chunk->length : -chunk->length);
 ;	
	?debug L 11
@4:
	mov eax,dword ptr [ebp+8]
	cmp dword ptr [eax+4],0
	jle       short @5
	mov edx,dword ptr [ebp+8]
	mov eax,dword ptr [edx+4]
	jmp short @7
@5:
	mov edx,dword ptr [ebp+8]
	mov eax,dword ptr [edx+4]
	neg eax
 ;	
 ;	}
 ;	
	?debug L 12
@8:
@7:
	pop ebp
	ret 
	?debug L 0
_chunk_length	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	46
	dw	516
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch4
	dd	?patch5
	dd	?patch6
	df	_chunk_length
	dw	0
	dw	4098
	dw	0
	dw	7
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	8
	dw	0
	dw	4099
	dw	0
	dw	8
	dw	0
	dw	0
	dw	0
?patch4	equ	@8-_chunk_length+2
?patch5	equ	0
?patch6	equ	@8-_chunk_length
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_chunk_is_used	proc	near
?live1@144:
 ;	
 ;	static int chunk_is_used(const chunk_header *chunk) {
 ;	
	?debug L 14
	push ebp
	mov ebp,esp
 ;	
 ;	    return chunk->length < 0;
 ;	
	?debug L 15
@9:
	mov eax,dword ptr [ebp+8]
	cmp dword ptr [eax+4],0
	setl al
	and eax,1
 ;	
 ;	}
 ;	
	?debug L 16
@11:
@10:
	pop ebp
	ret 
	?debug L 0
_chunk_is_used	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	46
	dw	516
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch7
	dd	?patch8
	dd	?patch9
	df	_chunk_is_used
	dw	0
	dw	4105
	dw	0
	dw	9
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	8
	dw	0
	dw	4099
	dw	0
	dw	10
	dw	0
	dw	0
	dw	0
?patch7	equ	@11-_chunk_is_used+2
?patch8	equ	0
?patch9	equ	@11-_chunk_is_used
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_chunk_set_used	proc	near
?live1@208:
 ;	
 ;	static void chunk_set_used(chunk_header *chunk, int used) {
 ;	
	?debug L 18
	push ebp
	mov ebp,esp
 ;	
 ;	    if (chunk_is_used(chunk) == used) {
 ;	
	?debug L 19
@12:
	push dword ptr [ebp+8]
	call _chunk_is_used
	pop ecx
	cmp eax,dword ptr [ebp+12]
	je        short @14
 ;	
 ;	        return;
 ;	
 ;	
 ;	    }
 ;	
 ;	    chunk->length = -chunk->length;
 ;	
	?debug L 23
	mov eax,dword ptr [ebp+8]
	neg dword ptr [eax+4]
 ;	
 ;	}
 ;	
	?debug L 24
@15:
@14:
	pop ebp
	ret 
	?debug L 0
_chunk_set_used	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	46
	dw	516
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch10
	dd	?patch11
	dd	?patch12
	df	_chunk_set_used
	dw	0
	dw	4107
	dw	0
	dw	11
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	8
	dw	0
	dw	4102
	dw	0
	dw	12
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	12
	dw	0
	dw	116
	dw	0
	dw	13
	dw	0
	dw	0
	dw	0
?patch10	equ	@15-_chunk_set_used+2
?patch11	equ	0
?patch12	equ	@15-_chunk_set_used
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_chunk_write	proc	near
?live1@304:
 ;	
 ;	static void chunk_write(chunk_header *chunk, chunk_header *next, size_t length, int used) {
 ;	
	?debug L 26
	push ebp
	mov ebp,esp
 ;	
 ;	    chunk->next = next;
 ;	
	?debug L 27
@16:
	mov eax,dword ptr [ebp+12]
	mov edx,dword ptr [ebp+8]
	mov dword ptr [edx],eax
 ;	
 ;	    chunk->length = used ? -((ptrdiff_t) length) : (ptrdiff_t) length;
 ;	
	?debug L 28
	cmp dword ptr [ebp+20],0
	je        short @17
	mov ecx,dword ptr [ebp+16]
	neg ecx
	jmp short @18
@17:
	mov ecx,dword ptr [ebp+16]
@18:
	mov eax,dword ptr [ebp+8]
	mov dword ptr [eax+4],ecx
 ;	
 ;	}
 ;	
	?debug L 29
@19:
	pop ebp
	ret 
	?debug L 0
_chunk_write	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	46
	dw	516
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch13
	dd	?patch14
	dd	?patch15
	df	_chunk_write
	dw	0
	dw	4109
	dw	0
	dw	14
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	8
	dw	0
	dw	4102
	dw	0
	dw	15
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	12
	dw	0
	dw	4102
	dw	0
	dw	16
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	16
	dw	0
	dw	117
	dw	0
	dw	17
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	20
	dw	0
	dw	116
	dw	0
	dw	18
	dw	0
	dw	0
	dw	0
?patch13	equ	@19-_chunk_write+2
?patch14	equ	0
?patch15	equ	@19-_chunk_write
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_chunk_to_data	proc	near
?live1@384:
 ;	
 ;	static unsigned char *chunk_to_data(chunk_header *chunk) {
 ;	
	?debug L 31
	push ebp
	mov ebp,esp
 ;	
 ;	    return ((unsigned char *) chunk) + sizeof(chunk_header);
 ;	
	?debug L 32
@20:
	mov eax,dword ptr [ebp+8]
	add eax,8
 ;	
 ;	}
 ;	
	?debug L 33
@22:
@21:
	pop ebp
	ret 
	?debug L 0
_chunk_to_data	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	46
	dw	516
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch16
	dd	?patch17
	dd	?patch18
	df	_chunk_to_data
	dw	0
	dw	4111
	dw	0
	dw	19
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	8
	dw	0
	dw	4102
	dw	0
	dw	20
	dw	0
	dw	0
	dw	0
?patch16	equ	@22-_chunk_to_data+2
?patch17	equ	0
?patch18	equ	@22-_chunk_to_data
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_chunk_from_data	proc	near
?live1@448:
 ;	
 ;	static chunk_header *chunk_from_data(void *ptr) {
 ;	
	?debug L 35
	push ebp
	mov ebp,esp
 ;	
 ;	    return (chunk_header *) (((unsigned char *) ptr) - sizeof(chunk_header));
 ;	
	?debug L 36
@23:
	mov eax,dword ptr [ebp+8]
	add eax,-8
 ;	
 ;	}
 ;	
	?debug L 37
@25:
@24:
	pop ebp
	ret 
	?debug L 0
_chunk_from_data	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	46
	dw	516
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch19
	dd	?patch20
	dd	?patch21
	df	_chunk_from_data
	dw	0
	dw	4113
	dw	0
	dw	21
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	8
	dw	0
	dw	1027
	dw	0
	dw	22
	dw	0
	dw	0
	dw	0
?patch19	equ	@25-_chunk_from_data+2
?patch20	equ	0
?patch21	equ	@25-_chunk_from_data
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_chunk_split	proc	near
?live1@512:
 ;	
 ;	static void chunk_split(chunk_header *chunk, size_t requested) {
 ;	
	?debug L 39
	push ebp
	mov ebp,esp
	add esp,-8
 ;	
 ;	    chunk_header *new_chunk = (chunk_header *) (((unsigned char *) chunk) + requested);
 ;	
	?debug L 40
@26:
	mov eax,dword ptr [ebp+8]
	add eax,dword ptr [ebp+12]
	mov dword ptr [ebp-4],eax
 ;	
 ;		size_t new_len = chunk_length(chunk) - requested;
 ;	
	?debug L 41
	push dword ptr [ebp+8]
	call _chunk_length
	pop ecx
	sub eax,dword ptr [ebp+12]
	mov dword ptr [ebp-8],eax
 ;	
 ;	
 ;	    /* Next chunk can't be smaller than the minimum chunk size. */
 ;		if (new_len < MIN_CHUNK_SIZE) {
 ;	
	?debug L 44
	cmp dword ptr [ebp-8],16
	jb        short @28
 ;	
 ;			return;
 ;	
 ;	
 ;		}
 ;	
 ;	    chunk_write(new_chunk, chunk->next, new_len, 0);
 ;	
	?debug L 48
	push 0
	push dword ptr [ebp-8]
	mov edx,dword ptr [ebp+8]
	push dword ptr [edx]
	push dword ptr [ebp-4]
	call _chunk_write
	add esp,16
 ;	
 ;	    chunk_write(chunk, new_chunk, requested, chunk_is_used(chunk));
 ;	
	?debug L 49
	push dword ptr [ebp+8]
	call _chunk_is_used
	pop ecx
	push eax
	push dword ptr [ebp+12]
	push dword ptr [ebp-4]
	push dword ptr [ebp+8]
	call _chunk_write
	add esp,16
 ;	
 ;	}
 ;	
	?debug L 50
@29:
@28:
	pop ecx
	pop ecx
	pop ebp
	ret 
	?debug L 0
_chunk_split	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	46
	dw	516
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch22
	dd	?patch23
	dd	?patch24
	df	_chunk_split
	dw	0
	dw	4115
	dw	0
	dw	23
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	8
	dw	0
	dw	4102
	dw	0
	dw	24
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	12
	dw	0
	dw	117
	dw	0
	dw	25
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65528
	dw	65535
	dw	117
	dw	0
	dw	26
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65532
	dw	65535
	dw	4102
	dw	0
	dw	27
	dw	0
	dw	0
	dw	0
?patch22	equ	@29-_chunk_split+4
?patch23	equ	0
?patch24	equ	@29-_chunk_split
	dw	2
	dw	6
	dw	4
	dw	531
	dw	0
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_freelist_init	proc	near
?live1@656:
 ;	
 ;	void freelist_init(void *heap, size_t heap_size) {
 ;	
	?debug L 52
	push ebp
	mov ebp,esp
 ;	
 ;	    chunk_write((chunk_header *) heap, NULL, heap_size, 0);
 ;	
	?debug L 53
@30:
	push 0
	push dword ptr [ebp+12]
	push 0
	push dword ptr [ebp+8]
	call _chunk_write
	add esp,16
 ;	
 ;	}
 ;	
	?debug L 54
@31:
	pop ebp
	ret 
	?debug L 0
_freelist_init	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	61
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
	df	_freelist_init
	dw	0
	dw	4117
	dw	0
	dw	28
	dw	0
	dw	0
	dw	0
	db	14
	db	95
	db	102
	db	114
	db	101
	db	101
	db	108
	db	105
	db	115
	db	116
	db	95
	db	105
	db	110
	db	105
	db	116
	dw	18
	dw	512
	dw	8
	dw	0
	dw	1027
	dw	0
	dw	29
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	12
	dw	0
	dw	117
	dw	0
	dw	30
	dw	0
	dw	0
	dw	0
?patch25	equ	@31-_freelist_init+2
?patch26	equ	0
?patch27	equ	@31-_freelist_init
	dw	2
	dw	6
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_freelist_alloc	proc	near
?live1@720:
 ;	
 ;	void *freelist_alloc(void *heap, size_t size) {
 ;	
	?debug L 56
	push ebp
	mov ebp,esp
	add esp,-8
 ;	
 ;	    size_t requested = sizeof(chunk_header) + align_up(size);
 ;	
	?debug L 57
@32:
	push dword ptr [ebp+12]
	call _align_up
	pop ecx
	add eax,8
	mov dword ptr [ebp-4],eax
 ;	
 ;	    chunk_header *cur;
 ;	
 ;	    if (size == 0u) {
 ;	
	?debug L 60
	cmp dword ptr [ebp+12],0
	jne       short @33
 ;	
 ;	        return NULL;
 ;	
	?debug L 61
	xor eax,eax
	jmp short @34
 ;	
 ;	    }
 ;	
 ;	    /* Allocated chunk can't be smaller than the minimum chunk size. */
 ;		if (requested < MIN_CHUNK_SIZE) {
 ;	
	?debug L 65
@33:
	cmp dword ptr [ebp-4],16
	jae       short @35
 ;	
 ;			requested = MIN_CHUNK_SIZE;
 ;	
	?debug L 66
	mov dword ptr [ebp-4],16
 ;	
 ;		}
 ;	
 ;	    /* First-fit search for a free chunk of sufficient size. */
 ;	    for (cur = (chunk_header *) heap; cur != NULL; cur = cur->next) {
 ;	
	?debug L 70
@35:
	mov edx,dword ptr [ebp+8]
	mov dword ptr [ebp-8],edx
	cmp dword ptr [ebp-8],0
	je        short @37
 ;	
 ;	        if (!chunk_is_used(cur) && chunk_length(cur) >= requested) {
 ;	
	?debug L 71
@36:
	push dword ptr [ebp-8]
	call _chunk_is_used
	pop ecx
	test eax,eax
	jne       short @38
	push dword ptr [ebp-8]
	call _chunk_length
	pop ecx
	cmp eax,dword ptr [ebp-4]
	jb        short @38
 ;	
 ;	            chunk_split(cur, requested);
 ;	
	?debug L 72
	push dword ptr [ebp-4]
	push dword ptr [ebp-8]
	call _chunk_split
	add esp,8
 ;	
 ;	            chunk_set_used(cur, 1);
 ;	
	?debug L 73
	push 1
	push dword ptr [ebp-8]
	call _chunk_set_used
	add esp,8
 ;	
 ;	
 ;	            return chunk_to_data(cur);
 ;	
	?debug L 75
	push dword ptr [ebp-8]
	call _chunk_to_data
	pop ecx
	jmp short @34
@38:
	mov ecx,dword ptr [ebp-8]
	mov eax,dword ptr [ecx]
	mov dword ptr [ebp-8],eax
	cmp dword ptr [ebp-8],0
	jne       short @36
 ;	
 ;	        }
 ;	    }
 ;	
 ;	    return NULL;
 ;	
	?debug L 79
@37:
	xor eax,eax
 ;	
 ;	}
 ;	
	?debug L 80
@40:
@34:
	pop ecx
	pop ecx
	pop ebp
	ret 
	?debug L 0
_freelist_alloc	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	62
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
	df	_freelist_alloc
	dw	0
	dw	4119
	dw	0
	dw	31
	dw	0
	dw	0
	dw	0
	db	15
	db	95
	db	102
	db	114
	db	101
	db	101
	db	108
	db	105
	db	115
	db	116
	db	95
	db	97
	db	108
	db	108
	db	111
	db	99
	dw	18
	dw	512
	dw	8
	dw	0
	dw	1027
	dw	0
	dw	32
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	12
	dw	0
	dw	117
	dw	0
	dw	33
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65528
	dw	65535
	dw	4102
	dw	0
	dw	34
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65532
	dw	65535
	dw	117
	dw	0
	dw	35
	dw	0
	dw	0
	dw	0
?patch28	equ	@40-_freelist_alloc+4
?patch29	equ	0
?patch30	equ	@40-_freelist_alloc
	dw	2
	dw	6
	dw	4
	dw	531
	dw	0
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_freelist_free	proc	near
?live1@944:
 ;	
 ;	void freelist_free(void *heap, void *ptr) {
 ;	
	?debug L 82
	push ebp
	mov ebp,esp
	add esp,-8
	push ebx
 ;	
 ;	    chunk_header *chunk;
 ;	
 ;	    if (ptr == NULL) {
 ;	
	?debug L 85
@41:
	cmp dword ptr [ebp+12],0
	je        @43
 ;	
 ;	        return;
 ;	
 ;	
 ;	    }
 ;	
 ;	    /* Mark chunk as free. */
 ;	    chunk = chunk_from_data(ptr);
 ;	
	?debug L 90
	push dword ptr [ebp+12]
	call _chunk_from_data
	pop ecx
	mov dword ptr [ebp-4],eax
 ;	
 ;	    chunk_set_used(chunk, 0);
 ;	
	?debug L 91
	push 0
	push dword ptr [ebp-4]
	call _chunk_set_used
	add esp,8
 ;	
 ;	    memset(ptr, 0, chunk_length(chunk) - sizeof(chunk_header));
 ;	
	?debug L 92
	push dword ptr [ebp-4]
	call _chunk_length
	pop ecx
	sub eax,8
	push eax
	push 0
	push dword ptr [ebp+12]
	call _memset
	add esp,12
 ;	
 ;	
 ;	    /* Coalesce adjacent free chunks. */
 ;	    chunk = (chunk_header *) heap;
 ;	
	?debug L 95
	mov eax,dword ptr [ebp+8]
	mov dword ptr [ebp-4],eax
	jmp short @45
 ;	
 ;	    while (chunk != NULL && chunk->next != NULL) {
 ;	        if (!chunk_is_used(chunk) && !chunk_is_used(chunk->next)) {
 ;	
	?debug L 97
@44:
	push dword ptr [ebp-4]
	call _chunk_is_used
	pop ecx
	test eax,eax
	jne       short @46
	mov edx,dword ptr [ebp-4]
	push dword ptr [edx]
	call _chunk_is_used
	pop ecx
	test eax,eax
	jne       short @46
 ;	
 ;	            void* old_next = chunk->next;
 ;	
	?debug L 98
@47:
	mov ecx,dword ptr [ebp-4]
	mov eax,dword ptr [ecx]
	mov dword ptr [ebp-8],eax
 ;	
 ;	
 ;	            chunk_write(chunk, chunk->next->next, chunk_length(chunk) + chunk_length(chunk->next), 0);
 ;	
	?debug L 100
	push 0
	push dword ptr [ebp-4]
	call _chunk_length
	pop ecx
	mov ebx,eax
	mov eax,dword ptr [ebp-4]
	push dword ptr [eax]
	call _chunk_length
	pop ecx
	add ebx,eax
	push ebx
	mov edx,dword ptr [ebp-4]
	mov ecx,dword ptr [edx]
	push dword ptr [ecx]
	push dword ptr [ebp-4]
	call _chunk_write
	add esp,16
 ;	
 ;	            memset(old_next, 0, sizeof(chunk_header));
 ;	
	?debug L 101
	push 8
	push 0
	push dword ptr [ebp-8]
	call _memset
	add esp,12
 ;	
 ;	        } else {
 ;	
	?debug L 102
@48:
	jmp short @49
 ;	
 ;	            chunk = chunk->next;
 ;	
	?debug L 103
@46:
	mov eax,dword ptr [ebp-4]
	mov edx,dword ptr [eax]
	mov dword ptr [ebp-4],edx
	?debug L 96
@49:
@45:
	cmp dword ptr [ebp-4],0
	je        short @50
	mov ecx,dword ptr [ebp-4]
	cmp dword ptr [ecx],0
	jne       short @44
 ;	
 ;	        }
 ;	    }
 ;	}
 ;	
	?debug L 106
@50:
@51:
@43:
	pop ebx
	pop ecx
	pop ecx
	pop ebp
	ret 
	?debug L 0
_freelist_free	endp
_TEXT	ends
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	61
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
	df	_freelist_free
	dw	0
	dw	4121
	dw	0
	dw	36
	dw	0
	dw	0
	dw	0
	db	14
	db	95
	db	102
	db	114
	db	101
	db	101
	db	108
	db	105
	db	115
	db	116
	db	95
	db	102
	db	114
	db	101
	db	101
	dw	18
	dw	512
	dw	8
	dw	0
	dw	1027
	dw	0
	dw	37
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	12
	dw	0
	dw	1027
	dw	0
	dw	38
	dw	0
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65532
	dw	65535
	dw	4102
	dw	0
	dw	39
	dw	0
	dw	0
	dw	0
	dw	24
	dw	519
	dw	0
	dw	0
	dw	0
	dw	0
	dd	?patch34
	df	@47
	dw	0
	dw	0
	dw	18
	dw	512
	dw	65528
	dw	65535
	dw	1027
	dw	0
	dw	40
	dw	0
	dw	0
	dw	0
?patch34	equ	@48-@47
	dw	2
	dw	6
?patch31	equ	@51-_freelist_free+5
?patch32	equ	0
?patch33	equ	@51-_freelist_free
	dw	2
	dw	6
	dw	8
	dw	531
	dw	1
	dw	65524
	dw	65535
$$BSYMS	ends
_TEXT	segment dword public use32 'CODE'
_TEXT	ends
	public	_freelist_init
	public	_freelist_alloc
	public	_freelist_free
 extrn _memset:near
$$BSYMS	segment byte public use32 'DEBSYM'
	dw	16
	dw	4
	dw	117
	dw	0
	dw	0
	dw	41
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	116
	dw	0
	dw	0
	dw	42
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	33
	dw	0
	dw	0
	dw	43
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	33
	dw	0
	dw	0
	dw	44
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	33
	dw	0
	dw	0
	dw	45
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4101
	dw	0
	dw	1
	dw	46
	dw	0
	dw	0
	dw	0
	dw	16
	dw	4
	dw	4101
	dw	0
	dw	0
	dw	47
	dw	0
	dw	0
	dw	0
	dw	?patch35
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
?patch35	equ	16
$$BSYMS	ends
$$BTYPES	segment byte public use32 'DEBTYP'
	db 2,0,0,0,14,0,8,0,117,0,0,0,0,0,1,0
	db 1,16,0,0,8,0,1,2,1,0,117,0,0,0,14,0
	db 8,0,117,0,0,0,0,0,1,0,8,16,0,0,8,0
	db 2,0,10,0,4,16,0,0,8,0,1,0,1,0,5,16
	db 0,0,28,0,5,0,2,0,7,16,0,0,0,0,0,0
	db 0,0,0,0,0,0,0,0,0,0,4,0,0,0,8,0
	db 8,0,2,0,10,0,5,16,0,0,40,0,4,2,6,4
	db 6,16,0,0,0,0,5,0,0,0,0,0,0,0,0,0
	db 242,241,6,4,116,0,0,0,0,0,6,0,0,0,0,0
	db 0,0,4,0,8,0,1,2,1,0,3,16,0,0,14,0
	db 8,0,116,0,0,0,0,0,1,0,10,16,0,0,8,0
	db 1,2,1,0,3,16,0,0,14,0,8,0,3,0,0,0
	db 0,0,2,0,12,16,0,0,12,0,1,2,2,0,6,16
	db 0,0,116,0,0,0,14,0,8,0,3,0,0,0,0,0
	db 4,0,14,16,0,0,20,0,1,2,4,0,6,16,0,0
	db 6,16,0,0,117,0,0,0,116,0,0,0,14,0,8,0
	db 32,4,0,0,0,0,1,0,16,16,0,0,8,0,1,2
	db 1,0,6,16,0,0,14,0,8,0,6,16,0,0,0,0
	db 1,0,18,16,0,0,8,0,1,2,1,0,3,4,0,0
	db 14,0,8,0,3,0,0,0,0,0,2,0,20,16,0,0
	db 12,0,1,2,2,0,6,16,0,0,117,0,0,0,14,0
	db 8,0,3,0,0,0,0,0,2,0,22,16,0,0,12,0
	db 1,2,2,0,3,4,0,0,117,0,0,0,14,0,8,0
	db 3,4,0,0,0,0,2,0,24,16,0,0,12,0,1,2
	db 2,0,3,4,0,0,117,0,0,0,14,0,8,0,3,0
	db 0,0,0,0,2,0,26,16,0,0,12,0,1,2,2,0
	db 3,4,0,0,3,4,0,0,14,0,8,0,3,4,0,0
	db 0,0,3,0,28,16,0,0,16,0,1,2,3,0,3,4
	db 0,0,116,0,0,0,117,0,0,0
$$BTYPES	ends
$$BNAMES	segment byte public use32 'DEBNAM'
	db	8,'align_up'
	db	5,'value'
	db	1,'m'
	db	12,'chunk_header'
	db	4,'next'
	db	6,'length'
	db	12,'chunk_length'
	db	5,'chunk'
	db	13,'chunk_is_used'
	db	5,'chunk'
	db	14,'chunk_set_used'
	db	5,'chunk'
	db	4,'used'
	db	11,'chunk_write'
	db	5,'chunk'
	db	4,'next'
	db	6,'length'
	db	4,'used'
	db	13,'chunk_to_data'
	db	5,'chunk'
	db	15,'chunk_from_data'
	db	3,'ptr'
	db	11,'chunk_split'
	db	5,'chunk'
	db	9,'requested'
	db	7,'new_len'
	db	9,'new_chunk'
	db	13,'freelist_init'
	db	4,'heap'
	db	9,'heap_size'
	db	14,'freelist_alloc'
	db	4,'heap'
	db	4,'size'
	db	3,'cur'
	db	9,'requested'
	db	13,'freelist_free'
	db	4,'heap'
	db	3,'ptr'
	db	5,'chunk'
	db	8,'old_next'
	db	6,'size_t'
	db	9,'ptrdiff_t'
	db	7,'wchar_t'
	db	6,'wint_t'
	db	8,'wctype_t'
	db	12,'chunk_header'
	db	12,'chunk_header'
$$BNAMES	ends
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\mem.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_loc.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\oldstl/locale.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_str.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\string.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_null.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_defs.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\_stddef.h" 11329 14336
	?debug	D "C:\Program Files (x86)\Borland\CBuilder6\Include\stddef.h" 11329 14336
	?debug	D "C:/Users/jblbe/Documents/Workspace/ghidra-delinker-extension/src/test/resources/programs/freelist-allocator/include\allocator.h" 23686 26776
	?debug	D "src/allocator.c" 23691 24756
	end
