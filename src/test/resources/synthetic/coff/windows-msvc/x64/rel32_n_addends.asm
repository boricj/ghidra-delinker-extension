; ==============================================================================
; Test Fixture for AMD64 COFF REL32_N Relocations with addends.
; Assemble with: ml64.exe /c rel32_n_addends.asm
; ==============================================================================

EXTERN target_symbol : BYTE
EXTERN target_array  : BYTE

.code

PUBLIC test_rel32_n_addends
test_rel32_n_addends PROC

    ; --------------------------------------------------------------------------
    ; 0 Trailing Bytes -> IMAGE_REL_AMD64_REL32
    ; --------------------------------------------------------------------------
    mov eax, dword ptr (target_array + 8)
    lea rdx, dword ptr (target_array + 12)

    ; --------------------------------------------------------------------------
    ; 1 Trailing Byte -> IMAGE_REL_AMD64_REL32_1
    ; --------------------------------------------------------------------------
    cmp byte ptr (target_array + 16), 07Fh
    add qword ptr (target_array + 16), 012h

    ; --------------------------------------------------------------------------
    ; 2 Trailing Bytes -> IMAGE_REL_AMD64_REL32_2
    ; --------------------------------------------------------------------------
    cmp word ptr (target_array + 32), 01234h
    mov word ptr (target_array + 32), 05678h

    ; --------------------------------------------------------------------------
    ; 4 Trailing Bytes -> IMAGE_REL_AMD64_REL32_4
    ; --------------------------------------------------------------------------
    cmp dword ptr (target_array + 64), 011223344h
    imul eax, dword ptr (target_array + 64), 011223344h

    ; --------------------------------------------------------------------------
    ; Negative Addend Check
    ; --------------------------------------------------------------------------
    mov eax, dword ptr (target_array - 4)
    imul ecx, dword ptr (target_array - 4), 011223344h

    ret
test_rel32_n_addends ENDP

END
