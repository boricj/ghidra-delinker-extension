; ==============================================================================
; Test Fixture for AMD64 COFF REL32_N Relocations.
; Assemble with: ml64.exe /c rel32_n.asm
; ==============================================================================

EXTERN target_symbol : BYTE
EXTERN target_array  : BYTE

.code

PUBLIC test_rel32_n
test_rel32_n PROC

    ; --------------------------------------------------------------------------
    ; 0 Trailing Bytes -> IMAGE_REL_AMD64_REL32
    ; --------------------------------------------------------------------------
    mov eax, dword ptr target_symbol
    lea rdx, dword ptr target_symbol

    ; --------------------------------------------------------------------------
    ; 1 Trailing Byte -> IMAGE_REL_AMD64_REL32_1
    ; --------------------------------------------------------------------------
    cmp byte ptr target_symbol, 07Fh
    add qword ptr target_symbol, 012h

    ; --------------------------------------------------------------------------
    ; 2 Trailing Bytes -> IMAGE_REL_AMD64_REL32_2
    ; --------------------------------------------------------------------------
    cmp word ptr target_symbol, 01234h
    mov word ptr target_symbol, 05678h

    ; --------------------------------------------------------------------------
    ; 4 Trailing Bytes -> IMAGE_REL_AMD64_REL32_4
    ; --------------------------------------------------------------------------
    cmp dword ptr target_symbol, 011223344h
    imul eax, dword ptr target_symbol, 011223344h

    ret
test_rel32_n ENDP

END
