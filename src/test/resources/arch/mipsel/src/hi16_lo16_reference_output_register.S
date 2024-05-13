#include <asm/reg.h>

.text
.set	noreorder
test:
	lui	$v0,%hi(HELLO_WORLD)
	addiu	$v0,$v0,%lo(HELLO_WORLD)
	lui	$v1,%hi(PTR)
	sw	$v0,%lo(PTR)($v1)
	jr	$ra
	nop
.data
HELLO_WORLD:
.asciiz	"Hello, world!"
PTR:
.word	0
