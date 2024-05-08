#include <asm/reg.h>

.text
.set	noreorder
test:
	beq	$a0,$zero,1f
	lui	$v0,%hi(HELLO_WORLD)
	lui	$v0,%hi(GOODBYE_WORLD)
	j	2f
	lb	$v0,%lo(GOODBYE_WORLD)($v0)
1:
	lb	$v0,%lo(HELLO_WORLD)($v0)
2:
	jr	$ra
	nop
.data
HELLO_WORLD:
.asciiz	"Hello, world!"
GOODBYE_WORLD:
.asciiz	"Goodbye, world!"
