#include <asm/reg.h>

.text
.set	noreorder
test:
	lui	$v0,%hi(HELLO_WORLD)
	lb	$at,%lo(HELLO_WORLD)($v0)
	lui	$v1,%hi(GOODBYE_WORLD)
	lb	$v0,%lo(GOODBYE_WORLD)($v1)
	jr	$ra
	nop
.data
HELLO_WORLD:
.asciiz	"Hello, world!"
GOODBYE_WORLD:
.asciiz	"Goodbye, world!"
