#include <asm/reg.h>

.text
.set	noreorder
test:
	lui	$a0,%hi(HELLO_WORLD)
	move	$v1,$a0
	lb	$v0,%lo(HELLO_WORLD)($v1)
	jr	$ra
	nop
.data
HELLO_WORLD:
.asciiz	"Hello, world!"
