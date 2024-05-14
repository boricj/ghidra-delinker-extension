#include <asm/reg.h>

.text
.set	noreorder
test:
	lui	$v0,%hi(HELLO_WORLD)
	addiu	$v0,$v0,%lo(HELLO_WORLD)
	lui	$v1,%hi(GOODBYE_WORLD)
	addiu	$v1,$v1,%lo(GOODBYE_WORLD)
	lwl	$t0,0x3($v0)
	lwr	$t0,0x0($v0)
	lwl	$t1,0x7($v0)
	lwr	$t1,0x4($v0)
	swl	$t0,0x3($v1)
	swr	$t0,0x0($v1)
	swl	$t1,0x7($v1)
	swr	$t1,0x4($v1)
	jr	$ra
	nop
.data
HELLO_WORLD:
.asciiz	"Hello, world!"
GOODBYE_WORLD:
.asciiz	"Goodbye, world!"
