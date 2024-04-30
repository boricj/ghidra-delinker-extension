#include <asm/reg.h>

.text
.set	noreorder
	lui	$v1,%hi(HELLO_WORLD)
	addiu	$v1,$v1,%lo(HELLO_WORLD)
	addiu	$v1,$v1,6
	addiu	$v1,$v1,2
	lb	$v0,0x1($v1)
	jr	$ra
	nop
.data
HELLO_WORLD:
.asciiz	"Hello, world!"
