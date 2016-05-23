#APP
	
#include "defs.h"
	
#if defined __i686 && defined __ASSEMBLER__
	
#undef __i686
	
#define __i686 __i686
	
#endif
	
/*@HEADER_ENDS*/
/*@_init_PROLOG_BEGINS*/
	.section .init
#NO_APP
	.section	.init,"ax",@progbits
	.p2align 4,,15
	.globl	_init
	.type	_init, @function
_init:
	subl	$12, %esp
	call	__pthread_initialize_minimal_internal
#APP
# 87 "../nptl/sysdeps/pthread/pt-initfini.c" 1
	ALIGN
# 0 "" 2
# 88 "../nptl/sysdeps/pthread/pt-initfini.c" 1
	END_INIT
# 0 "" 2
# 90 "../nptl/sysdeps/pthread/pt-initfini.c" 1
	
/*@_init_PROLOG_ENDS*/
/*@_fini_PROLOG_BEGINS*/
	.section .fini
#NO_APP
	.section	.fini,"ax",@progbits
	.p2align 4,,15
	.globl	_fini
	.type	_fini, @function
_fini:
	pushl	%ebx
	subl	$8, %esp
	call	__i686.get_pc_thunk.bx
	addl	$_GLOBAL_OFFSET_TABLE_, %ebx
#APP
# 107 "../nptl/sysdeps/pthread/pt-initfini.c" 1
	ALIGN
# 0 "" 2
# 108 "../nptl/sysdeps/pthread/pt-initfini.c" 1
	END_FINI
# 0 "" 2
# 109 "../nptl/sysdeps/pthread/pt-initfini.c" 1
	
/*@_fini_PROLOG_ENDS*/
/*@TRAILER_BEGINS*/
	.section	.text.__i686.get_pc_thunk.bx,"axG",@progbits,__i686.get_pc_thunk.bx,comdat
	.globl	__i686.get_pc_thunk.bx
	.hidden	__i686.get_pc_thunk.bx
	.type	__i686.get_pc_thunk.bx, @function
__i686.get_pc_thunk.bx:
	movl	(%esp), %ebx
	ret
#NO_APP
	.hidden	__pthread_initialize_minimal_internal
	.ident	"GCC: (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3"
	.section	.note.GNU-stack,"",@progbits
