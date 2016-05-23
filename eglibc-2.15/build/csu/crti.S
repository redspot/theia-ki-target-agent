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
	.p2align 2,,3
	.globl	_init
	.type	_init, @function
_init:
	pushl	%ebx
	subl	$8, %esp
	call	.L6
.L6:
	popl	%ebx
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L6], %ebx
	movl	__gmon_start__@GOT(%ebx), %eax
	testl	%eax, %eax
	je	.L5
	call	__gmon_start__@PLT
.L5:
#APP
# 101 "../sysdeps/generic/initfini.c" 1
	ALIGN
# 0 "" 2
# 102 "../sysdeps/generic/initfini.c" 1
	END_INIT
# 0 "" 2
# 104 "../sysdeps/generic/initfini.c" 1
	
/*@_init_PROLOG_ENDS*/
/*@_fini_PROLOG_BEGINS*/
	.section .fini
#NO_APP
	.section	.fini,"ax",@progbits
	.p2align 2,,3
	.globl	_fini
	.type	_fini, @function
_fini:
	pushl	%ebx
	subl	$8, %esp
	call	.L8
.L8:
	popl	%ebx
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L8], %ebx
#APP
# 121 "../sysdeps/generic/initfini.c" 1
	ALIGN
# 0 "" 2
# 122 "../sysdeps/generic/initfini.c" 1
	END_FINI
# 0 "" 2
# 123 "../sysdeps/generic/initfini.c" 1
	
/*@_fini_PROLOG_ENDS*/
/*@TRAILER_BEGINS*/
	.weak	__gmon_start__
	.ident	"GCC: (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3"
	.section	.note.GNU-stack,"",@progbits
