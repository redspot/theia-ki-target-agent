/* Copyright (C) 2002-2006, 2009 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Jakub Jelinek <jakub@redhat.com>, 2002.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include <sysdep.h>
#include <tls.h>
#ifndef __ASSEMBLER__
# include <nptl/pthreadP.h>
#endif

#if !defined NOT_IN_libc || defined IS_IN_libpthread || defined IS_IN_librt

/* The code to disable cancellation depends on the fact that the called
   functions are special.  They don't modify registers other than %rax
   and %r11 if they return.  Therefore we don't have to preserve other
   registers around these calls.  */
# undef PSEUDO
# define PSEUDO(name, syscall_name, args)				      \
  .text;								      \
  ENTRY (name)								      \
    SINGLE_THREAD_P;							      \
    jne L(pseudo_cancel);						      \
  .type __##syscall_name##_nocancel,@function;				      \
  .globl __##syscall_name##_nocancel;					      \
  __##syscall_name##_nocancel:						      \
    DO_CALL (syscall_name, args);					      \
    cmpq $-4095, %rax;							      \
    jae SYSCALL_ERROR_LABEL;						      \
    ret;								      \
  .size __##syscall_name##_nocancel,.-__##syscall_name##_nocancel;	      \
  L(pseudo_cancel):							      \
    pushq %rdi; cfi_adjust_cfa_offset (8); cfi_rel_offset (%rdi, 0);	      \
    pushq %rsi; cfi_adjust_cfa_offset (8); cfi_rel_offset (%rsi, 0);	      \
    pushq %rdx; cfi_adjust_cfa_offset (8); cfi_rel_offset (%rdx, 0);	      \
    pushq %r10; cfi_adjust_cfa_offset (8); cfi_rel_offset (%r10, 0);	      \
    pushq %r8; cfi_adjust_cfa_offset (8); cfi_rel_offset (%r8, 0);	      \
    pushq %r9; cfi_adjust_cfa_offset (8); cfi_rel_offset (%r9, 0);	      \
    CENABLE                                                                   \
    popq %r9; cfi_adjust_cfa_offset (-8); cfi_restore (%r9);		      \
    popq %r8; cfi_adjust_cfa_offset (-8); cfi_restore (%r8);		      \
    popq %r10; cfi_adjust_cfa_offset (-8); cfi_restore (%r10);		      \
    popq %rdx; cfi_adjust_cfa_offset (-8); cfi_restore (%rdx);		      \
    popq %rsi; cfi_adjust_cfa_offset (-8); cfi_restore (%rsi);		      \
    popq %rdi; cfi_adjust_cfa_offset (-8); cfi_restore (%rdi);		      \
    subq $8, %rsp; cfi_adjust_cfa_offset (8);                                 \
    movq %rax, (%rsp);                                                        \
    DO_CALL (syscall_name, args);					      \
    movq (%rsp), %rdi;                                                        \
    movq %rax, (%rsp);                                                        \
    CDISABLE                                                                  \
    movq (%rsp), %rax;                                                        \
    addq $8,%rsp; cfi_adjust_cfa_offset (-8);                                 \
    cmpq $-4095, %rax;							      \
    jae SYSCALL_ERROR_LABEL;						      \
  L(pseudo_end):

// Sangho's version
//  L(pseudo_cancel):							      \
//    /* THEIA: workaround for *_nocancel */                                    \
//    DO_CALL (syscall_name, args);					      \
//    cmpq $-4095, %rax;							      \
//    jae SYSCALL_ERROR_LABEL;						      \
//  L(pseudo_end):

# ifdef IS_IN_libpthread
#  define CENABLE	call __pthread_enable_asynccancel;
#  define CDISABLE	call __pthread_disable_asynccancel;
#  define __local_multiple_threads __pthread_multiple_threads
# elif !defined NOT_IN_libc
#  define CENABLE	call __libc_enable_asynccancel;
#  define CDISABLE	call __libc_disable_asynccancel;
#  define __local_multiple_threads __libc_multiple_threads
# elif defined IS_IN_librt
#  define CENABLE	call __librt_enable_asynccancel;
#  define CDISABLE	call __librt_disable_asynccancel;
# else
#  error Unsupported library
# endif

# if defined IS_IN_libpthread || !defined NOT_IN_libc
#  ifndef __ASSEMBLER__
extern int __local_multiple_threads attribute_hidden;
#   define SINGLE_THREAD_P \
  __builtin_expect (__local_multiple_threads == 0, 1)
#  else
#   define SINGLE_THREAD_P cmpl $0, __local_multiple_threads(%rip)
#  endif

# else

#  ifndef __ASSEMBLER__
#   define SINGLE_THREAD_P \
  __builtin_expect (THREAD_GETMEM (THREAD_SELF, \
				   header.multiple_threads) == 0, 1)
#  else
#   define SINGLE_THREAD_P cmpl $0, %fs:MULTIPLE_THREADS_OFFSET
#  endif

# endif

#elif !defined __ASSEMBLER__

# define SINGLE_THREAD_P (1)
# define NO_CANCELLATION 1

#endif

#ifndef __ASSEMBLER__
# define RTLD_SINGLE_THREAD_P \
  __builtin_expect (THREAD_GETMEM (THREAD_SELF, \
				   header.multiple_threads) == 0, 1)
#endif
