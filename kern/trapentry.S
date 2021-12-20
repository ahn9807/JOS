/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>
#include <kern/macro.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushq $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushq $0;							\
	pushq $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
   Find the PUSHA,POPA macros in kern/macro.h. Since amd64 doesn't support
   pusha,popa so you will find these macros handy.
 */

# trap numbers order
TRAPHANDLER_NOEC(XTRPX_divzero, T_DIVIDE)  # 0
TRAPHANDLER_NOEC(XTRPX_debug, T_DEBUG)     # 1
TRAPHANDLER_NOEC(XTRPX_nmint, T_NMI)       # 2
TRAPHANDLER_NOEC(XTRPX_brkpt, T_BRKPT)     # 3
TRAPHANDLER_NOEC(XTRPX_oflow, T_OFLOW)     # 4
TRAPHANDLER_NOEC(XTRPX_bound, T_BOUND)     # 5
TRAPHANDLER_NOEC(XTRPX_illop, T_ILLOP)     # 6
TRAPHANDLER_NOEC(XTRPX_device, T_DEVICE)   # 7

TRAPHANDLER(XTRPX_dblflt, T_DBLFLT)        # 8
TRAPHANDLER(XTRPX_tss, T_TSS)              # 10
TRAPHANDLER(XTRPX_segnp, T_SEGNP)          # 11
TRAPHANDLER(XTRPX_stack, T_STACK)          # 12
TRAPHANDLER(XTRPX_gpflt, T_GPFLT)          # 13
TRAPHANDLER(XTRPX_pgflt, T_PGFLT)          # 14

TRAPHANDLER_NOEC(XTRPX_fperr, T_FPERR)     # 16
TRAPHANDLER(XTRPX_align, T_ALIGN)          # 17
TRAPHANDLER_NOEC(XTRPX_mchk, T_MCHK)       # 18
TRAPHANDLER_NOEC(XTRPX_simderr, T_SIMDERR) # 19

TRAPHANDLER_NOEC(IRQ_32, IRQ_OFFSET + 0);
TRAPHANDLER_NOEC(IRQ_33, IRQ_OFFSET + 1);
TRAPHANDLER_NOEC(IRQ_34, IRQ_OFFSET + 2);
TRAPHANDLER_NOEC(IRQ_35, IRQ_OFFSET + 3);
TRAPHANDLER_NOEC(IRQ_36, IRQ_OFFSET + 4);
TRAPHANDLER_NOEC(IRQ_37, IRQ_OFFSET + 5);
TRAPHANDLER_NOEC(IRQ_38, IRQ_OFFSET + 6);
TRAPHANDLER_NOEC(IRQ_39, IRQ_OFFSET + 7);
TRAPHANDLER_NOEC(IRQ_40, IRQ_OFFSET + 8);
TRAPHANDLER_NOEC(IRQ_41, IRQ_OFFSET + 9);
TRAPHANDLER_NOEC(IRQ_42, IRQ_OFFSET + 10);
TRAPHANDLER_NOEC(IRQ_43, IRQ_OFFSET + 11);
TRAPHANDLER_NOEC(IRQ_44, IRQ_OFFSET + 12);
TRAPHANDLER_NOEC(IRQ_45, IRQ_OFFSET + 13);
TRAPHANDLER_NOEC(IRQ_46, IRQ_OFFSET + 14);
TRAPHANDLER_NOEC(IRQ_47, IRQ_OFFSET + 15);

TRAPHANDLER_NOEC(XTRPX_syscall, T_SYSCALL) # 48
TRAPHANDLER_NOEC(XTRPX_default, T_DEFAULT) # 500


/*
 * Lab 3: Your code here for _alltraps
 *
 * Hint: Be sure to review the x64 calling convention from lab1
 *       for how to pass a pointer to the trapframe.
 */

_alltraps:
	# 1. push values to make the stack look like a struct Trapframe
	subq $0x10, %rsp
	movw %es, 0x8(%rsp)
	movw %ds, 0x0(%rsp)
	PUSHA
	
	movq $GD_KD, %rax # 2. load GD_KD into %ds and %es
	movw %ax, %ds    
	movq $GD_KD, %rax
	movw %ax, %es
	
	movq %rsp, %rdi   # 3. Pass a pointer to the Trapframe as an argument to trap()
	call trap         # 4. call trap
	# POPA_
	# iret