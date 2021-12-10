/*
 *  include/asm-s390/sigp.h
 *
 *  S390 version
 *    Copyright (C) 1999 IBM Deutschland Entwicklung GmbH, IBM Corporation
 *    Author(s): Denis Joseph Barrow (djbarrow@de.ibm.com,barrow_dj@yahoo.com),
 *               Martin Schwidefsky (schwidefsky@de.ibm.com)
 *               Heiko Carstens (heiko.carstens@de.ibm.com)
 *
 *  sigp.h by D.J. Barrow (c) IBM 1999
 *  contains routines / structures for signalling other S/390 processors in an
 *  SMP configuration.
 */

#ifndef __SIGP__
#define __SIGP__

#include <asm/system.h>

/* get real cpu address from logical cpu number */
extern int __cpu_logical_map[];

static inline int cpu_logical_map(int cpu)
{
#ifdef CONFIG_SMP
	return __cpu_logical_map[cpu];
#else
	return stap();
#endif
}

typedef enum
{
	sigp_sense = 1,
	sigp_external_call = 2,
	sigp_emergency_signal = 3,
	sigp_start = 4,
	sigp_stop = 5,
	sigp_restart = 6,
	sigp_stop_and_store_status = 9,
	sigp_initial_cpu_reset = 11,
	sigp_cpu_reset = 12,
	sigp_set_prefix = 13,
	sigp_store_status_at_address = 14,
	sigp_store_extended_status_at_address = 15,
	sigp_set_architecture = 18,
	sigp_conditional_emergency_signal = 19,
	sigp_sense_running = 21,
} sigp_order_code;

typedef __u32 sigp_status_word;

typedef enum
{
	sigp_order_code_accepted = 0,
	sigp_status_stored = 1,
	sigp_busy = 2,
	sigp_not_operational = 3,
} sigp_ccode;


/*
 * Definitions for the external call
 */

/* 'Bit' signals, asynchronous */
typedef enum
{
	ec_schedule=0,
	ec_call_function,
	ec_call_function_single,
	ec_stop_cpu,
} ec_bit_sig;

/*
 * Signal processor
 */
static inline sigp_ccode
signal_processor(__u16 cpu_addr, sigp_order_code order_code)
{
	register unsigned long reg1 asm ("1") = 0;
	sigp_ccode ccode;

	asm volatile(
		"	sigp	%1,%2,0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28\n"
		:	"=d"	(ccode)
		: "d" (reg1), "d" (cpu_logical_map(cpu_addr)),
		  "a" (order_code) : "cc" , "memory");
	return ccode;
}

/*
 * Signal processor with parameter
 */
static inline sigp_ccode
signal_processor_p(__u32 parameter, __u16 cpu_addr, sigp_order_code order_code)
{
	register unsigned int reg1 asm ("1") = parameter;
	sigp_ccode ccode;

	asm volatile(
		"	sigp	%1,%2,0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28\n"
		: "=d" (ccode)
		: "d" (reg1), "d" (cpu_logical_map(cpu_addr)),
		  "a" (order_code) : "cc" , "memory");
	return ccode;
}

/*
 * Signal processor with parameter and return status
 */
static inline sigp_ccode
signal_processor_ps(__u32 *statusptr, __u32 parameter, __u16 cpu_addr,
		    sigp_order_code order_code)
{
	register unsigned int reg1 asm ("1") = parameter;
	sigp_ccode ccode;

	asm volatile(
		"	sigp	%1,%2,0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28\n"
		: "=d" (ccode), "+d" (reg1)
		: "d" (cpu_logical_map(cpu_addr)), "a" (order_code)
		: "cc" , "memory");
	*statusptr = reg1;
	return ccode;
}

/*
 * Signal processor
 */
static inline int raw_sigp(u16 cpu, int order)
{
	register unsigned long reg1 asm ("1") = 0;
	int ccode;

	asm volatile(
		"       sigp    %1,%2,0(%3)\n"
		"       ipm     %0\n"
		"       srl     %0,28\n"
		:       "=d"    (ccode)
		: "d" (reg1), "d" (cpu),
		  "a" (order) : "cc" , "memory");
	return ccode;
}

#endif /* __SIGP__ */
