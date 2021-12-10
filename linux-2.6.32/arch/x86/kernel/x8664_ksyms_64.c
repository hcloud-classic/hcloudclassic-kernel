/* Exports for assembly files.
   All C exports should go in the respective C files. */

#include <linux/module.h>
#include <linux/smp.h>

#include <net/checksum.h>

#include <asm/processor.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include <asm/desc.h>
#include <asm/ftrace.h>
#include <asm/asm.h>

#ifdef CONFIG_FUNCTION_TRACER
/* mcount is defined in assembly */
EXPORT_SYMBOL(mcount);
#endif

EXPORT_SYMBOL(kernel_thread);

EXPORT_SYMBOL(__get_user_1);
EXPORT_SYMBOL(__get_user_2);
EXPORT_SYMBOL(__get_user_4);
EXPORT_SYMBOL(__get_user_8);
#ifdef CONFIG_HCC_FAF
EXPORT_SYMBOL(ruaccess_get_user_asm);
#endif /* CONFIG_HCC_FAF */
EXPORT_SYMBOL(__put_user_1);
EXPORT_SYMBOL(__put_user_2);
EXPORT_SYMBOL(__put_user_4);
EXPORT_SYMBOL(__put_user_8);
#ifdef CONFIG_HCC_FAF
EXPORT_SYMBOL(ruaccess_put_user_asm);
#endif /* CONFIG_HCC_FAF */

__must_check unsigned long notrace
copy_user_generic(void *to, const void *from, unsigned len)
{
	unsigned ret;

	alternative_call(copy_user_generic_unrolled,
			 copy_user_generic_string,
			 X86_FEATURE_REP_GOOD,
			 ASM_OUTPUT2("=a" (ret), "=D" (to), "=S" (from),
				     "=d" (len)),
			 "1" (to), "2" (from), "3" (len)
			 : "memory", "rcx", "r8", "r9", "r10", "r11");
	return ret;
}
EXPORT_SYMBOL(copy_user_generic);
EXPORT_SYMBOL(copy_user_generic_string);
EXPORT_SYMBOL(copy_user_generic_unrolled);
EXPORT_SYMBOL(__copy_user_nocache);
EXPORT_SYMBOL(copy_from_user);
EXPORT_SYMBOL(copy_to_user);

__must_check long __copy_from_user_inatomic(void *dst, const void __user *src,
					    unsigned size)
{
	return copy_user_generic(dst, (__force const void *)src, size);
}
EXPORT_SYMBOL(__copy_from_user_inatomic);

EXPORT_SYMBOL(copy_page);
EXPORT_SYMBOL(clear_page);

EXPORT_SYMBOL(csum_partial);

/*
 * Export string functions. We normally rely on gcc builtin for most of these,
 * but gcc sometimes decides not to inline them.
 */
#undef memcpy
#undef memset
#undef memmove

extern void *memset(void *, int, __kernel_size_t);
extern void *memcpy(void *, const void *, __kernel_size_t);
extern void *__memcpy(void *, const void *, __kernel_size_t);

EXPORT_SYMBOL(memset);
EXPORT_SYMBOL(memcpy);
EXPORT_SYMBOL(__memcpy);
EXPORT_SYMBOL(memmove);

EXPORT_SYMBOL(empty_zero_page);
EXPORT_SYMBOL(init_level4_pgt);
EXPORT_SYMBOL(load_gs_index);

#ifdef CONFIG_RETPOLINE
#define EXPORT_THUNK(reg)						\
	extern void __x86_indirect_thunk_ ## reg(void);			\
	EXPORT_SYMBOL(__x86_indirect_thunk_ ## reg)

EXPORT_THUNK(rax);
EXPORT_THUNK(rbx);
EXPORT_THUNK(rcx);
EXPORT_THUNK(rdx);
EXPORT_THUNK(rsi);
EXPORT_THUNK(rdi);
EXPORT_THUNK(rbp);
EXPORT_THUNK(r8);
EXPORT_THUNK(r9);
EXPORT_THUNK(r10);
EXPORT_THUNK(r11);
EXPORT_THUNK(r12);
EXPORT_THUNK(r13);
EXPORT_THUNK(r14);
EXPORT_THUNK(r15);
#endif /* CONFIG_RETPOLINE */
