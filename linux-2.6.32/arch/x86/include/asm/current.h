#ifndef _ASM_X86_CURRENT_H
#define _ASM_X86_CURRENT_H

#include <linux/compiler.h>
#include <asm/percpu.h>

#ifndef __ASSEMBLY__
struct task_struct;

DECLARE_PER_CPU(struct task_struct *, current_task);

static __always_inline struct task_struct *get_current(void)
{
	return percpu_read_stable(current_task);
}

#ifdef CONFIG_HCC_GPM
#define hcc_current (get_current()->effective_current)
#define current ({							\
	struct task_struct *__cur = get_current();			\
	__cur->effective_current ? __cur->effective_current : __cur;	\
})
#else /* !CONFIG_HCC_GPM */
#define current get_current()
#endif /* !CONFIG_HCC_GPM */

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_CURRENT_H */
