#ifndef __HCC_HCC_SIGNAL_H__
#define __HCC_HCC_SIGNAL_H__

/* HCC signal */

#ifdef CONFIG_HCC_GPM

#include <asm/signal.h>

struct siginfo;
struct pt_regs;
struct task_struct;

typedef void hcc_handler_t(int sig, struct siginfo *info,
				 struct pt_regs *regs);

extern hcc_handler_t *hcc_handler[_NSIG];

int send_hcc_signal(int sig, struct siginfo *info, struct task_struct *t);

#endif /* CONFIG_HCC_GPM */

#endif /* __HCC_HCC_SIGNAL_H__ */
