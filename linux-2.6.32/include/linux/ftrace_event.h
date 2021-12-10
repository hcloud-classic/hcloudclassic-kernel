#ifndef _LINUX_FTRACE_EVENT_H
#define _LINUX_FTRACE_EVENT_H

#include <linux/ring_buffer.h>
#include <linux/trace_seq.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>

#ifndef __GENKSYMS__
#include <linux/perf_event.h>
#endif

struct trace_array;
struct tracer;
struct dentry;

DECLARE_PER_CPU(struct trace_seq, ftrace_event_seq);

struct trace_print_flags {
	unsigned long		mask;
	const char		*name;
};

struct trace_print_flags_u64 {
	unsigned long long	mask;
	const char		*name;
};

const char *ftrace_print_flags_seq(struct trace_seq *p, const char *delim,
				   unsigned long flags,
				   const struct trace_print_flags *flag_array);

const char *ftrace_print_symbols_seq(struct trace_seq *p, unsigned long val,
				     const struct trace_print_flags *symbol_array);

#if BITS_PER_LONG == 32
const char *ftrace_print_symbols_seq_u64(struct trace_seq *p,
					 unsigned long long val,
					 const struct trace_print_flags_u64
								 *symbol_array);
#endif

const char *ftrace_print_hex_seq(struct trace_seq *p,
				 const unsigned char *buf, int len);

/*
 * The trace entry - the most basic unit of tracing. This is what
 * is printed in the end as a single line in the trace output, such as:
 *
 *     bash-15816 [01]   235.197585: idle_cpu <- irq_enter
 */
struct trace_entry {
	unsigned short		type;
	unsigned char		flags;
	unsigned char		preempt_count;
	int			pid;
	int			lock_depth;
};

#define FTRACE_MAX_EVENT						\
	((1 << (sizeof(((struct trace_entry *)0)->type) * 8)) - 1)

/*
 * Trace iterator - used by printout routines who present trace
 * results to users and which routines might sleep, etc:
 */
struct trace_iterator {
	struct trace_array	*tr;
	struct tracer		*trace;
	void			*private;
	int			cpu_file;
	struct mutex		mutex;
	struct ring_buffer_iter	*buffer_iter[NR_CPUS];
	unsigned long		iter_flags;

	/* The below is zeroed out in pipe_read */
	struct trace_seq	seq;
	struct trace_entry	*ent;
	int			cpu;
	u64			ts;

	loff_t			pos;
	long			idx;

	cpumask_var_t		started;
#ifndef __GENKSYMS__
	int			leftover;
#endif
};

enum trace_iter_flags {
	TRACE_FILE_LAT_FMT	= 1,
	TRACE_FILE_ANNOTATE	= 2,
	TRACE_FILE_TIME_IN_NS	= 4,
};


typedef enum print_line_t (*trace_print_func)(struct trace_iterator *iter,
					      int flags);
struct trace_event {
	struct hlist_node	node;
	struct list_head	list;
	int			type;
	trace_print_func	trace;
	trace_print_func	raw;
	trace_print_func	hex;
	trace_print_func	binary;
};

extern int register_ftrace_event(struct trace_event *event);
extern int unregister_ftrace_event(struct trace_event *event);

/* Return values for print_line callback */
enum print_line_t {
	TRACE_TYPE_PARTIAL_LINE	= 0,	/* Retry after flushing the seq */
	TRACE_TYPE_HANDLED	= 1,
	TRACE_TYPE_UNHANDLED	= 2,	/* Relay to other output functions */
	TRACE_TYPE_NO_CONSUME	= 3	/* Handled but ask to not consume */
};

void tracing_generic_entry_update(struct trace_entry *entry,
				  unsigned long flags,
				  int pc);
struct ring_buffer_event *
trace_current_buffer_lock_reserve(struct ring_buffer **current_buffer,
				  int type, unsigned long len,
				  unsigned long flags, int pc);
void trace_current_buffer_unlock_commit(struct ring_buffer *buffer,
					struct ring_buffer_event *event,
					unsigned long flags, int pc);
void trace_nowake_buffer_unlock_commit(struct ring_buffer *buffer,
				       struct ring_buffer_event *event,
					unsigned long flags, int pc);
void trace_nowake_buffer_unlock_commit_regs(struct ring_buffer *buffer,
					    struct ring_buffer_event *event,
					    unsigned long flags, int pc,
					    struct pt_regs *regs);
void trace_current_buffer_discard_commit(struct ring_buffer *buffer,
					 struct ring_buffer_event *event);

void tracing_record_cmdline(struct task_struct *tsk);

struct event_filter;

enum {
	TRACE_EVENT_FL_ENABLED_BIT,
	TRACE_EVENT_FL_FILTERED_BIT,
	TRACE_EVENT_FL_RECORDED_CMD_BIT,

	/*
	 * RHEL6 specific bit.
	 *
	 * Due to KABI constraints, we cannot change ftrace_event_call
	 * struct. This bit is to differentiate among current RHEL6
	 * version with 'print_fmt' pointer and older releases versions
	 * with show_format pointer. Both occupy same place.
	 */
	TRACE_EVENT_FL_KABI_PRINT_FMT_BIT = 31,
};

enum {
	TRACE_EVENT_FL_ENABLED		= (1 << TRACE_EVENT_FL_ENABLED_BIT),
	TRACE_EVENT_FL_FILTERED		= (1 << TRACE_EVENT_FL_FILTERED_BIT),
	TRACE_EVENT_FL_RECORDED_CMD	= (1 << TRACE_EVENT_FL_RECORDED_CMD_BIT),
	TRACE_EVENT_FL_KABI_PRINT_FMT	= (1 << TRACE_EVENT_FL_KABI_PRINT_FMT_BIT),
};

struct ftrace_event_call {
	struct list_head	list;
	char			*name;
	char			*system;
	struct dentry		*dir;
	struct trace_event	*event;
	/* The enabled field was invalidated by flags field,
	 * but is left here due to the KABI constrains. */
	int			enabled;
	int			(*regfunc)(struct ftrace_event_call *);
	void			(*unregfunc)(struct ftrace_event_call *);
	int			id;
	int			(*raw_init)(struct ftrace_event_call *);
#ifdef __GENKSYMS__
	int			(*show_format)(struct ftrace_event_call *,
					       struct trace_seq *);
#else
	/*
	 * RHEL6 specific.
	 *
	 * TRACE_EVENT_FL_KABI_PRINT_FMT flags bit tells what
	 * pointer to use. From this version onward RHEL6 uses
	 * print_fmt and have TRACE_EVENT_FL_KABI_PRINT_FMT
	 * flags bit enabled by default. Older releases have this
	 * flags bit set to 0 and use show_format pointer.
	 */
	union {
		int		(*show_format)(struct ftrace_event_call *,
					       struct trace_seq *);
		const char	*print_fmt;
	} fmt;
#endif
	int			(*define_fields)(struct ftrace_event_call *);
	struct list_head	fields;
#ifdef __GENKSYMS__
	int			filter_active;
#else
	/*
	 * 32 bit flags:
	 *   bit 1:		enabled
	 *   bit 2:		filter_active
	 *   bit 3:		enabled cmd record
	 *   bit 31:		print_fmt format display
	 *   			(read TRACE_EVENT_FL_KABI_PRINT_FMT_BIT
	 *   			enum comment)
	 *
	 * Changes to flags must hold the event_mutex.
	 *
	 * Note: Reads of flags do not hold the event_mutex since
	 * they occur in critical sections. But the way flags
	 * is currently used, these changes do no affect the code
	 * except that when a change is made, it may have a slight
	 * delay in propagating the changes to other CPUs due to
	 * caching and such.
	 */
	unsigned int		flags;
#endif
	struct event_filter	*filter;
	void			*mod;
	void			*data;

	atomic_t		profile_count;
	int			(*profile_enable)(struct ftrace_event_call *);
	void			(*profile_disable)(struct ftrace_event_call *);
};

#define FTRACE_MAX_PROFILE_SIZE	2048

extern char *trace_profile_buf;
extern char *trace_profile_buf_nmi;

#define MAX_FILTER_PRED		32
#define MAX_FILTER_STR_VAL	256	/* Should handle KSYM_SYMBOL_LEN */

extern void destroy_preds(struct ftrace_event_call *call);
extern int filter_match_preds(struct event_filter *filter, void *rec);
extern int filter_current_check_discard(struct ring_buffer *buffer,
					struct ftrace_event_call *call,
					void *rec,
					struct ring_buffer_event *event);

enum {
	FILTER_OTHER = 0,
	FILTER_STATIC_STRING,
	FILTER_DYN_STRING,
	FILTER_PTR_STRING,
};

extern int trace_define_common_fields(struct ftrace_event_call *call);
extern int trace_define_field(struct ftrace_event_call *call, const char *type,
			      const char *name, int offset, int size,
			      int is_signed, int filter_type);
extern int trace_add_event_call(struct ftrace_event_call *call);
extern void trace_remove_event_call(struct ftrace_event_call *call);

#define is_signed_type(type)	(((type)(-1)) < 0)

int trace_set_clr_event(const char *system, const char *event, int set);

/*
 * The double __builtin_constant_p is because gcc will give us an error
 * if we try to allocate the static variable to fmt if it is not a
 * constant. Even with the outer if statement optimizing out.
 */
#define event_trace_printk(ip, fmt, args...)				\
do {									\
	__trace_printk_check_format(fmt, ##args);			\
	tracing_record_cmdline(current);				\
	if (__builtin_constant_p(fmt)) {				\
		static const char *trace_printk_fmt			\
		  __attribute__((section("__trace_printk_fmt"))) =	\
			__builtin_constant_p(fmt) ? fmt : NULL;		\
									\
		__trace_bprintk(ip, trace_printk_fmt, ##args);		\
	} else								\
		__trace_printk(ip, fmt, ##args);			\
} while (0)

#ifdef CONFIG_EVENT_PROFILE
struct perf_event;
extern int ftrace_profile_enable(int event_id);
extern void ftrace_profile_disable(int event_id);
extern int ftrace_profile_set_filter(struct perf_event *event, int event_id,
				     char *filter_str);
extern void ftrace_profile_free_filter(struct perf_event *event);
extern void *
ftrace_perf_buf_prepare(int size, unsigned short type, int *rctxp,
			 unsigned long *irq_flags);

static inline void
ftrace_perf_buf_submit(void *raw_data, int size, int rctx, u64 addr,
		       u64 count, unsigned long irq_flags,
		       struct pt_regs *regs)
{
	struct trace_entry *entry = raw_data;

	perf_tp_event_regs(entry->type, addr, count, raw_data, size, regs);
	perf_swevent_put_recursion_context(rctx);
	local_irq_restore(irq_flags);
}
#endif

#define PTRS_MASK 1

static inline bool use_ftrace_events_ptrs(void *ptr)
{
	return ((unsigned long) ptr & PTRS_MASK) == 0;
}

static inline bool module_has_ftrace_events_ptrs(struct module *mod)
{
	return (unsigned long) mod->trace_events.ptrs & PTRS_MASK;
}

static inline struct ftrace_event_call**
ftrace_events_ptrs_mask(struct ftrace_event_call** ptrs)
{
	unsigned long p = (unsigned long) ptrs;

	p |= PTRS_MASK;
	return (struct ftrace_event_call**) p;
}

static inline struct ftrace_event_call**
module_ftrace_events_ptrs_unmask(struct ftrace_event_call** ptrs)
{
	unsigned long p = (unsigned long) ptrs;

	p &= ~PTRS_MASK;
	return (struct ftrace_event_call**) p;
}

#undef PTRS_MASK
#endif /* _LINUX_FTRACE_EVENT_H */
