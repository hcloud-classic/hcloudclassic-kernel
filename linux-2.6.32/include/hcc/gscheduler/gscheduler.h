#ifndef __HCC_GSCHEDULER_GSCHEDULER_H__
#define __HCC_GSCHEDULER_GSCHEDULER_H__

#include <hcc/gscheduler/process_set.h>

struct gscheduler_policy;
struct gscheduler;

/**
 * Get a reference on a gscheduler
 *
 * @param gscheduler	gscheduler to get a reference on
 */
void gscheduler_get(struct gscheduler *gscheduler);
/**
 * Put a reference on a gscheduler
 *
 * @param gscheduler	gscheduler to put a reference on
 */
void gscheduler_put(struct gscheduler *gscheduler);

/**
 * Get a reference on the gscheduler owning a gscheduler_policy
 * The reference must be put with gscheduler_put()
 *
 * @param policy	scheduling policy of the searched gscheduler
 *
 * @return		gscheduler owning the gscheduler_policy, or
 *			NULL if the gscheduler_policy is not used anymore
 */
struct gscheduler *
gscheduler_policy_get_gscheduler(struct gscheduler_policy *policy);

/**
 * Get a reference on the gscheduler owning a process set
 * The reference must be put with gscheduler_put()
 *
 * @param pset		process set of the searched gscheduler
 *
 * @return		gscheduler owning the process set
 */
struct gscheduler *process_set_get_gscheduler(struct process_set *pset);

/**
 * Get a reference on the sched policy of a gscheduler
 * The reference must be put with gscheduler_policy_put()
 *
 * @param gscheduler	gscheduler which sched policy to get
 *
 * @return		sched policy of the gscheduler
 */
struct gscheduler_policy *
gscheduler_get_gscheduler_policy(struct gscheduler *gscheduler);

/**
 * Get a reference on the process set managed by a gscheduler
 * The reference must be put with process_set_put()
 *
 * @param gscheduler	gscheduler to get the process set of
 *
 * @return		process set of the gscheduler, or
 *			NULL if the gscheduler is not active anymore
 */
struct process_set *gscheduler_get_process_set(struct gscheduler *gscheduler);

/**
 * Get the current node set of the gscheduler
 *
 * @param gscheduler	gscheduler which node set to get
 * @param node_set	node_set to copy the gscheduler's node set in
 */
void gscheduler_get_node_set(struct gscheduler *gscheduler,
			    hcc_nodemask_t *node_set);

/**
 * do {} while () style macro to begin an iteration over all universal
 * gschedulers (that is set to handle all processes)
 *
 * @param gscheduler	the gscheduler * to use as a loop cursor
 */
#define do_each_gscheduler_universal(gscheduler)			       \
	do {							       \
		struct process_set *__pset;			       \
		for_each_process_set_full(__pset) {		       \
			gscheduler = process_set_get_gscheduler(__pset); \
			if (gscheduler) {			       \
				do {

/**
 * do {} while () style macro to end an iteration over all universal
 * gschedulers (that is set to handle all processes)
 * Arguments must be the same as for do_each_gscheduler_universal()
 */
#define while_each_gscheduler_universal(gscheduler)		       \
				} while (0);			       \
				gscheduler_put(gscheduler);	       \
			}					       \
		}						       \
	} while (0)

/**
 * do {} while () style macro to begin an iteration over the gschedulers managing
 * a task
 * Schedulers attached to all tasks have to be separately parsed with
 * do_each_gscheduler_universal()
 * caller must hold either RCU lock or tasklist_lock
 *
 * @param gscheduler	the gscheduler * to use a loop cursor
 * @param task		task which gschedulers to iterate over
 */
#define do_each_gscheduler_task(gscheduler, task)			       \
	do {							       \
		struct process_set *__pset;			       \
		do_each_process_set_task(__pset, task) {	       \
			gscheduler = process_set_get_gscheduler(__pset); \
			if (gscheduler) {			       \
				do {

/**
 * do {} while () style macro to end an iteration over the gschedulers managing
 * a task
 * Arguments must be the same as for do_each_gscheduler_task()
 */
#define while_each_gscheduler_task(gscheduler, task)		       \
				} while (0);			       \
				gscheduler_put(gscheduler);	       \
			}					       \
		} while_each_process_set_task(__pset, task);	       \
	} while (0)

#endif /* __HCC_GSCHEDULER_GSCHEDULER_H__ */
