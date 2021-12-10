#include <linux/notifier.h>
#include <hcc/ghotplug.h>
#include <hcc/hcc_nodemask.h>
#include <hcc/sys/types.h>
#include <hcc/hcc_init.h>

static void membership_online_add(hcc_nodemask_t *vector)
{
	hcc_node_t i;

	__for_each_hcc_node_mask(i, vector){
		if(hcc_node_online(i))
			continue;
		set_hcc_node_online(i);
		hcc_nb_nodes++;
	}
}

static void membership_online_remove(hcc_nodemask_t *vector)
{
	hcc_node_t i;

	__for_each_hcc_node_mask(i, vector){
		if(!hcc_node_online(i))
			continue;
		clear_hcc_node_online(i);
		hcc_nb_nodes--;
	}
}

static
int membership_online_notification(struct notifier_block *nb,
				   ghotplug_event_t event,
				   void *data)
{
	
	switch(event){
	case GHOTPLUG_NOTIFY_ADD:{
		struct ghotplug_context *ctx = data;
		membership_online_add(&ctx->node_set.v);
		break;
	}

	case GHOTPLUG_NOTIFY_REMOVE_LOCAL:{
		hcc_node_t node;
		for_each_online_hcc_node(node)
			if(node != hcc_node_id)
				clear_hcc_node_online(node);
	}
		
	case GHOTPLUG_NOTIFY_REMOVE_ADVERT:{
		struct ghotplug_node_set *node_set = data;
		membership_online_remove(&node_set->v);
		break;
	}

	default:
		break;

	} /* switch */
	
	return NOTIFY_OK;
}

static
int membership_present_notification(struct notifier_block *nb,
				    ghotplug_event_t event, void *data)
{
	switch(event){
	default:
		break;
	} /* switch */

	return NOTIFY_OK;
}

int ghotplug_membership_init(void)
{
	register_ghotplug_notifier(membership_present_notification,
				  GHOTPLUG_PRIO_MEMBERSHIP_PRESENT);
	register_ghotplug_notifier(membership_online_notification,
				  GHOTPLUG_PRIO_MEMBERSHIP_ONLINE);
	return 0;
}

void ghotplug_membership_cleanup(void)
{
}
