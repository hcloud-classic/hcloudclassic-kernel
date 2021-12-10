/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the Interfaces handler.
 *
 * Version:	@(#)dev.h	1.0.10	08/12/93
 *
 * Authors:	Ross Biro
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Corey Minyard <wf-rch!minyard@relay.EU.net>
 *		Donald J. Becker, <becker@cesdis.gsfc.nasa.gov>
 *		Alan Cox, <alan@lxorguk.ukuu.org.uk>
 *		Bjorn Ekwall. <bj0rn@blox.se>
 *              Pekka Riikonen <priikone@poseidon.pspt.fi>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *		Moved to /usr/include/linux for NET3
 */
#ifndef _LINUX_NETDEVICE_H
#define _LINUX_NETDEVICE_H

#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_link.h>

#ifdef __KERNEL__
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <asm/atomic.h>
#include <asm/cache.h>
#include <asm/byteorder.h>

#include <linux/device.h>
#include <linux/percpu.h>
#include <linux/rculist.h>
#include <linux/dmaengine.h>
#include <linux/workqueue.h>

#include <linux/ethtool.h>
#include <net/net_namespace.h>
#include <net/dsa.h>
#ifdef CONFIG_DCB
#include <net/dcbnl.h>
#endif
#ifndef __GENKSYMS__
#include <net/netprio_cgroup.h>
#include <linux/neighbour.h>
#endif

struct vlan_group;
struct netpoll_info;
/* 802.11 specific */
struct wireless_dev;
					/* source back-compat hooks */
#define SET_ETHTOOL_OPS(netdev,ops) \
	( (netdev)->ethtool_ops = (ops) )

#define HAVE_ALLOC_NETDEV		/* feature macro: alloc_xxxdev
					   functions are available. */
#define HAVE_FREE_NETDEV		/* free_netdev() */
#define HAVE_NETDEV_PRIV		/* netdev_priv() */

#define NET_XMIT_SUCCESS	0
#define NET_XMIT_DROP		1	/* skb dropped			*/
#define NET_XMIT_CN		2	/* congestion notification	*/
#define NET_XMIT_POLICED	3	/* skb is shot by police	*/
#define NET_XMIT_MASK		0xFFFF	/* qdisc flags in net/sch_generic.h */

/* hardware address assignment types */
#define NET_ADDR_PERM		0	/* address is permanent (default) */
#define NET_ADDR_RANDOM		1	/* address is generated randomly */
#define NET_ADDR_STOLEN		2	/* address is stolen from other device */
#define NET_ADDR_SET		3	/* address is set using
					 * dev_set_mac_address() */

/* Backlog congestion levels */
#define NET_RX_SUCCESS		0   /* keep 'em coming, baby */
#define NET_RX_DROP		1  /* packet dropped */

/* NET_XMIT_CN is special. It does not guarantee that this packet is lost. It
 * indicates that the device will soon be dropping packets, or already drops
 * some packets of the same priority; prompting us to send less aggressively. */
#define net_xmit_eval(e)	((e) == NET_XMIT_CN? 0 : (e))
#define net_xmit_errno(e)	((e) != NET_XMIT_CN ? -ENOBUFS : 0)

/* Driver transmit return codes */
enum netdev_tx {
	NETDEV_TX_OK = 0,	/* driver took care of packet */
	NETDEV_TX_BUSY,		/* driver tx path was busy*/
	NETDEV_TX_LOCKED = -1,	/* driver tx lock was already taken */
};
typedef enum netdev_tx netdev_tx_t;

#endif

#define MAX_ADDR_LEN	32		/* Largest hardware address length */

#ifdef  __KERNEL__
/*
 *	Compute the worst case header length according to the protocols
 *	used.
 */

#if defined(CONFIG_WLAN_80211) || defined(CONFIG_AX25) || defined(CONFIG_AX25_MODULE)
# if defined(CONFIG_MAC80211_MESH)
#  define LL_MAX_HEADER 128
# else
#  define LL_MAX_HEADER 96
# endif
#elif defined(CONFIG_TR) || defined(CONFIG_TR_MODULE)
# define LL_MAX_HEADER 48
#else
# define LL_MAX_HEADER 32
#endif

#if !defined(CONFIG_NET_IPIP) && !defined(CONFIG_NET_IPIP_MODULE) && \
    !defined(CONFIG_NET_IPGRE) &&  !defined(CONFIG_NET_IPGRE_MODULE) && \
    !defined(CONFIG_IPV6_SIT) && !defined(CONFIG_IPV6_SIT_MODULE) && \
    !defined(CONFIG_IPV6_TUNNEL) && !defined(CONFIG_IPV6_TUNNEL_MODULE)
#define MAX_HEADER LL_MAX_HEADER
#else
#define MAX_HEADER (LL_MAX_HEADER + 48)
#endif

/*
 *	Old network device statistics. Fields are native words
 *	(unsigned long) so they can be read and written atomically.
 */

struct net_device_stats {
	unsigned long	rx_packets;
	unsigned long	tx_packets;
	unsigned long	rx_bytes;
	unsigned long	tx_bytes;
	unsigned long	rx_errors;
	unsigned long	tx_errors;
	unsigned long	rx_dropped;
	unsigned long	tx_dropped;
	unsigned long	multicast;
	unsigned long	collisions;
	unsigned long	rx_length_errors;
	unsigned long	rx_over_errors;
	unsigned long	rx_crc_errors;
	unsigned long	rx_frame_errors;
	unsigned long	rx_fifo_errors;
	unsigned long	rx_missed_errors;
	unsigned long	tx_aborted_errors;
	unsigned long	tx_carrier_errors;
	unsigned long	tx_fifo_errors;
	unsigned long	tx_heartbeat_errors;
	unsigned long	tx_window_errors;
	unsigned long	rx_compressed;
	unsigned long	tx_compressed;
};

#endif  /*  __KERNEL__  */

/* interface name assignment types (sysfs name_assign_type attribute) */
#define NET_NAME_UNKNOWN	0	/* unknown origin (not exposed to userspace) */
#define NET_NAME_ENUM		1	/* enumerated by kernel */
#define NET_NAME_PREDICTABLE	2	/* predictably named by the kernel */
#define NET_NAME_USER		3	/* provided by user-space */
#define NET_NAME_RENAMED	4	/* renamed by user-space */

/* Media selection options. */
enum {
        IF_PORT_UNKNOWN = 0,
        IF_PORT_10BASE2,
        IF_PORT_10BASET,
        IF_PORT_AUI,
        IF_PORT_100BASET,
        IF_PORT_100BASETX,
        IF_PORT_100BASEFX
};

#ifdef __KERNEL__

#include <linux/cache.h>
#include <linux/skbuff.h>

struct neighbour;
struct neigh_parms;
struct sk_buff;

struct netif_rx_stats
{
	unsigned total;
	unsigned dropped;
	unsigned time_squeeze;
	unsigned cpu_collision;
	unsigned received_rps;
};

DECLARE_PER_CPU(struct netif_rx_stats, netdev_rx_stat);

struct dev_addr_list
{
	struct dev_addr_list	*next;
	u8			da_addr[MAX_ADDR_LEN];
	u8			da_addrlen;
	u8			da_synced;
	int			da_users;
	int			da_gusers;
};

/*
 *	We tag multicasts with these structures.
 */

#define dev_mc_list	dev_addr_list
#define dmi_addr	da_addr
#define dmi_addrlen	da_addrlen
#define dmi_users	da_users
#define dmi_gusers	da_gusers

struct netdev_hw_addr {
	struct list_head	list;
	unsigned char		addr[MAX_ADDR_LEN];
	unsigned char		type;
#define NETDEV_HW_ADDR_T_LAN		1
#define NETDEV_HW_ADDR_T_SAN		2
#define NETDEV_HW_ADDR_T_SLAVE		3
#define NETDEV_HW_ADDR_T_UNICAST	4
	int			refcount;
	bool			synced;
	struct rcu_head		rcu_head;
};

struct netdev_hw_addr_list {
	struct list_head	list;
	int			count;
};

#define netdev_uc_count(dev) ((dev)->uc.count)
#define netdev_uc_empty(dev) ((dev)->uc.count == 0)
#define netdev_for_each_uc_addr(ha, dev) \
	list_for_each_entry(ha, &dev->uc.list, list)

#define netdev_mc_count(dev) ((dev)->mc_count)
#define netdev_mc_empty(dev) (netdev_mc_count(dev) == 0)

#define netdev_for_each_mc_addr(mclist, dev) \
	for (mclist = dev->mc_list; mclist; mclist = mclist->next)

struct hh_cache {
	struct hh_cache *hh_next;	/* Next entry			     */
	atomic_t	hh_refcnt;	/* number of users                   */
/*
 * We want hh_output, hh_len, hh_lock and hh_data be a in a separate
 * cache line on SMP.
 * They are mostly read, but hh_refcnt may be changed quite frequently,
 * incurring cache line ping pongs.
 */
	__be16		hh_type ____cacheline_aligned_in_smp;
					/* protocol identifier, f.e ETH_P_IP
                                         *  NOTE:  For VLANs, this will be the
                                         *  encapuslated type. --BLG
                                         */
	u16		hh_len;		/* length of header */
	int		(*hh_output)(struct sk_buff *skb);
	seqlock_t	hh_lock;

	/* cached hardware header; allow for machine alignment needs.        */
#define HH_DATA_MOD	16
#define HH_DATA_OFF(__len) \
	(HH_DATA_MOD - (((__len - 1) & (HH_DATA_MOD - 1)) + 1))
#define HH_DATA_ALIGN(__len) \
	(((__len)+(HH_DATA_MOD-1))&~(HH_DATA_MOD - 1))
	unsigned long	hh_data[HH_DATA_ALIGN(LL_MAX_HEADER) / sizeof(long)];
};

/* Reserve HH_DATA_MOD byte aligned hard_header_len, but at least that much.
 * Alternative is:
 *   dev->hard_header_len ? (dev->hard_header_len +
 *                           (HH_DATA_MOD - 1)) & ~(HH_DATA_MOD - 1) : 0
 *
 * We could use other alignment values, but we must maintain the
 * relationship HH alignment <= LL alignment.
 *
 * LL_ALLOCATED_SPACE also takes into account the tailroom the device
 * may need.
 */
#define LL_RESERVED_SPACE(dev) \
	((((dev)->hard_header_len+(dev)->needed_headroom)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_RESERVED_SPACE_EXTRA(dev,extra) \
	((((dev)->hard_header_len+(dev)->needed_headroom+(extra))&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)
#define LL_ALLOCATED_SPACE(dev) \
	((((dev)->hard_header_len+(dev)->needed_headroom+(dev)->needed_tailroom)&~(HH_DATA_MOD - 1)) + HH_DATA_MOD)

struct header_ops {
	int	(*create) (struct sk_buff *skb, struct net_device *dev,
			   unsigned short type, const void *daddr,
			   const void *saddr, unsigned len);
	int	(*parse)(const struct sk_buff *skb, unsigned char *haddr);
	int	(*rebuild)(struct sk_buff *skb);
#define HAVE_HEADER_CACHE
	int	(*cache)(const struct neighbour *neigh, struct hh_cache *hh);
	void	(*cache_update)(struct hh_cache *hh,
				const struct net_device *dev,
				const unsigned char *haddr);
};

/* These flag bits are private to the generic network queueing
 * layer, they may not be explicitly referenced by any other
 * code.
 */

enum netdev_state_t
{
	__LINK_STATE_START,
	__LINK_STATE_PRESENT,
	__LINK_STATE_NOCARRIER,
	__LINK_STATE_LINKWATCH_PENDING,
	__LINK_STATE_DORMANT,
};


/*
 * This structure holds at boot time configured netdevice settings. They
 * are then used in the device probing.
 */
struct netdev_boot_setup {
	char name[IFNAMSIZ];
	struct ifmap map;
};
#define NETDEV_BOOT_SETUP_MAX 8

extern int __init netdev_boot_setup(char *str);

/*
 * Structure for NAPI scheduling similar to tasklet but with weighting
 */
struct napi_struct {
	/* The poll_list must only be managed by the entity which
	 * changes the state of the NAPI_STATE_SCHED bit.  This means
	 * whoever atomically sets that bit can add this napi_struct
	 * to the per-cpu poll_list, and whoever clears that bit
	 * can remove from the list right before clearing the bit.
	 */
	struct list_head	poll_list;

	unsigned long		state;
	int			weight;
	int			(*poll)(struct napi_struct *, int);
#ifdef CONFIG_NETPOLL
	spinlock_t		poll_lock;
	int			poll_owner;
#endif

	unsigned int		gro_count;

	struct net_device	*dev;
	struct list_head	dev_list;
	struct sk_buff		*gro_list;
	struct sk_buff		*skb;
#ifndef __GENKSYMS__
	struct hlist_node	napi_hash_node;
	unsigned int		napi_id;
	size_t			size;
	struct hrtimer		timer;
#endif
};

#define NAPI_STRUCT_HAS(napi, member)					\
	({ const struct napi_struct *__n = napi;			\
	 (test_bit(NAPI_STATE_EXT, &__n->state) &&			\
	  (offsetof(struct napi_struct, member) < __n->size)); })

enum
{
	NAPI_STATE_SCHED,	/* Poll is scheduled */
	NAPI_STATE_DISABLE,	/* Disable pending */
	NAPI_STATE_NPSVC,	/* Netpoll - don't dequeue from poll_list */
	NAPI_STATE_HASHED,	/* In NAPI hash */
	NAPI_STATE_EXT,		/* Extended napi_struct */
};

enum gro_result {
	GRO_MERGED,
	GRO_MERGED_FREE,
	GRO_HELD,
	GRO_NORMAL,
	GRO_DROP,
};
/*
 * Make gro_result_t a separate type for the sparse checker.
 * This helps avoid confusion between napi_gro_frags{,_gr}
 * and similar function pairs we have in RHEL.
 */
typedef enum gro_result __bitwise__ gro_result_t;
#define GRO_MERGED	((__force gro_result_t) GRO_MERGED)
#define GRO_MERGED_FREE	((__force gro_result_t) GRO_MERGED_FREE)
#define GRO_HELD	((__force gro_result_t) GRO_HELD)
#define GRO_NORMAL	((__force gro_result_t) GRO_NORMAL)
#define GRO_DROP	((__force gro_result_t) GRO_DROP)

/*
 * enum rx_handler_result - Possible return values for rx_handlers.
 * @RX_HANDLER_CONSUMED: skb was consumed by rx_handler, do not process it
 * further.
 * @RX_HANDLER_ANOTHER: Do another round in receive path. This is indicated in
 * case skb->dev was changed by rx_handler.
 * @RX_HANDLER_EXACT: Force exact delivery, no wildcard.
 * @RX_HANDLER_PASS: Do nothing, passe the skb as if no rx_handler was called.
 *
 * rx_handlers are functions called from inside __netif_receive_skb(), to do
 * special processing of the skb, prior to delivery to protocol handlers.
 *
 * Currently, a net_device can only have a single rx_handler registered. Trying
 * to register a second rx_handler will return -EBUSY.
 *
 * To register a rx_handler on a net_device, use netdev_rx_handler_register().
 * To unregister a rx_handler on a net_device, use
 * netdev_rx_handler_unregister().
 *
 * Upon return, rx_handler is expected to tell __netif_receive_skb() what to
 * do with the skb.
 *
 * If the rx_handler consumed to skb in some way, it should return
 * RX_HANDLER_CONSUMED. This is appropriate when the rx_handler arranged for
 * the skb to be delivered in some other ways.
 *
 * If the rx_handler changed skb->dev, to divert the skb to another
 * net_device, it should return RX_HANDLER_ANOTHER. The rx_handler for the
 * new device will be called if it exists.
 *
 * If the rx_handler consider the skb should be ignored, it should return
 * RX_HANDLER_EXACT. The skb will only be delivered to protocol handlers that
 * are registred on exact device (ptype->dev == skb->dev).
 *
 * If the rx_handler didn't changed skb->dev, but want the skb to be normally
 * delivered, it should return RX_HANDLER_PASS.
 *
 * A device without a registered rx_handler will behave as if rx_handler
 * returned RX_HANDLER_PASS.
 */

enum rx_handler_result {
	RX_HANDLER_CONSUMED,
	RX_HANDLER_ANOTHER,
	RX_HANDLER_EXACT,
	RX_HANDLER_PASS,
};
typedef enum rx_handler_result rx_handler_result_t;
typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **pskb);

extern void __napi_schedule(struct napi_struct *n);

static inline int napi_disable_pending(struct napi_struct *n)
{
	return test_bit(NAPI_STATE_DISABLE, &n->state);
}

/**
 *	napi_schedule_prep - check if napi can be scheduled
 *	@n: napi context
 *
 * Test if NAPI routine is already running, and if not mark
 * it as running.  This is used as a condition variable
 * insure only one NAPI poll instance runs.  We also make
 * sure there is no pending NAPI disable.
 */
static inline int napi_schedule_prep(struct napi_struct *n)
{
	return !napi_disable_pending(n) &&
		!test_and_set_bit(NAPI_STATE_SCHED, &n->state);
}

/**
 *	napi_schedule - schedule NAPI poll
 *	@n: napi context
 *
 * Schedule NAPI poll routine to be called if it is not already
 * running.
 */
static inline void napi_schedule(struct napi_struct *n)
{
	if (napi_schedule_prep(n))
		__napi_schedule(n);
}

/* Try to reschedule poll. Called by dev->poll() after napi_complete().  */
static inline int napi_reschedule(struct napi_struct *napi)
{
	if (napi_schedule_prep(napi)) {
		__napi_schedule(napi);
		return 1;
	}
	return 0;
}

void __napi_complete(struct napi_struct *n);
void napi_complete_done(struct napi_struct *n, int work_done);
/**
 *	napi_complete - NAPI processing complete
 *	@n: napi context
 *
 * Mark NAPI processing as complete.
 * Consider using napi_complete_done() instead.
 */
static inline void _napi_complete(struct napi_struct *n)
{
	return napi_complete_done(n, 0);
}

/* RHEL has napi_complete in KABI so we need to keep it for binary
 * modules. Newly compiled modules will use inlined function. */
void napi_complete(struct napi_struct *n);
#define napi_complete _napi_complete

/**
 *	napi_by_id - lookup a NAPI by napi_id
 *	@napi_id: hashed napi_id
 *
 * lookup @napi_id in napi_hash table
 * must be called under rcu_read_lock()
 */
extern struct napi_struct *napi_by_id(unsigned int napi_id);

/**
 *	napi_hash_add - add a NAPI to global hashtable
 *	@napi: napi context
 *
 * generate a new napi_id and store a @napi under it in napi_hash
 */
extern void napi_hash_add(struct napi_struct *napi);

/**
 *	napi_hash_del - remove a NAPI from global table
 *	@napi: napi context
 *
 * Warning: caller must observe rcu grace period
 * before freeing memory containing @napi
 */
extern void napi_hash_del(struct napi_struct *napi);

/**
 *	napi_disable - prevent NAPI from scheduling
 *	@n: napi context
 *
 * Stop NAPI from being scheduled on this context.
 * Waits till any outstanding processing completes.
 */
void napi_disable(struct napi_struct *n);

/**
 *	napi_enable - enable NAPI scheduling
 *	@n: napi context
 *
 * Resume NAPI from being scheduled on this context.
 * Must be paired with napi_disable.
 */
static inline void napi_enable(struct napi_struct *n)
{
	BUG_ON(!test_bit(NAPI_STATE_SCHED, &n->state));
	smp_mb__before_clear_bit();
	clear_bit(NAPI_STATE_SCHED, &n->state);
	clear_bit(NAPI_STATE_NPSVC, &n->state);
}

#ifdef CONFIG_SMP
/**
 *	napi_synchronize - wait until NAPI is not running
 *	@n: napi context
 *
 * Wait until NAPI is done being scheduled on this context.
 * Waits till any outstanding processing completes but
 * does not disable future activations.
 */
static inline void napi_synchronize(const struct napi_struct *n)
{
	while (test_bit(NAPI_STATE_SCHED, &n->state))
		msleep(1);
}
#else
# define napi_synchronize(n)	barrier()
#endif

enum netdev_queue_state_t
{
	__QUEUE_STATE_XOFF,
	__QUEUE_STATE_FROZEN,
};

struct netdev_queue {
/*
 * read mostly part
 */
	struct net_device	*dev;
	struct Qdisc		*qdisc;
	unsigned long		state;
	struct Qdisc		*qdisc_sleeping;
/*
 * write mostly part
 */
	spinlock_t		_xmit_lock ____cacheline_aligned_in_smp;
	int			xmit_lock_owner;
	/*
	 * please use this field instead of dev->trans_start
	 */
	unsigned long		trans_start;
	unsigned long		tx_bytes;
	unsigned long		tx_packets;
	unsigned long		tx_dropped;
} ____cacheline_aligned_in_smp;

/*
 * This structure holds an RPS map which can be of variable length.  The
 * map is an array of CPUs.
 */
struct rps_map {
	unsigned int len;
	struct rcu_head rcu;
	u16 cpus[0];
};
#define RPS_MAP_SIZE(_num) (sizeof(struct rps_map) + ((_num) * sizeof(u16)))

/*
 * This structure holds an XPS map which can be of variable length.  The
 * map is an array of queues.
 */
struct xps_map {
	unsigned int len;
	unsigned int alloc_len;
	struct rcu_head rcu;
	u16 queues[0];
};
#define XPS_MAP_SIZE(_num) (sizeof(struct xps_map) + ((_num) * sizeof(u16)))
#define XPS_MIN_MAP_ALLOC ((L1_CACHE_BYTES - sizeof(struct xps_map))	\
    / sizeof(u16))

/*
 * This structure holds all XPS maps for device.  Maps are indexed by CPU.
 */
struct xps_dev_maps {
	struct rcu_head rcu;
	struct xps_map *cpu_map[0];
};
#define XPS_DEV_MAPS_SIZE (sizeof(struct xps_dev_maps) +		\
    (nr_cpu_ids * sizeof(struct xps_map *)))

 /*
  * The rps_dev_flow structure contains the mapping of a flow to a CPU, the
  * tail pointer for that CPU's input queue at the time of last enqueue, and
  * a hardware filter index.
  */
struct rps_dev_flow {
	u16 cpu;
	u16 filter;
	unsigned int last_qtail;
};
#define RPS_NO_FILTER 0xffff

 /*
  * The rps_dev_flow_table structure contains a table of flow mappings.
  */
struct rps_dev_flow_table {
	unsigned int mask;
	struct rcu_head rcu;
	struct work_struct free_work;
	struct rps_dev_flow flows[0];
};

#define RPS_DEV_FLOW_TABLE_SIZE(_num) (sizeof(struct rps_dev_flow_table) + \
     ((_num) * sizeof(struct rps_dev_flow)))

 /*
  * The rps_sock_flow_table contains mappings of flows to the last CPU
  * on which they were processed by the application (set in recvmsg).
  */
struct rps_sock_flow_table {
	unsigned int mask;
	u16 ents[0];
};
#define	RPS_SOCK_FLOW_TABLE_SIZE(_num) (sizeof(struct rps_sock_flow_table) + \
     ((_num) * sizeof(u16)))

#define RPS_NO_CPU 0xffff

static inline void rps_record_sock_flow(struct rps_sock_flow_table *table,
					u32 hash)
{
	if (table && hash) {
		unsigned int cpu, index = hash & table->mask;

		/* We only give a hint, preemption can change cpu under us */
		cpu = raw_smp_processor_id();

		if (table->ents[index] != cpu)
			table->ents[index] = cpu;
	}
}

static inline void rps_reset_sock_flow(struct rps_sock_flow_table *table,
				       u32 hash)
{
	if (table && hash)
		table->ents[hash & table->mask] = RPS_NO_CPU;
}

extern struct rps_sock_flow_table *rps_sock_flow_table;

#ifdef CONFIG_RFS_ACCEL
extern bool rps_may_expire_flow(struct net_device *dev, u16 rxq_index,
				u32 flow_id, u16 filter_id);
#endif

/* This structure contains an instance of an RX queue. */
struct netdev_rx_queue {
	struct rps_map *rps_map;
	struct rps_dev_flow_table *rps_flow_table;
	struct kobject kobj;
	struct net_device *dev;
} ____cacheline_aligned_in_smp;

#define TC_MAX_QUEUE	16
#define TC_BITMASK	15
/* HW offloaded queuing disciplines txq count and offset maps */
struct netdev_tc_txq {
	u16 count;
	u16 offset;
};

#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
/*
 * This structure is to hold information about the device
 * configured to run FCoE protocol stack.
 */
struct netdev_fcoe_hbainfo {
	char	manufacturer[64];
	char	serial_number[64];
	char	hardware_version[64];
	char	driver_version[64];
	char	optionrom_version[64];
	char	firmware_version[64];
	char	model[256];
	char	model_description[256];
};
#endif

#define MAX_PHYS_PORT_ID_LEN 32

/* This structure holds a unique identifier to identify the
 * physical port used by a netdevice.
 */
struct netdev_phys_port_id {
	unsigned char id[MAX_PHYS_PORT_ID_LEN];
	unsigned char id_len;
};

/*
 * This structure defines the management hooks for network devices.
 * The following hooks can be defined; unless noted otherwise, they are
 * optional and can be filled with a null pointer.
 *
 * int (*ndo_init)(struct net_device *dev);
 *     This function is called once when network device is registered.
 *     The network device can use this to any late stage initializaton
 *     or semantic validattion. It can fail with an error code which will
 *     be propogated back to register_netdev
 *
 * void (*ndo_uninit)(struct net_device *dev);
 *     This function is called when device is unregistered or when registration
 *     fails. It is not called if init fails.
 *
 * int (*ndo_open)(struct net_device *dev);
 *     This function is called when network device transistions to the up
 *     state.
 *
 * int (*ndo_stop)(struct net_device *dev);
 *     This function is called when network device transistions to the down
 *     state.
 *
 * netdev_tx_t (*ndo_start_xmit)(struct sk_buff *skb,
 *                               struct net_device *dev);
 *	Called when a packet needs to be transmitted.
 *	Must return NETDEV_TX_OK , NETDEV_TX_BUSY.
 *        (can also return NETDEV_TX_LOCKED iff NETIF_F_LLTX)
 *	Required can not be NULL.
 *
 * u16 (*ndo_select_queue)(struct net_device *dev, struct sk_buff *skb);
 *	Called to decide which queue to when device supports multiple
 *	transmit queues.
 *
 * void (*ndo_change_rx_flags)(struct net_device *dev, int flags);
 *	This function is called to allow device receiver to make
 *	changes to configuration when multicast or promiscious is enabled.
 *
 * void (*ndo_set_rx_mode)(struct net_device *dev);
 *	This function is called when the device changes either the unicast or
 *	multicast address filter lists.
 *	If the device defines this entry point, but can't enable reception
 *	of more than it's own unicast MAC address, then it should also set
 *	netdev_extended(dev)->ext_priv_flags |= IFF_NO_UNICAST_FLT to signal
 *	that we should enable promisc mode on this interface when we need
 *	to receive more than just our own MAC's Unicast address.
 *
 * void (*ndo_set_multicast_list)(struct net_device *dev);
 *	This function is called when the multicast address list changes.
 *
 * int (*ndo_set_mac_address)(struct net_device *dev, void *addr);
 *	This function  is called when the Media Access Control address
 *	needs to be changed. If this interface is not defined, the
 *	mac address can not be changed.
 *
 * int (*ndo_validate_addr)(struct net_device *dev);
 *	Test if Media Access Control address is valid for the device.
 *
 * int (*ndo_do_ioctl)(struct net_device *dev, struct ifreq *ifr, int cmd);
 *	Called when a user request an ioctl which can't be handled by
 *	the generic interface code. If not defined ioctl's return
 *	not supported error code.
 *
 * int (*ndo_set_config)(struct net_device *dev, struct ifmap *map);
 *	Used to set network devices bus interface parameters. This interface
 *	is retained for legacy reason, new devices should use the bus
 *	interface (PCI) for low level management.
 *
 * int (*ndo_change_mtu)(struct net_device *dev, int new_mtu);
 *	Called when a user wants to change the Maximum Transfer Unit
 *	of a device. If not defined, any request to change MTU will
 *	will return an error.
 *
 * void (*ndo_tx_timeout)(struct net_device *dev);
 *	Callback uses when the transmitter has not made any progress
 *	for dev->watchdog ticks.
 *
 * struct rtnl_link_stats64* (*ndo_get_stats64)(struct net_device *dev,
 * 			struct rtnl_link_stats64 *storage);
 * struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);
 *	Called when a user wants to get the network device usage
 *	statistics. Drivers must do one of the following:
 *	1. Define @ndo_get_stats64 to fill in a zero-initialised
 *	   rtnl_link_stats64 structure passed by the caller.
 *	2. Define @ndo_get_stats to update a net_device_stats64 structure
 *	   (which should normally be dev->stats) and return a pointer to
 *	   it. The structure may be changed asynchronously only if each
 *	   field is written atomically.
 *	3. Update dev->stats asynchronously and atomically, and define
 *	   neither operation.
 *
 * void (*ndo_vlan_rx_register)(struct net_device *dev, struct vlan_group *grp);
 *	If device support VLAN receive accleration
 *	(ie. dev->features & NETIF_F_HW_VLAN_RX), then this function is called
 *	when vlan groups for the device changes.  Note: grp is NULL
 *	if no vlan's groups are being used.
 *
 * void (*ndo_vlan_rx_add_vid)(struct net_device *dev, unsigned short vid);
 *	If device support VLAN filtering (dev->features & NETIF_F_HW_VLAN_FILTER)
 *	this function is called when a VLAN id is registered.
 *
 * void (*ndo_vlan_rx_kill_vid)(struct net_device *dev, unsigned short vid);
 *	If device support VLAN filtering (dev->features & NETIF_F_HW_VLAN_FILTER)
 *	this function is called when a VLAN id is unregistered.
 *
 * void (*ndo_poll_controller)(struct net_device *dev);
 *
 *	SR-IOV management functions.
 * int (*ndo_set_vf_mac)(struct net_device *dev, int vf, u8* mac);
 * int (*ndo_set_vf_vlan)(struct net_device *dev, int vf, u16 vlan, u8 qos);
 * int (*ndo_set_vf_tx_rate)(struct net_device *dev, int vf, int rate);
 * int (*ndo_set_vf_spoofchk)(struct net_device *dev, int vf, bool setting);
 * int (*ndo_get_vf_config)(struct net_device *dev,
 *			    int vf, struct ifla_vf_info *ivf);
 * int (*ndo_set_vf_link_state)(struct net_device *dev, int vf, int link_state);
 * int (*ndo_set_vf_port)(struct net_device *dev, int vf,
 *			  struct nlattr *port[]);
 * int (*ndo_get_vf_port)(struct net_device *dev, int vf, struct sk_buff *skb);
 *
 * int (*ndo_fdb_add)(struct ndmsg *ndm, struct nlattr *tb[],
 *		      struct net_device *dev,
 *		      const unsigned char *addr, u16 flags)
 *	Adds an FDB entry to dev for addr.
 * int (*ndo_fdb_del)(struct ndmsg *ndm, struct nlattr *tb[],
 *		      struct net_device *dev,
 *		      const unsigned char *addr)
 *	Deletes the FDB entry from dev coresponding to addr.
 * int (*ndo_fdb_dump)(struct sk_buff *skb, struct netlink_callback *cb,
 *		       struct net_device *dev, int idx)
 *	Used to add FDB entries to dump requests. Implementers should add
 *	entries to skb and update idx with the number of entries.
 *
 *      Feature/offload setting functions.
 * u32 (*ndo_fix_features)(struct net_device *dev, u32 features);
 *	Adjusts the requested feature flags according to device-specific
 *	constraints, and returns the resulting flags. Must not modify
 *	the device state.
 *
 * int (*ndo_set_features)(struct net_device *dev, u32 features);
 *	Called to update device configuration to new features. Passed
 *	feature set might be less than what was returned by ndo_fix_features()).
 *	Must return >0 or -errno if it changed dev->features itself.
 *
 * int (*ndo_get_phys_port_id)(struct net_device *dev,
 *			       struct netdev_phys_port_id *ppid);
 *	Called to get ID of physical port of this device. If driver does
 *	not implement this, it is assumed that the hw is not able to have
 *	multiple net devices on single physical port.
 */
#define HAVE_NET_DEVICE_OPS
struct net_device_ops {
	int			(*ndo_init)(struct net_device *dev);
	void			(*ndo_uninit)(struct net_device *dev);
	int			(*ndo_open)(struct net_device *dev);
	int			(*ndo_stop)(struct net_device *dev);
	netdev_tx_t		(*ndo_start_xmit) (struct sk_buff *skb,
						   struct net_device *dev);
	u16			(*ndo_select_queue)(struct net_device *dev,
						    struct sk_buff *skb);
#define HAVE_CHANGE_RX_FLAGS
	void			(*ndo_change_rx_flags)(struct net_device *dev,
						       int flags);
#define HAVE_SET_RX_MODE
	void			(*ndo_set_rx_mode)(struct net_device *dev);
#define HAVE_MULTICAST
	void			(*ndo_set_multicast_list)(struct net_device *dev);
#define HAVE_SET_MAC_ADDR
	int			(*ndo_set_mac_address)(struct net_device *dev,
						       void *addr);
#define HAVE_VALIDATE_ADDR
	int			(*ndo_validate_addr)(struct net_device *dev);
#define HAVE_PRIVATE_IOCTL
	int			(*ndo_do_ioctl)(struct net_device *dev,
					        struct ifreq *ifr, int cmd);
#define HAVE_SET_CONFIG
	int			(*ndo_set_config)(struct net_device *dev,
					          struct ifmap *map);
#define HAVE_CHANGE_MTU
	int			(*ndo_change_mtu)(struct net_device *dev,
						  int new_mtu);
	int			(*ndo_neigh_setup)(struct net_device *dev,
						   struct neigh_parms *);
#define HAVE_TX_TIMEOUT
	void			(*ndo_tx_timeout) (struct net_device *dev);

	struct net_device_stats* (*ndo_get_stats)(struct net_device *dev);

	void			(*ndo_vlan_rx_register)(struct net_device *dev,
						        struct vlan_group *grp);
	void			(*ndo_vlan_rx_add_vid)(struct net_device *dev,
						       unsigned short vid);
	void			(*ndo_vlan_rx_kill_vid)(struct net_device *dev,
						        unsigned short vid);
#ifdef CONFIG_NET_POLL_CONTROLLER
#define HAVE_NETDEV_POLL
	void                    (*ndo_poll_controller)(struct net_device *dev);
	void			(*ndo_netpoll_cleanup)(struct net_device *dev);
#endif
	int			(*ndo_set_vf_mac)(struct net_device *dev,
						  int queue, u8 *mac);
	int			(*ndo_set_vf_vlan)(struct net_device *dev,
						   int queue, u16 vlan, u8 qos);
	int			(*ndo_set_vf_tx_rate)(struct net_device *dev,
						      int vf, int rate);
	int			(*ndo_get_vf_config)(struct net_device *dev,
						     int vf,
						     struct ifla_vf_info *ivf);
	int			(*ndo_set_vf_port)(struct net_device *dev,
						   int vf,
						   struct nlattr *port[]);
	int			(*ndo_get_vf_port)(struct net_device *dev,
						   int vf, struct sk_buff *skb);
#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
	int			(*ndo_fcoe_enable)(struct net_device *dev);
	int			(*ndo_fcoe_disable)(struct net_device *dev);
	int			(*ndo_fcoe_ddp_setup)(struct net_device *dev,
						      u16 xid,
						      struct scatterlist *sgl,
						      unsigned int sgc);
	int			(*ndo_fcoe_ddp_done)(struct net_device *dev,
						     u16 xid);
#define NETDEV_FCOE_WWNN 0
#define NETDEV_FCOE_WWPN 1
	int			(*ndo_fcoe_get_wwn)(struct net_device *dev,
						    u64 *wwn, int type);
#endif
};

/**
 * struct net_device_ops_ext - structure for extending net_device_ops in RHEL
 *
 * New methods can be added at the end. Do not change existing ones.
 *
 * @size: This field should be initialized to the size of the structure
 *	  by the drivers.
 */
struct net_device_ops_ext {
	size_t			size;
	u32			(*ndo_fix_features)(struct net_device *dev,
						    u32 features);
	int			(*ndo_set_features)(struct net_device *dev,
						    u32 features);
	int			(*ndo_get_phys_port_id)(struct net_device *dev,
							struct netdev_phys_port_id *ppid);
	struct rtnl_link_stats64* (*ndo_get_stats64)(struct net_device *dev,
						     struct rtnl_link_stats64 *storage);
	int			(*ndo_set_vf_spoofchk)(struct net_device *dev,
						       int vf, bool setting);
	int			(*ndo_set_vf_link_state)(struct net_device *dev,
							 int vf, int link_state);
};

typedef u64 netdev_features_t;

/*
 *	The DEVICE structure.
 *	Actually, this whole structure is a big mistake.  It mixes I/O
 *	data with strictly "high-level" data, and it has to know about
 *	almost every data structure used in the INET module.
 *
 *	FIXME: cleanup struct net_device such that network protocol info
 *	moves out.
 */

struct net_device
{

	/*
	 * This is the first field of the "visible" part of this structure
	 * (i.e. as seen by users in the "Space.c" file).  It is the name
	 * the interface.
	 */
	char			name[IFNAMSIZ];
	/* device name hash chain */
	struct hlist_node	name_hlist;
	/* snmp alias */
	char 			*ifalias;

	/*
	 *	I/O specific fields
	 *	FIXME: Merge these and struct ifmap into one
	 */
	unsigned long		mem_end;	/* shared mem end	*/
	unsigned long		mem_start;	/* shared mem start	*/
	unsigned long		base_addr;	/* device I/O address	*/
	unsigned int		irq;		/* device IRQ number	*/

	/*
	 *	Some hardware also needs these fields, but they are not
	 *	part of the usual set specified in Space.c.
	 */

	unsigned char		if_port;	/* Selectable AUI, TP,..*/
	unsigned char		dma;		/* DMA channel		*/

	unsigned long		state;

	struct list_head	dev_list;
	struct list_head	napi_list;

	/* currently active device features */
	unsigned long		features;

	/* Net device feature bits; if you change something,
	 * also update netdev_features_strings[] in ethtool.c */

#define NETIF_F_SG		1	/* Scatter/gather IO. */
#define NETIF_F_IP_CSUM		2	/* Can checksum TCP/UDP over IPv4. */
#define NETIF_F_NO_CSUM		4	/* Does not require checksum. F.e. loopack. */
#define NETIF_F_HW_CSUM		8	/* Can checksum all the packets. */
#define NETIF_F_IPV6_CSUM	16	/* Can checksum TCP/UDP over IPV6 */
#define NETIF_F_HIGHDMA		32	/* Can DMA to high memory. */
#define NETIF_F_FRAGLIST	64	/* Scatter/gather IO. */
#define NETIF_F_HW_VLAN_TX	128	/* Transmit VLAN hw acceleration */
#define NETIF_F_HW_VLAN_RX	256	/* Receive VLAN hw acceleration */
#define NETIF_F_HW_VLAN_FILTER	512	/* Receive filtering on VLAN */
#define NETIF_F_VLAN_CHALLENGED	1024	/* Device cannot handle VLAN packets */
#define NETIF_F_GSO		2048	/* Enable software GSO. */
#define NETIF_F_LLTX		4096	/* LockLess TX - deprecated. Please */
					/* do not use LLTX in new drivers */
#define NETIF_F_NETNS_LOCAL	8192	/* Does not change network namespaces */
#define NETIF_F_GRO		16384	/* Generic receive offload */
#define NETIF_F_LRO		32768	/* large receive offload */

/* the GSO_MASK reserves bits 16 through 23 */
#define NETIF_F_FCOE_CRC	(1 << 24) /* FCoE CRC32 */
#define NETIF_F_SCTP_CSUM	(1 << 25) /* SCTP checksum offload */
#define NETIF_F_FCOE_MTU	(1 << 26) /* Supports max FCoE MTU, 2158 bytes*/
#define NETIF_F_NTUPLE		(1 << 27) /* N-tuple filters supported */
#define NETIF_F_RXHASH		(1 << 28) /* Receive hashing offload */
#define NETIF_F_RXCSUM		(1 << 29) /* Receive checksumming offload */
#define NETIF_F_LOOPBACK	(1 << 31) /* Enable loopback */

	/* Segmentation offload features */
#define NETIF_F_GSO_SHIFT	16
#define NETIF_F_GSO_MASK	0x00ff0000
#define NETIF_F_TSO		(SKB_GSO_TCPV4 << NETIF_F_GSO_SHIFT)
#define NETIF_F_UFO		(SKB_GSO_UDP << NETIF_F_GSO_SHIFT)
#define NETIF_F_GSO_ROBUST	(SKB_GSO_DODGY << NETIF_F_GSO_SHIFT)
#define NETIF_F_TSO_ECN		(SKB_GSO_TCP_ECN << NETIF_F_GSO_SHIFT)
#define NETIF_F_TSO6		(SKB_GSO_TCPV6 << NETIF_F_GSO_SHIFT)
#define NETIF_F_FSO		(SKB_GSO_FCOE << NETIF_F_GSO_SHIFT)
#define NETIF_F_GSO_GRE		(SKB_GSO_GRE << NETIF_F_GSO_SHIFT)
#define NETIF_F_GSO_UDP_TUNNEL	(SKB_GSO_UDP_TUNNEL << NETIF_F_GSO_SHIFT)

	/* Features valid for ethtool to change */
	/* = all defined minus driver/device-class-related */
#define NETIF_F_NEVER_CHANGE	(NETIF_F_VLAN_CHALLENGED | \
				  NETIF_F_LLTX | NETIF_F_NETNS_LOCAL)
#define NETIF_F_ETHTOOL_BITS	(0xbf3fffff & ~NETIF_F_NEVER_CHANGE)

	/* List of features with software fallbacks. */
#define NETIF_F_GSO_SOFTWARE	(NETIF_F_TSO | NETIF_F_TSO_ECN | \
				 NETIF_F_TSO6 | NETIF_F_UFO)


#define NETIF_F_GEN_CSUM	(NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)
#define NETIF_F_V4_CSUM		(NETIF_F_GEN_CSUM | NETIF_F_IP_CSUM)
#define NETIF_F_V6_CSUM		(NETIF_F_GEN_CSUM | NETIF_F_IPV6_CSUM)
#define NETIF_F_ALL_CSUM	(NETIF_F_V4_CSUM | NETIF_F_V6_CSUM)

#define NETIF_F_ALL_TSO 	(NETIF_F_TSO | NETIF_F_TSO6 | NETIF_F_TSO_ECN)

#define NETIF_F_ALL_FCOE	(NETIF_F_FCOE_CRC | NETIF_F_FCOE_MTU | \
				 NETIF_F_FSO)

	/*
	 * If one device supports one of these features, then enable them
	 * for all in netdev_increment_features.
	 */
#define NETIF_F_ONE_FOR_ALL	(NETIF_F_GSO_SOFTWARE | NETIF_F_GSO_ROBUST | \
				 NETIF_F_SG | NETIF_F_HIGHDMA |		\
				 NETIF_F_FRAGLIST | NETIF_F_VLAN_CHALLENGED)
	/*
	 * If one device doesn't support one of these features, then disable it
	 * for all in netdev_increment_features.
	 */
#define NETIF_F_ALL_FOR_ALL	(NETIF_F_FSO)

	/* changeable features with no special hardware requirements */
#define NETIF_F_SOFT_FEATURES	(NETIF_F_GSO | NETIF_F_GRO)

	/* Interface index. Unique device identifier	*/
	int			ifindex;
	int			iflink;

	struct net_device_stats	stats;

#ifdef CONFIG_WIRELESS_EXT
	/* List of functions to handle Wireless Extensions (instead of ioctl).
	 * See <net/iw_handler.h> for details. Jean II */
	const struct iw_handler_def *	wireless_handlers;
	/* Instance data managed by the core of Wireless Extensions. */
	struct iw_public_data *	wireless_data;
#endif
	/* Management operations */
	const struct net_device_ops *netdev_ops;
	const struct ethtool_ops *ethtool_ops;

	/* Hardware header description */
	const struct header_ops *header_ops;

	unsigned int		flags;	/* interface flags (a la BSD)	*/
	unsigned short		gflags;
        unsigned short          priv_flags; /* Like 'flags' but invisible to userspace. */
	unsigned short		padded;	/* How much padding added by alloc_netdev() */

	unsigned char		operstate; /* RFC2863 operstate */
	unsigned char		link_mode; /* mapping policy to operstate */

	unsigned		mtu;	/* interface MTU value		*/
	unsigned short		type;	/* interface hardware type	*/
	unsigned short		hard_header_len;	/* hardware hdr length	*/

	/* extra head- and tailroom the hardware may need, but not in all cases
	 * can this be guaranteed, especially tailroom. Some cases also use
	 * LL_MAX_HEADER instead to allocate the skb.
	 */
	unsigned short		needed_headroom;
	unsigned short		needed_tailroom;

	struct net_device	*master; /* Pointer to master device of a group,
					  * which this device is member of.
					  */

	/* Interface address info. */
	unsigned char		perm_addr[MAX_ADDR_LEN]; /* permanent hw address */
	unsigned char		addr_assign_type; /* hw address assignment type */
	unsigned char		addr_len;	/* hardware address length	*/
	unsigned short          dev_id;		/* for shared network cards */

	struct netdev_hw_addr_list	uc;	/* Secondary unicast
						   mac addresses */
	int			uc_promisc;
	spinlock_t		addr_list_lock;
	struct dev_addr_list	*mc_list;	/* Multicast mac addresses	*/
	int			mc_count;	/* Number of installed mcasts	*/
	unsigned int		promiscuity;
	unsigned int		allmulti;


	/* Protocol specific pointers */

#ifdef CONFIG_NET_DSA
	void			*dsa_ptr;	/* dsa specific data */
#endif
	void 			*atalk_ptr;	/* AppleTalk link 	*/
	void			*ip_ptr;	/* IPv4 specific data	*/
	void                    *dn_ptr;        /* DECnet specific data */
	void                    *ip6_ptr;       /* IPv6 specific data */
	void			*ec_ptr;	/* Econet specific data	*/
	void			*ax25_ptr;	/* AX.25 specific data
						   also used by openvswitch */
	struct wireless_dev	*ieee80211_ptr;	/* IEEE 802.11 specific data,
						   assign before registering */

/*
 * Cache line mostly used on receive path (including eth_type_trans())
 */
	unsigned long		last_rx;	/* Time of last Rx */

	/* Interface address info used in eth_type_trans() */
	unsigned char		*dev_addr;	/* hw address, (before bcast
						   because most packets are
						   unicast) */

	struct netdev_hw_addr_list	dev_addrs; /* list of device
						      hw addresses */

	unsigned char		broadcast[MAX_ADDR_LEN];	/* hw bcast add	*/

	struct netdev_queue	rx_queue;

	struct netdev_queue	*_tx ____cacheline_aligned_in_smp;

	/* Number of TX queues allocated at alloc_netdev_mq() time  */
	unsigned int		num_tx_queues;

	/* Number of TX queues currently active in device  */
	unsigned int		real_num_tx_queues;

	/* root qdisc from userspace point of view */
	struct Qdisc		*qdisc;

	unsigned long		tx_queue_len;	/* Max frames per queue allowed */
	spinlock_t		tx_global_lock;
/*
 * One part is mostly used on xmit path (device)
 */
	/* These may be needed for future network-power-down code. */

	/*
	 * trans_start here is expensive for high speed devices on SMP,
	 * please use netdev_queue->trans_start instead.
	 */
	unsigned long		trans_start;	/* Time (in jiffies) of last Tx	*/

	int			watchdog_timeo; /* used by dev_watchdog() */
	struct timer_list	watchdog_timer;

	/* Number of references to this device */
	atomic_t		refcnt ____cacheline_aligned_in_smp;

	/* delayed register/unregister */
	struct list_head	todo_list;
	/* device index hash chain */
	struct hlist_node	index_hlist;

	struct net_device	*link_watch_next;

	/* register/unregister state machine */
	enum { NETREG_UNINITIALIZED=0,
	       NETREG_REGISTERED,	/* completed register_netdevice */
	       NETREG_UNREGISTERING,	/* called unregister_netdevice */
	       NETREG_UNREGISTERED,	/* completed unregister todo */
	       NETREG_RELEASED,		/* called free_netdev */
	       NETREG_DUMMY,		/* dummy device for NAPI poll */
	} reg_state;

	/* Called from unregister, can be used to call free_netdev */
	void (*destructor)(struct net_device *dev);

#ifdef CONFIG_NETPOLL
	struct netpoll_info	*npinfo;
#endif

#ifdef CONFIG_NET_NS
	/* Network namespace this network device is inside */
	struct net		*nd_net;
#endif

	/* mid-layer private */
	void			*ml_priv;

	/* bridge stuff */
	struct net_bridge_port	*br_port;
	/* macvlan */
	struct macvlan_port	*macvlan_port;
	/* GARP */
	struct garp_port	*garp_port;

	/* class/net/name entry */
	struct device		dev;
	/* space for optional statistics and wireless sysfs groups */
	const struct attribute_group *sysfs_groups[3];

	/* rtnetlink link ops */
	const struct rtnl_link_ops *rtnl_link_ops;

	/* VLAN feature mask */
	unsigned long vlan_features;

	/* for setting kernel sock attribute on TCP connection setup */
#define GSO_MAX_SIZE		65536
	unsigned int		gso_max_size;

#ifdef CONFIG_DCB
	/* Data Center Bridging netlink ops */
	const struct dcbnl_rtnl_ops *dcbnl_ops;
#endif

#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
	/* max exchange id for FCoE LRO by ddp */
	unsigned int		fcoe_ddp_xid;
#endif
};
#define to_net_dev(d) container_of(d, struct net_device, dev)

#define	NETDEV_ALIGN		32
#define NET_DEVICE_SIZE \
	ALIGN(sizeof(struct net_device), NETDEV_ALIGN)

/*
 * To prevent KABI-breakage, few structs are added to extend the original
 * struct net_device. Also few helpers are added:
 * netdev_extended_frozen_get_dev
 *     - used to get pointer to net_device from frozen extend pointer
 * netdev_extended_frozen-
 *     - should be used to access items in struct net_device_extended_frozen
 * netdev_extended
 *     - should be used to access items in struct net_device_extended
 *
 * Structures are supposed to be located in memory in following way:
 * struct net_device_extended_frozen - for storing pointer to extension
 * struct net_device - original struct
 * driver priv
 * struct net_device_extended - extend to store additional values.
 */

struct netdev_tx_queue_extended {
	struct netdev_queue	*q;
	struct kobject		kobj;
};

struct netdev_rps_info {
	struct kset	*queues_kset;
	struct netdev_rx_queue	*_rx;
	/* Number of RX queues allocated at alloc_netdev_mq() time  */
	unsigned int	num_rx_queues;
};

struct netdev_rfs_info {
#ifdef CONFIG_RFS_ACCEL
	/* CPU reverse-mapping for RX completion interrupts, indexed
	 * by RX queue number.  Assigned by driver.  This must only be
	 * set if the ndo_rx_flow_steer operation is defined.
	 */
	struct cpu_rmap		*rx_cpu_rmap;
	/* RFS acceleration.
	 * int (*ndo_rx_flow_steer)(struct net_device *dev,
	 * 			    const struct sk_buff *skb,
	 *			    u16 rxq_index, u32 flow_id);
	 * Set hardware filter for RFS.  rxq_index is the target queue index;
	 * flow_id is a flow ID to be passed to rps_may_expire_flow() later.
	 * Return the filter ID on success, or a negative error code.
	 */
	int			(*ndo_rx_flow_steer)(struct net_device *dev,
						     const struct sk_buff *skb,
						     u16 rxq_index,
						     u32 flow_id);
#endif
};

struct netdev_qos_info {
	u8 num_tc;
	struct netdev_tc_txq tc_to_txq[TC_MAX_QUEUE];
	u8 prio_tc_map[TC_BITMASK + 1];
};

struct netdev_netpoll_ext_info {
	int			(*ndo_netpoll_setup)(struct net_device *dev,
						     struct netpoll_info *info,
						     gfp_t gfp);
};

struct netdev_priomap_info {
#ifdef CONFIG_NETPRIO_CGROUP
	struct netprio_map *priomap;
#endif
};

/* Only append, do not change existing! */
struct net_device_extended {
	struct xps_dev_maps			*xps_maps;
	struct netdev_tx_queue_extended		*_tx_ext;
	struct netdev_rps_info			rps_data;
	struct netdev_qos_info			qos_data;
	unsigned long				ext_priv_flags;
	struct netdev_priomap_info		priomap_data;
#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
	int                     (*ndo_fcoe_get_hbainfo)(struct net_device *dev,
					struct netdev_fcoe_hbainfo *hbainfo);
#endif
	struct netdev_netpoll_ext_info		netpoll_data;
	unsigned int				real_num_rx_queues;
	const struct ethtool_ops_ext		*ethtool_ops_ext;
#if defined(CONFIG_FCOE) || defined(CONFIG_FCOE_MODULE)
	int			(*ndo_fcoe_ddp_target)(struct net_device *dev,
					u16 xid,
					struct scatterlist *sgl,
					unsigned int sgc);
#endif
	int			(*ndo_fdb_add)(struct ndmsg *ndm,
					       struct nlattr *tb[],
					       struct net_device *dev,
					       const unsigned char *addr,
					       u16 flags);
	int			(*ndo_fdb_del)(struct ndmsg *ndm,
					       struct nlattr *tb[],
					       struct net_device *dev,
					       const unsigned char *addr);
	int			(*ndo_fdb_dump)(struct sk_buff *skb,
						struct netlink_callback *cb,
						struct net_device *dev,
						int idx);
	struct list_head			unreg_list;
	struct net_device			*dev;
	struct net				*src_net;
	struct netdev_rfs_info			rfs_data;
#define GSO_MAX_SEGS		65535
	u16			gso_max_segs;
#ifdef CONFIG_NET_RX_BUSY_POLL
	int			(*ndo_busy_poll)(struct napi_struct *dev);
#endif
	const struct net_device_ops_ext		*netdev_ops_ext;
	/* user-changeable features */
	u32			hw_features;
	/* user-requested features */
	u32			wanted_features;
#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
	struct vlan_group	*vlgrp;		/* VLAN group */
#endif
	rx_handler_func_t	*rx_handler;
	void			*rx_handler_data;
	/* space for optional device, statistics, and wireless sysfs groups */
	const struct attribute_group *sysfs_groups[6];
	unsigned short          dev_port;	/* Used to differentiate
						 * devices that share the same
						 * function
						 */
	unsigned long		gro_flush_timeout;
	unsigned char		name_assign_type;
};

#define NET_DEVICE_EXTENDED_SIZE \
	ALIGN(sizeof(struct net_device_extended), NETDEV_ALIGN)

/* Do not add anything here! */
struct net_device_extended_frozen {
	struct net_device_extended *dev_ext; /* Pointer to net_device extension */
};

#define NET_DEVICE_EXTENDED_FROZEN_SIZE \
	ALIGN(sizeof(struct net_device_extended_frozen), NETDEV_ALIGN)

static inline struct net_device *
netdev_extended_frozen_get_dev(const struct net_device_extended_frozen *dev_ext_frozen)
{
	return (struct net_device *)
			(((char *) dev_ext_frozen) +
			 NET_DEVICE_EXTENDED_FROZEN_SIZE);
}

static inline struct net_device_extended_frozen *
netdev_extended_frozen(const struct net_device *dev)
{
	return (struct net_device_extended_frozen *)
			(((char *) dev) - NET_DEVICE_EXTENDED_FROZEN_SIZE);
}

static inline struct net_device_extended *
netdev_extended(const struct net_device *dev)
{
	return netdev_extended_frozen(dev)->dev_ext;
}

extern void set_netdev_hw_features(struct net_device *, u32);
extern u32  get_netdev_hw_features(struct net_device *);

extern void set_netdev_ops_ext(struct net_device *, const struct net_device_ops_ext *);
extern const struct net_device_ops_ext *get_netdev_ops_ext(const struct net_device *);

#define GET_NETDEV_OP_EXT(dev, op) \
	({ const struct net_device_ops_ext *ops = get_netdev_ops_ext(dev); \
	   ops && (offsetof(struct net_device_ops_ext, op) < ops->size) ? \
	   ops->op : NULL; })

extern void set_ethtool_ops_ext(struct net_device *, const struct ethtool_ops_ext *);
extern const struct ethtool_ops_ext *get_ethtool_ops_ext(const struct net_device *);

#define GET_ETHTOOL_OP_EXT(net, op) \
	({ const struct ethtool_ops_ext *ops = get_ethtool_ops_ext(net); \
	   ops && (offsetof(struct ethtool_ops_ext, op) < ops->size) ? \
	   ops->op : NULL; })

static inline
int netdev_get_prio_tc_map(const struct net_device *dev, u32 prio)
{
	return netdev_extended(dev)->qos_data.prio_tc_map[prio & TC_BITMASK];
}

static inline
int netdev_set_prio_tc_map(struct net_device *dev, u8 prio, u8 tc)
{
	struct netdev_qos_info *qos = &netdev_extended(dev)->qos_data;
	if (tc >= qos->num_tc)
		return -EINVAL;

	qos->prio_tc_map[prio & TC_BITMASK] = tc & TC_BITMASK;
	return 0;
}

static inline
void netdev_reset_tc(struct net_device *dev)
{
	struct netdev_qos_info *qos = &netdev_extended(dev)->qos_data;
	qos->num_tc = 0;
	memset(qos->tc_to_txq, 0, sizeof(qos->tc_to_txq));
	memset(qos->prio_tc_map, 0, sizeof(qos->prio_tc_map));
}

static inline
int netdev_set_tc_queue(struct net_device *dev, u8 tc, u16 count, u16 offset)
{
	struct netdev_qos_info *qos = &netdev_extended(dev)->qos_data;
	if (tc >= qos->num_tc)
		return -EINVAL;

	qos->tc_to_txq[tc].count = count;
	qos->tc_to_txq[tc].offset = offset;
	return 0;
}

static inline
int netdev_set_num_tc(struct net_device *dev, u8 num_tc)
{
	if (num_tc > TC_MAX_QUEUE)
		return -EINVAL;

	netdev_extended(dev)->qos_data.num_tc = num_tc;
	return 0;
}

static inline
int netdev_get_num_tc(struct net_device *dev)
{
	return netdev_extended(dev)->qos_data.num_tc;
}

static inline
struct netdev_queue *netdev_get_tx_queue(const struct net_device *dev,
					 unsigned int index)
{
	return &dev->_tx[index];
}

static inline void netdev_for_each_tx_queue(struct net_device *dev,
					    void (*f)(struct net_device *,
						      struct netdev_queue *,
						      void *),
					    void *arg)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++)
		f(dev, &dev->_tx[i], arg);
}

extern struct netdev_queue *netdev_pick_tx(struct net_device *dev,
					   struct sk_buff *skb);
extern u16 __netdev_pick_tx(struct net_device *dev, struct sk_buff *skb);

/*
 * Net namespace inlines
 */
static inline
struct net *dev_net(const struct net_device *dev)
{
#ifdef CONFIG_NET_NS
	return dev->nd_net;
#else
	return &init_net;
#endif
}

static inline
void dev_net_set(struct net_device *dev, struct net *net)
{
#ifdef CONFIG_NET_NS
	release_net(dev->nd_net);
	dev->nd_net = hold_net(net);
#endif
}

static inline bool netdev_uses_dsa_tags(struct net_device *dev)
{
#ifdef CONFIG_NET_DSA_TAG_DSA
	if (dev->dsa_ptr != NULL)
		return dsa_uses_dsa_tags(dev->dsa_ptr);
#endif

	return 0;
}

static inline bool netdev_uses_trailer_tags(struct net_device *dev)
{
#ifdef CONFIG_NET_DSA_TAG_TRAILER
	if (dev->dsa_ptr != NULL)
		return dsa_uses_trailer_tags(dev->dsa_ptr);
#endif

	return 0;
}

/**
 *	netdev_priv - access network device private data
 *	@dev: network device
 *
 * Get network device private data
 */
static inline void *netdev_priv(const struct net_device *dev)
{
	return (char *)dev + ALIGN(sizeof(struct net_device), NETDEV_ALIGN);
}

/* Set the sysfs physical device reference for the network logical device
 * if set prior to registration will cause a symlink during initialization.
 */
#define SET_NETDEV_DEV(net, pdev)	((net)->dev.parent = (pdev))

/* Set the sysfs device type for the network logical device to allow
 * fin grained indentification of different network device types. For
 * example Ethernet, Wirelss LAN, Bluetooth, WiMAX etc.
 */
#define SET_NETDEV_DEVTYPE(net, devtype)	((net)->dev.type = (devtype))

/* Default NAPI poll() weight
 * Device drivers are strongly advised to not use bigger value
 */
#define NAPI_POLL_WEIGHT 64

void __netif_napi_add(struct net_device *dev, struct napi_struct *napi,
		      int (*poll)(struct napi_struct *, int), int weight,
		      size_t size);

/**
 *	netif_napi_add - initialize a napi context
 *	@dev:  network device
 *	@napi: napi context
 *	@poll: polling function
 *	@weight: default weight
 *
 * netif_napi_add() must be used to initialize a napi context prior to calling
 * *any* of the other napi related functions.
 */
static inline void _netif_napi_add(struct net_device *dev,
				   struct napi_struct *napi,
				   int (*poll)(struct napi_struct *, int),
				   int weight)
{
	__netif_napi_add(dev, napi, poll, weight, sizeof(struct napi_struct));
}

/* RHEL has netif_napi_add in KABI so we need to keep it for binary
 * modules. Another reason is that older binary modules uses non-extended
 * napi_struct. Newly compiled modules will use inlined function that uses
 * current (extended) napi_struct. */
void netif_napi_add(struct net_device *dev, struct napi_struct *napi,
		    int (*poll)(struct napi_struct *, int), int weight);
#define netif_napi_add _netif_napi_add

/**
 *  netif_napi_del - remove a napi context
 *  @napi: napi context
 *
 *  netif_napi_del() removes a napi context from the network device napi list
 */
void netif_napi_del(struct napi_struct *napi);

struct napi_gro_cb {
	/* Virtual address of skb_shinfo(skb)->frags[0].page + offset. */
	void *frag0;

	/* Length of frag0. */
	unsigned int frag0_len;

	/* This indicates where we are processing relative to skb->data. */
	int data_offset;

	/* This is non-zero if the packet cannot be merged with the new skb. */
	int flush;

	/* Number of segments aggregated. */
	u16	count;

	/* This is non-zero if the packet may be of the same flow. */
	u8	same_flow;

	/* Free the skb? */
	u8	free;

	/* jiffies when first packet was created/queued */
	unsigned long age;

	/* used in skb_gro_receive() slow path */
	struct sk_buff *last;
};

#define NAPI_GRO_CB(skb) ((struct napi_gro_cb *)(skb)->cb)

struct packet_type {
	__be16			type;	/* This is really htons(ether_type). */
	struct net_device	*dev;	/* NULL is wildcarded here	     */
	int			(*func) (struct sk_buff *,
					 struct net_device *,
					 struct packet_type *,
					 struct net_device *);
	struct sk_buff		*(*gso_segment)(struct sk_buff *skb,
						int features);
	int			(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff		**(*gro_receive)(struct sk_buff **head,
					       struct sk_buff *skb);
	int			(*gro_complete)(struct sk_buff *skb);
	void			*af_packet_priv;
	struct list_head	list;
};

struct packet_offload {
	__be16			type;	/* This is really htons(ether_type). */
	struct sk_buff		*(*gso_segment)(struct sk_buff *skb,
						int features);
	int			(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff		**(*gro_receive)(struct sk_buff **head,
					       struct sk_buff *skb);
	int			(*gro_complete)(struct sk_buff *skb);
	struct list_head	list;
};

#include <linux/interrupt.h>
#include <linux/notifier.h>

extern rwlock_t				dev_base_lock;		/* Device list lock */


#define for_each_netdev(net, d)		\
		list_for_each_entry(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_safe(net, d, n)	\
		list_for_each_entry_safe(d, n, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue(net, d)		\
		list_for_each_entry_continue(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_continue_rcu(net, d)		\
	list_for_each_entry_continue_rcu(d, &(net)->dev_base_head, dev_list)
#define for_each_netdev_in_bond(bond, slave)		\
		for_each_netdev(&init_net, slave)	\
			if (slave->master == bond)

#define net_device_entry(lh)	list_entry(lh, struct net_device, dev_list)

static inline struct net_device *next_net_device(struct net_device *dev)
{
	struct list_head *lh;
	struct net *net;

	net = dev_net(dev);
	lh = dev->dev_list.next;
	return lh == &net->dev_base_head ? NULL : net_device_entry(lh);
}

static inline struct net_device *first_net_device(struct net *net)
{
	return list_empty(&net->dev_base_head) ? NULL :
		net_device_entry(net->dev_base_head.next);
}

extern int 			netdev_boot_setup_check(struct net_device *dev);
extern unsigned long		netdev_boot_base(const char *prefix, int unit);
extern struct net_device    *dev_getbyhwaddr(struct net *net, unsigned short type, char *hwaddr);
extern struct net_device *dev_getfirstbyhwtype(struct net *net, unsigned short type);
extern struct net_device *__dev_getfirstbyhwtype(struct net *net, unsigned short type);
extern void		dev_add_pack(struct packet_type *pt);
extern void		dev_remove_pack(struct packet_type *pt);
extern void		__dev_remove_pack(struct packet_type *pt);
extern void		dev_add_offload(struct packet_offload *po);
extern void		dev_remove_offload(struct packet_offload *po);
extern void		__dev_remove_offload(struct packet_offload *po);

extern struct net_device	*dev_get_by_flags(struct net *net, unsigned short flags,
						  unsigned short mask);
extern struct net_device	*dev_get_by_name(struct net *net, const char *name);
extern struct net_device	*__dev_get_by_name(struct net *net, const char *name);
extern int		dev_alloc_name(struct net_device *dev, const char *name);
extern int		dev_open(struct net_device *dev);
extern int		dev_close(struct net_device *dev);
extern void		dev_disable_lro(struct net_device *dev);
extern int		dev_queue_xmit(struct sk_buff *skb);
extern int		register_netdevice(struct net_device *dev);
extern void		unregister_netdevice(struct net_device *dev);
extern void		unregister_netdevice_queue(struct net_device *dev,
						   struct list_head *head);
extern void		unregister_netdevice_many(struct list_head *head);
extern void		free_netdev(struct net_device *dev);
extern void		synchronize_net(void);
extern int 		register_netdevice_notifier(struct notifier_block *nb);
extern int		unregister_netdevice_notifier(struct notifier_block *nb);
extern int		init_dummy_netdev(struct net_device *dev);
extern void		netdev_resync_ops(struct net_device *dev);

extern int call_netdevice_notifiers(unsigned long val, struct net_device *dev);
extern struct net_device	*dev_get_by_index(struct net *net, int ifindex);
extern struct net_device	*__dev_get_by_index(struct net *net, int ifindex);
extern int		dev_restart(struct net_device *dev);
#ifdef CONFIG_NETPOLL_TRAP
extern int		netpoll_trap(void);
#endif
extern int	       skb_gro_receive(struct sk_buff **head,
				       struct sk_buff *skb);
extern void	       skb_gro_reset_offset(struct sk_buff *skb);

static inline unsigned int skb_gro_offset(const struct sk_buff *skb)
{
	return NAPI_GRO_CB(skb)->data_offset;
}

static inline unsigned int skb_gro_len(const struct sk_buff *skb)
{
	return skb->len - NAPI_GRO_CB(skb)->data_offset;
}

static inline void skb_gro_pull(struct sk_buff *skb, unsigned int len)
{
	NAPI_GRO_CB(skb)->data_offset += len;
}

static inline void *skb_gro_header_fast(struct sk_buff *skb,
					unsigned int offset)
{
	return NAPI_GRO_CB(skb)->frag0 + offset;
}

static inline int skb_gro_header_hard(struct sk_buff *skb, unsigned int hlen)
{
	return NAPI_GRO_CB(skb)->frag0_len < hlen;
}

static inline void *skb_gro_header_slow(struct sk_buff *skb, unsigned int hlen,
					unsigned int offset)
{
	if (!pskb_may_pull(skb, hlen))
		return NULL;

	NAPI_GRO_CB(skb)->frag0 = NULL;
	NAPI_GRO_CB(skb)->frag0_len = 0;
	return skb->data + offset;
}

static inline void *skb_gro_mac_header(struct sk_buff *skb)
{
	return NAPI_GRO_CB(skb)->frag0 ?: skb_mac_header(skb);
}

static inline void *skb_gro_network_header(struct sk_buff *skb)
{
	return (NAPI_GRO_CB(skb)->frag0 ?: skb->data) +
	       skb_network_offset(skb);
}

static inline int dev_hard_header(struct sk_buff *skb, struct net_device *dev,
				  unsigned short type,
				  const void *daddr, const void *saddr,
				  unsigned len)
{
	if (!dev->header_ops || !dev->header_ops->create)
		return 0;

	return dev->header_ops->create(skb, dev, type, daddr, saddr, len);
}

static inline int dev_parse_header(const struct sk_buff *skb,
				   unsigned char *haddr)
{
	const struct net_device *dev = skb->dev;

	if (!dev->header_ops || !dev->header_ops->parse)
		return 0;
	return dev->header_ops->parse(skb, haddr);
}

typedef int gifconf_func_t(struct net_device * dev, char __user * bufptr, int len);
extern int		register_gifconf(unsigned int family, gifconf_func_t * gifconf);
static inline int unregister_gifconf(unsigned int family)
{
	return register_gifconf(family, NULL);
}

/*
 * Incoming packets are placed on per-cpu queues so that
 * no locking is needed.
 */
struct softnet_data
{
	struct Qdisc		*output_queue;
	struct list_head	poll_list;
	struct sk_buff		*completion_queue;

	/* Elements below can be accessed between CPUs for RPS */
	struct call_single_data	csd ____cacheline_aligned_in_smp;
	unsigned int            input_queue_head;
	struct sk_buff_head	input_pkt_queue;
	struct napi_struct	backlog;
};

static inline void incr_input_queue_head(struct softnet_data *queue)
{
	queue->input_queue_head++;
}


DECLARE_PER_CPU_ALIGNED(struct softnet_data, softnet_data);

#define HAVE_NETIF_QUEUE

extern void __netif_schedule(struct Qdisc *q);

static inline void netif_schedule_queue(struct netdev_queue *txq)
{
	if (!test_bit(__QUEUE_STATE_XOFF, &txq->state))
		__netif_schedule(txq->qdisc);
}

static inline void netif_tx_schedule_all(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++)
		netif_schedule_queue(netdev_get_tx_queue(dev, i));
}

static inline void netif_tx_start_queue(struct netdev_queue *dev_queue)
{
	clear_bit(__QUEUE_STATE_XOFF, &dev_queue->state);
}

/**
 *	netif_start_queue - allow transmit
 *	@dev: network device
 *
 *	Allow upper layers to call the device hard_start_xmit routine.
 */
static inline void netif_start_queue(struct net_device *dev)
{
	netif_tx_start_queue(netdev_get_tx_queue(dev, 0));
}

static inline void netif_tx_start_all_queues(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		netif_tx_start_queue(txq);
	}
}

static inline void netif_tx_wake_queue(struct netdev_queue *dev_queue)
{
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap()) {
		netif_tx_start_queue(dev_queue);
		return;
	}
#endif
	if (test_and_clear_bit(__QUEUE_STATE_XOFF, &dev_queue->state))
		__netif_schedule(dev_queue->qdisc);
}

/**
 *	netif_wake_queue - restart transmit
 *	@dev: network device
 *
 *	Allow upper layers to call the device hard_start_xmit routine.
 *	Used for flow control when transmit resources are available.
 */
static inline void netif_wake_queue(struct net_device *dev)
{
	netif_tx_wake_queue(netdev_get_tx_queue(dev, 0));
}

static inline void netif_tx_wake_all_queues(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		netif_tx_wake_queue(txq);
	}
}

static inline void netif_tx_stop_queue(struct netdev_queue *dev_queue)
{
	set_bit(__QUEUE_STATE_XOFF, &dev_queue->state);
}

/**
 *	netif_stop_queue - stop transmitted packets
 *	@dev: network device
 *
 *	Stop upper layers calling the device hard_start_xmit routine.
 *	Used for flow control when transmit resources are unavailable.
 */
static inline void netif_stop_queue(struct net_device *dev)
{
	netif_tx_stop_queue(netdev_get_tx_queue(dev, 0));
}

static inline void netif_tx_stop_all_queues(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		netif_tx_stop_queue(txq);
	}
}

static inline int netif_tx_queue_stopped(const struct netdev_queue *dev_queue)
{
	return test_bit(__QUEUE_STATE_XOFF, &dev_queue->state);
}

/**
 *	netif_queue_stopped - test if transmit queue is flowblocked
 *	@dev: network device
 *
 *	Test if transmit queue on device is currently unable to send.
 */
static inline int netif_queue_stopped(const struct net_device *dev)
{
	return netif_tx_queue_stopped(netdev_get_tx_queue(dev, 0));
}

static inline int netif_tx_queue_frozen(const struct netdev_queue *dev_queue)
{
	return test_bit(__QUEUE_STATE_FROZEN, &dev_queue->state);
}

static inline void netdev_tx_sent_queue(struct netdev_queue *dev_queue,
					unsigned int bytes)
{
}

static inline void netdev_sent_queue(struct net_device *dev, unsigned int bytes)
{
	netdev_tx_sent_queue(netdev_get_tx_queue(dev, 0), bytes);
}

static inline void netdev_tx_completed_queue(struct netdev_queue *dev_queue,
					     unsigned pkts, unsigned bytes)
{
}

static inline void netdev_completed_queue(struct net_device *dev,
					  unsigned pkts, unsigned bytes)
{
	netdev_tx_completed_queue(netdev_get_tx_queue(dev, 0), pkts, bytes);
}

static inline void netdev_tx_reset_queue(struct netdev_queue *q)
{
}

static inline void netdev_reset_queue(struct net_device *dev_queue)
{
	netdev_tx_reset_queue(netdev_get_tx_queue(dev_queue, 0));
}

/**
 *	netif_running - test if up
 *	@dev: network device
 *
 *	Test if the device has been brought up.
 */
static inline int netif_running(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_START, &dev->state);
}

/*
 * Routines to manage the subqueues on a device.  We only need start
 * stop, and a check if it's stopped.  All other device management is
 * done at the overall netdevice level.
 * Also test the device if we're multiqueue.
 */

/**
 *	netif_start_subqueue - allow sending packets on subqueue
 *	@dev: network device
 *	@queue_index: sub queue index
 *
 * Start individual transmit queue of a device with multiple transmit queues.
 */
static inline void netif_start_subqueue(struct net_device *dev, u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);

	netif_tx_start_queue(txq);
}

/**
 *	netif_stop_subqueue - stop sending packets on subqueue
 *	@dev: network device
 *	@queue_index: sub queue index
 *
 * Stop individual transmit queue of a device with multiple transmit queues.
 */
static inline void netif_stop_subqueue(struct net_device *dev, u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap())
		return;
#endif
	netif_tx_stop_queue(txq);
}

/**
 *	netif_subqueue_stopped - test status of subqueue
 *	@dev: network device
 *	@queue_index: sub queue index
 *
 * Check individual transmit queue of a device with multiple transmit queues.
 */
static inline int __netif_subqueue_stopped(const struct net_device *dev,
					 u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);

	return netif_tx_queue_stopped(txq);
}

static inline int netif_subqueue_stopped(const struct net_device *dev,
					 struct sk_buff *skb)
{
	return __netif_subqueue_stopped(dev, skb_get_queue_mapping(skb));
}

/**
 *	netif_wake_subqueue - allow sending packets on subqueue
 *	@dev: network device
 *	@queue_index: sub queue index
 *
 * Resume individual transmit queue of a device with multiple transmit queues.
 */
static inline void netif_wake_subqueue(struct net_device *dev, u16 queue_index)
{
	struct netdev_queue *txq = netdev_get_tx_queue(dev, queue_index);
#ifdef CONFIG_NETPOLL_TRAP
	if (netpoll_trap())
		return;
#endif
	if (test_and_clear_bit(__QUEUE_STATE_XOFF, &txq->state))
		__netif_schedule(txq->qdisc);
}

/**
 *	netif_is_multiqueue - test if device has multiple transmit queues
 *	@dev: network device
 *
 * Check if device has multiple transmit queues
 */
static inline int netif_is_multiqueue(const struct net_device *dev)
{
	return (dev->num_tx_queues > 1);
}

extern void netif_set_real_num_tx_queues(struct net_device *dev,
					 unsigned int txq);

#ifdef CONFIG_RPS
extern int netif_set_real_num_rx_queues(struct net_device *dev,
					unsigned int rxq);
#else
static inline int netif_set_real_num_rx_queues(struct net_device *dev,
						unsigned int rxq)
{
	return 0;
}
#endif

#define DEFAULT_MAX_NUM_RSS_QUEUES	(8)
extern int netif_get_num_default_rss_queues(void);

static inline bool netif_is_bond_master(struct net_device *dev)
{
	return dev->flags & IFF_MASTER && dev->priv_flags & IFF_BONDING;
}

static inline bool netif_is_bond_slave(struct net_device *dev)
{
	return dev->flags & IFF_SLAVE && dev->priv_flags & IFF_BONDING;
}

/* Use this variant when it is known for sure that it
 * is executing from hardware interrupt context or with hardware interrupts
 * disabled.
 */
extern void dev_kfree_skb_irq(struct sk_buff *skb);

/* Use this variant in places where it could be invoked
 * from either hardware interrupt or other context, with hardware interrupts
 * either disabled or enabled.
 */
extern void dev_kfree_skb_any(struct sk_buff *skb);

#define HAVE_NETIF_RX 1
extern int		netif_rx(struct sk_buff *skb);
extern int		netif_rx_ni(struct sk_buff *skb);
#define HAVE_NETIF_RECEIVE_SKB 1
extern int		netif_receive_skb(struct sk_buff *skb);
extern void		napi_gro_flush(struct napi_struct *napi, bool flush_old);
extern gro_result_t	dev_gro_receive(struct napi_struct *napi,
					struct sk_buff *skb);
extern gro_result_t	napi_skb_finish(gro_result_t ret, struct sk_buff *skb);
extern int		napi_gro_receive(struct napi_struct *napi,
					 struct sk_buff *skb);
extern gro_result_t	napi_gro_receive_gr(struct napi_struct *napi,
					    struct sk_buff *skb);
extern void		napi_reuse_skb(struct napi_struct *napi,
				       struct sk_buff *skb);
extern struct sk_buff *	napi_get_frags(struct napi_struct *napi);
extern gro_result_t	napi_frags_finish(struct napi_struct *napi,
					  struct sk_buff *skb,
					  gro_result_t ret);
extern struct sk_buff *	napi_frags_skb(struct napi_struct *napi);
extern int		napi_gro_frags(struct napi_struct *napi);
extern gro_result_t	napi_gro_frags_gr(struct napi_struct *napi);

static inline void napi_free_frags(struct napi_struct *napi)
{
	kfree_skb(napi->skb);
	napi->skb = NULL;
}

extern int netdev_rx_handler_register(struct net_device *dev,
				      rx_handler_func_t *rx_handler,
				      void *rx_handler_data);
extern void netdev_rx_handler_unregister(struct net_device *dev);

extern int		dev_valid_name(const char *name);
extern int		dev_ioctl(struct net *net, unsigned int cmd, void __user *);
extern int		dev_ethtool(struct net *net, struct ifreq *);
extern unsigned		dev_get_flags(const struct net_device *);
extern int		dev_change_flags(struct net_device *, unsigned);
extern int		dev_change_name(struct net_device *, const char *);
extern int		dev_set_alias(struct net_device *, const char *, size_t);
extern int		dev_change_net_namespace(struct net_device *,
						 struct net *, const char *);
extern int		dev_set_mtu(struct net_device *, int);
extern int		dev_set_mac_address(struct net_device *,
					    struct sockaddr *);
extern int		dev_get_phys_port_id(struct net_device *dev,
					     struct netdev_phys_port_id *ppid);
extern int		dev_hard_start_xmit(struct sk_buff *skb,
					    struct net_device *dev,
					    struct netdev_queue *txq);
extern int		dev_forward_skb(struct net_device *dev,
					struct sk_buff *skb);

extern int		netdev_budget;

/* Called by rtnetlink.c:rtnl_unlock() */
extern void netdev_run_todo(void);

/**
 *	dev_put - release reference to device
 *	@dev: network device
 *
 * Release reference to device to allow it to be freed.
 */
static inline void dev_put(struct net_device *dev)
{
	atomic_dec(&dev->refcnt);
}

/**
 *	dev_hold - get reference to device
 *	@dev: network device
 *
 * Hold reference to device to keep it from being freed.
 */
static inline void dev_hold(struct net_device *dev)
{
	atomic_inc(&dev->refcnt);
}

/* Carrier loss detection, dial on demand. The functions netif_carrier_on
 * and _off may be called from IRQ context, but it is caller
 * who is responsible for serialization of these calls.
 *
 * The name carrier is inappropriate, these functions should really be
 * called netif_lowerlayer_*() because they represent the state of any
 * kind of lower layer not just hardware media.
 */

extern int linkwatch_init(void);
extern void linkwatch_fire_event(struct net_device *dev);

/**
 *	netif_carrier_ok - test if carrier present
 *	@dev: network device
 *
 * Check if carrier is present on device
 */
static inline int netif_carrier_ok(const struct net_device *dev)
{
	return !test_bit(__LINK_STATE_NOCARRIER, &dev->state);
}

extern unsigned long dev_trans_start(struct net_device *dev);

extern void __netdev_watchdog_up(struct net_device *dev);

extern void netif_carrier_on(struct net_device *dev);

extern void netif_carrier_off(struct net_device *dev);

extern void netif_notify_peers(struct net_device *dev);

/**
 *	netif_dormant_on - mark device as dormant.
 *	@dev: network device
 *
 * Mark device as dormant (as per RFC2863).
 *
 * The dormant state indicates that the relevant interface is not
 * actually in a condition to pass packets (i.e., it is not 'up') but is
 * in a "pending" state, waiting for some external event.  For "on-
 * demand" interfaces, this new state identifies the situation where the
 * interface is waiting for events to place it in the up state.
 *
 */
static inline void netif_dormant_on(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_DORMANT, &dev->state))
		linkwatch_fire_event(dev);
}

/**
 *	netif_dormant_off - set device as not dormant.
 *	@dev: network device
 *
 * Device is not in dormant state.
 */
static inline void netif_dormant_off(struct net_device *dev)
{
	if (test_and_clear_bit(__LINK_STATE_DORMANT, &dev->state))
		linkwatch_fire_event(dev);
}

/**
 *	netif_dormant - test if carrier present
 *	@dev: network device
 *
 * Check if carrier is present on device
 */
static inline int netif_dormant(const struct net_device *dev)
{
	return test_bit(__LINK_STATE_DORMANT, &dev->state);
}


/**
 *	netif_oper_up - test if device is operational
 *	@dev: network device
 *
 * Check if carrier is operational
 */
static inline int netif_oper_up(const struct net_device *dev) {
	return (dev->operstate == IF_OPER_UP ||
		dev->operstate == IF_OPER_UNKNOWN /* backward compat */);
}

/**
 *	netif_device_present - is device available or removed
 *	@dev: network device
 *
 * Check if device has not been removed from system.
 */
static inline int netif_device_present(struct net_device *dev)
{
	return test_bit(__LINK_STATE_PRESENT, &dev->state);
}

extern void netif_device_detach(struct net_device *dev);

extern void netif_device_attach(struct net_device *dev);

/*
 * Network interface message level settings
 */
#define HAVE_NETIF_MSG 1

enum {
	NETIF_MSG_DRV		= 0x0001,
	NETIF_MSG_PROBE		= 0x0002,
	NETIF_MSG_LINK		= 0x0004,
	NETIF_MSG_TIMER		= 0x0008,
	NETIF_MSG_IFDOWN	= 0x0010,
	NETIF_MSG_IFUP		= 0x0020,
	NETIF_MSG_RX_ERR	= 0x0040,
	NETIF_MSG_TX_ERR	= 0x0080,
	NETIF_MSG_TX_QUEUED	= 0x0100,
	NETIF_MSG_INTR		= 0x0200,
	NETIF_MSG_TX_DONE	= 0x0400,
	NETIF_MSG_RX_STATUS	= 0x0800,
	NETIF_MSG_PKTDATA	= 0x1000,
	NETIF_MSG_HW		= 0x2000,
	NETIF_MSG_WOL		= 0x4000,
};

#define netif_msg_drv(p)	((p)->msg_enable & NETIF_MSG_DRV)
#define netif_msg_probe(p)	((p)->msg_enable & NETIF_MSG_PROBE)
#define netif_msg_link(p)	((p)->msg_enable & NETIF_MSG_LINK)
#define netif_msg_timer(p)	((p)->msg_enable & NETIF_MSG_TIMER)
#define netif_msg_ifdown(p)	((p)->msg_enable & NETIF_MSG_IFDOWN)
#define netif_msg_ifup(p)	((p)->msg_enable & NETIF_MSG_IFUP)
#define netif_msg_rx_err(p)	((p)->msg_enable & NETIF_MSG_RX_ERR)
#define netif_msg_tx_err(p)	((p)->msg_enable & NETIF_MSG_TX_ERR)
#define netif_msg_tx_queued(p)	((p)->msg_enable & NETIF_MSG_TX_QUEUED)
#define netif_msg_intr(p)	((p)->msg_enable & NETIF_MSG_INTR)
#define netif_msg_tx_done(p)	((p)->msg_enable & NETIF_MSG_TX_DONE)
#define netif_msg_rx_status(p)	((p)->msg_enable & NETIF_MSG_RX_STATUS)
#define netif_msg_pktdata(p)	((p)->msg_enable & NETIF_MSG_PKTDATA)
#define netif_msg_hw(p)		((p)->msg_enable & NETIF_MSG_HW)
#define netif_msg_wol(p)	((p)->msg_enable & NETIF_MSG_WOL)

static inline u32 netif_msg_init(int debug_value, int default_msg_enable_bits)
{
	/* use default */
	if (debug_value < 0 || debug_value >= (sizeof(u32) * 8))
		return default_msg_enable_bits;
	if (debug_value == 0)	/* no output */
		return 0;
	/* set low N bits */
	return (1 << debug_value) - 1;
}

static inline void __netif_tx_lock(struct netdev_queue *txq, int cpu)
{
	spin_lock(&txq->_xmit_lock);
	txq->xmit_lock_owner = cpu;
}

static inline void __netif_tx_lock_bh(struct netdev_queue *txq)
{
	spin_lock_bh(&txq->_xmit_lock);
	txq->xmit_lock_owner = smp_processor_id();
}

static inline int __netif_tx_trylock(struct netdev_queue *txq)
{
	int ok = spin_trylock(&txq->_xmit_lock);
	if (likely(ok))
		txq->xmit_lock_owner = smp_processor_id();
	return ok;
}

static inline void __netif_tx_unlock(struct netdev_queue *txq)
{
	txq->xmit_lock_owner = -1;
	spin_unlock(&txq->_xmit_lock);
}

static inline void __netif_tx_unlock_bh(struct netdev_queue *txq)
{
	txq->xmit_lock_owner = -1;
	spin_unlock_bh(&txq->_xmit_lock);
}

static inline void txq_trans_update(struct netdev_queue *txq)
{
	if (txq->xmit_lock_owner != -1)
		txq->trans_start = jiffies;
}

/**
 *	netif_tx_lock - grab network device transmit lock
 *	@dev: network device
 *
 * Get network device transmit lock
 */
static inline void netif_tx_lock(struct net_device *dev)
{
	unsigned int i;
	int cpu;

	spin_lock(&dev->tx_global_lock);
	cpu = smp_processor_id();
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		/* We are the only thread of execution doing a
		 * freeze, but we have to grab the _xmit_lock in
		 * order to synchronize with threads which are in
		 * the ->hard_start_xmit() handler and already
		 * checked the frozen bit.
		 */
		__netif_tx_lock(txq, cpu);
		set_bit(__QUEUE_STATE_FROZEN, &txq->state);
		__netif_tx_unlock(txq);
	}
}

static inline void netif_tx_lock_bh(struct net_device *dev)
{
	local_bh_disable();
	netif_tx_lock(dev);
}

static inline void netif_tx_unlock(struct net_device *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		/* No need to grab the _xmit_lock here.  If the
		 * queue is not stopped for another reason, we
		 * force a schedule.
		 */
		clear_bit(__QUEUE_STATE_FROZEN, &txq->state);
		netif_schedule_queue(txq);
	}
	spin_unlock(&dev->tx_global_lock);
}

static inline void netif_tx_unlock_bh(struct net_device *dev)
{
	netif_tx_unlock(dev);
	local_bh_enable();
}

#define HARD_TX_LOCK(dev, txq, cpu) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_lock(txq, cpu);		\
	}						\
}

#define HARD_TX_UNLOCK(dev, txq) {			\
	if ((dev->features & NETIF_F_LLTX) == 0) {	\
		__netif_tx_unlock(txq);			\
	}						\
}

static inline void netif_tx_disable(struct net_device *dev)
{
	unsigned int i;
	int cpu;

	local_bh_disable();
	cpu = smp_processor_id();
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		__netif_tx_lock(txq, cpu);
		netif_tx_stop_queue(txq);
		__netif_tx_unlock(txq);
	}
	local_bh_enable();
}

static inline void netif_addr_lock(struct net_device *dev)
{
	spin_lock(&dev->addr_list_lock);
}

static inline void netif_addr_lock_bh(struct net_device *dev)
{
	spin_lock_bh(&dev->addr_list_lock);
}

static inline void netif_addr_unlock(struct net_device *dev)
{
	spin_unlock(&dev->addr_list_lock);
}

static inline void netif_addr_unlock_bh(struct net_device *dev)
{
	spin_unlock_bh(&dev->addr_list_lock);
}

/*
 * dev_addrs walker. Should be used only for read access. Call with
 * rcu_read_lock held.
 */
#define for_each_dev_addr(dev, ha) \
		list_for_each_entry_rcu(ha, &dev->dev_addrs.list, list)

/* These functions live elsewhere (drivers/net/net_init.c, but related) */

extern void		ether_setup(struct net_device *dev);

/* Support for loadable net-drivers */
extern struct net_device *alloc_netdev_mq(int sizeof_priv, const char *name,
				       void (*setup)(struct net_device *),
				       unsigned int queue_count);
extern struct net_device *alloc_netdev_mqs(int sizeof_priv, const char *name,
				       void (*setup)(struct net_device *),
				       unsigned int txqs, unsigned int rxqs);
#define alloc_netdev(sizeof_priv, name, setup) \
	alloc_netdev_mq(sizeof_priv, name, setup, 1)
extern int		register_netdev(struct net_device *dev);
extern void		unregister_netdev(struct net_device *dev);

/* Functions used for device addresses handling */
extern int dev_addr_add(struct net_device *dev, unsigned char *addr,
			unsigned char addr_type);
extern int dev_addr_del(struct net_device *dev, unsigned char *addr,
			unsigned char addr_type);
extern int dev_addr_add_multiple(struct net_device *to_dev,
				 struct net_device *from_dev,
				 unsigned char addr_type);
extern int dev_addr_del_multiple(struct net_device *to_dev,
				 struct net_device *from_dev,
				 unsigned char addr_type);

/* Functions used for secondary unicast and multicast support */
extern void		dev_set_rx_mode(struct net_device *dev);
extern void		__dev_set_rx_mode(struct net_device *dev);
extern int		dev_unicast_delete(struct net_device *dev, void *addr);
extern int		dev_unicast_add(struct net_device *dev, void *addr);
extern int		dev_unicast_sync(struct net_device *to, struct net_device *from);
extern void		dev_unicast_unsync(struct net_device *to, struct net_device *from);
extern void		dev_unicast_flush(struct net_device *dev);
extern int 		dev_mc_delete(struct net_device *dev, void *addr, int alen, int all);
extern int		dev_mc_add(struct net_device *dev, void *addr, int alen, int newonly);
extern int		dev_mc_sync(struct net_device *to, struct net_device *from);
extern void		dev_mc_unsync(struct net_device *to, struct net_device *from);
extern void		dev_addr_discard(struct net_device *dev);
extern int 		__dev_addr_delete(struct dev_addr_list **list, int *count, void *addr, int alen, int all);
extern int		__dev_addr_add(struct dev_addr_list **list, int *count, void *addr, int alen, int newonly);
extern int		__dev_addr_sync(struct dev_addr_list **to, int *to_count, struct dev_addr_list **from, int *from_count);
extern void		__dev_addr_unsync(struct dev_addr_list **to, int *to_count, struct dev_addr_list **from, int *from_count);
extern int		dev_set_promiscuity(struct net_device *dev, int inc);
extern int		dev_set_allmulti(struct net_device *dev, int inc);
extern void		netdev_state_change(struct net_device *dev);
extern void		netdev_features_change(struct net_device *dev);
/* Load a device via the kmod */
extern void		dev_load(struct net *net, const char *name);
extern void		dev_mcast_init(void);
extern const struct net_device_stats *dev_get_stats(struct net_device *dev);
extern const struct rtnl_link_stats64 *dev_get_stats64(struct net_device *dev,
						       struct rtnl_link_stats64 *storage);
extern void netdev_stats_to_stats64(struct rtnl_link_stats64 *stats64,
				    const struct net_device_stats *netdev_stats);
extern void		dev_txq_stats_fold(const struct net_device *dev, struct net_device_stats *stats);
extern void		dev_txq_stats_fold64(const struct net_device *dev,
					     struct rtnl_link_stats64 *stats);

extern int		netdev_max_backlog;
extern int		weight_p;
extern int		netdev_set_master(struct net_device *dev, struct net_device *master);

/* RSS keys are 40 or 52 bytes long */
#define NETDEV_RSS_KEY_LEN 52
extern u8 netdev_rss_key[NETDEV_RSS_KEY_LEN];
void netdev_rss_key_fill(void *buffer, size_t len);

extern int skb_checksum_help(struct sk_buff *skb);
extern struct sk_buff *skb_gso_segment(struct sk_buff *skb, int features);
extern struct sk_buff *__skb_gso_segment(struct sk_buff *skb, int features, bool tx_path);
extern struct sk_buff *skb_mac_gso_segment(struct sk_buff *skb, int features);
__be16 skb_network_protocol(struct sk_buff *skb, int *depth);

static inline bool can_checksum_protocol(int features, __be16 protocol)
{
	return ((features & NETIF_F_GEN_CSUM) ||
		((features & NETIF_F_V4_CSUM) &&
		 protocol == htons(ETH_P_IP)) ||
		((features & NETIF_F_V6_CSUM) &&
		 protocol == htons(ETH_P_IPV6)) ||
		((features & NETIF_F_FCOE_CRC) &&
		 protocol == htons(ETH_P_FCOE)));
}

#ifdef CONFIG_BUG
extern void netdev_rx_csum_fault(struct net_device *dev);
#else
static inline void netdev_rx_csum_fault(struct net_device *dev)
{
}
#endif
/* rx skb timestamps */
extern void		net_enable_timestamp(void);
extern void		net_disable_timestamp(void);

#ifdef CONFIG_PROC_FS
extern void *dev_seq_start(struct seq_file *seq, loff_t *pos);
extern void *dev_seq_next(struct seq_file *seq, void *v, loff_t *pos);
extern void dev_seq_stop(struct seq_file *seq, void *v);
#endif

extern int netdev_class_create_file(struct class_attribute *class_attr);
extern void netdev_class_remove_file(struct class_attribute *class_attr);

extern char *netdev_drivername(const struct net_device *dev, char *buffer, int len);

extern void linkwatch_run_queue(void);

static inline u32 netdev_get_wanted_features(struct net_device *dev)
{
	return (dev->features & ~netdev_extended(dev)->hw_features)
	       | netdev_extended(dev)->wanted_features;
}

static inline netdev_features_t netdev_intersect_features(netdev_features_t f1,
							  netdev_features_t f2)
{
	if (f1 & NETIF_F_GEN_CSUM)
		f1 |= (NETIF_F_ALL_CSUM & ~NETIF_F_GEN_CSUM);
	if (f2 & NETIF_F_GEN_CSUM)
		f2 |= (NETIF_F_ALL_CSUM & ~NETIF_F_GEN_CSUM);
	f1 &= f2;
	if (f1 & NETIF_F_GEN_CSUM)
		f1 &= ~(NETIF_F_ALL_CSUM & ~NETIF_F_GEN_CSUM);

	return f1;
}

unsigned long netdev_increment_features(unsigned long all, unsigned long one,
					unsigned long mask);
unsigned long netdev_fix_features(unsigned long features, const char *name);
u32 netdev_fix_features_dev(struct net_device *dev, u32 features);

/* Allow TSO being used on stacked device :
 * Performing the GSO segmentation before last device
 * is a performance improvement.
 */
static inline netdev_features_t netdev_add_tso_features(unsigned long features,
							unsigned long mask)
{
	return netdev_increment_features(features, NETIF_F_ALL_TSO, mask);
}

int __netdev_update_features(struct net_device *dev);
void netdev_update_features(struct net_device *dev);

void netif_stacked_transfer_operstate(const struct net_device *rootdev,
					struct net_device *dev);

int netif_skb_features(struct sk_buff *skb);

static inline int net_gso_ok(int features, int gso_type)
{
	int feature = gso_type << NETIF_F_GSO_SHIFT;
	return (features & feature) == feature;
}

static inline int skb_gso_ok(struct sk_buff *skb, int features)
{
	return net_gso_ok(features, skb_shinfo(skb)->gso_type) &&
	       (!skb_has_frag_list(skb) || (features & NETIF_F_FRAGLIST));
}

static inline int netif_needs_gso(struct sk_buff *skb, int features)
{
	return skb_is_gso(skb) && (!skb_gso_ok(skb, features) ||
		unlikely((skb->ip_summed != CHECKSUM_PARTIAL) &&
			 (skb->ip_summed != CHECKSUM_UNNECESSARY)));
}

static inline void netif_set_gso_max_size(struct net_device *dev,
					  unsigned int size)
{
	dev->gso_max_size = size;
}

extern struct net_device *br_get_br_dev_for_port_rcu(struct net_device *port_dev);

extern struct pernet_operations __net_initdata loopback_net_ops;

static inline int dev_ethtool_get_settings(struct net_device *dev,
					   struct ethtool_cmd *cmd)
{
	if (!dev->ethtool_ops || !dev->ethtool_ops->get_settings)
		return -EOPNOTSUPP;
	return dev->ethtool_ops->get_settings(dev, cmd);
}

static inline u32 dev_ethtool_get_rx_csum(struct net_device *dev)
{
	if (dev->features & NETIF_F_RXCSUM)
		return 1;
	if (!dev->ethtool_ops || !dev->ethtool_ops->get_rx_csum)
		return 0;
	return dev->ethtool_ops->get_rx_csum(dev);
}

static inline u32 dev_ethtool_get_flags(struct net_device *dev)
{
	if (!dev->ethtool_ops || !dev->ethtool_ops->get_flags)
		return 0;
	return dev->ethtool_ops->get_flags(dev);
}

/* Logging, debugging and troubleshooting/diagnostic helpers. */

/* netdev_printk helpers, similar to dev_printk */

static inline const char *netdev_name(const struct net_device *dev)
{
	if (dev->reg_state != NETREG_REGISTERED)
		return "(unregistered net_device)";
	return dev->name;
}

extern int __netdev_printk(const char *level, const struct net_device *dev,
			struct va_format *vaf);

extern __printf(3, 4)
int netdev_printk(const char *level, const struct net_device *dev,
		  const char *format, ...);
extern __printf(2, 3)
int netdev_emerg(const struct net_device *dev, const char *format, ...);
extern __printf(2, 3)
int netdev_alert(const struct net_device *dev, const char *format, ...);
extern __printf(2, 3)
int netdev_crit(const struct net_device *dev, const char *format, ...);
extern __printf(2, 3)
int netdev_err(const struct net_device *dev, const char *format, ...);
extern __printf(2, 3)
int netdev_warn(const struct net_device *dev, const char *format, ...);
extern __printf(2, 3)
int netdev_notice(const struct net_device *dev, const char *format, ...);
extern __printf(2, 3)
int netdev_info(const struct net_device *dev, const char *format, ...);

#define MODULE_ALIAS_NETDEV(device)				\
	MODULE_ALIAS("netdev-" device)

#if defined(CONFIG_DYNAMIC_DEBUG)
#define netdev_dbg(__dev, format, args...)			\
do {								\
	dynamic_netdev_dbg(__dev, format, ##args);		\
} while (0)
#elif defined(DEBUG)
#define netdev_dbg(__dev, format, args...)			\
	netdev_printk(KERN_DEBUG, __dev, format, ##args)
#else
#define netdev_dbg(__dev, format, args...)			\
({								\
	if (0)							\
		netdev_printk(KERN_DEBUG, __dev, format, ##args); \
	0;							\
})
#endif

#if defined(VERBOSE_DEBUG)
#define netdev_vdbg	netdev_dbg
#else

#define netdev_vdbg(dev, format, args...)			\
({								\
	if (0)							\
		netdev_printk(KERN_DEBUG, dev, format, ##args);	\
	0;							\
})
#endif

/*
 * netdev_WARN() acts like dev_printk(), but with the key difference
 * of using a WARN/WARN_ON to get the message out, including the
 * file/line information and a backtrace.
 */
#define netdev_WARN(dev, format, args...)			\
	WARN(1, "netdevice: %s\n" format, netdev_name(dev), ##args);

/* netif printk helpers, similar to netdev_printk */

#define netif_printk(priv, type, level, dev, fmt, args...)	\
do {					  			\
	if (netif_msg_##type(priv))				\
		netdev_printk(level, (dev), fmt, ##args);	\
} while (0)

#define netif_emerg(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_EMERG, dev, fmt, ##args)
#define netif_alert(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_ALERT, dev, fmt, ##args)
#define netif_crit(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_CRIT, dev, fmt, ##args)
#define netif_err(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_ERR, dev, fmt, ##args)
#define netif_warn(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_WARNING, dev, fmt, ##args)
#define netif_notice(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_NOTICE, dev, fmt, ##args)
#define netif_info(priv, type, dev, fmt, args...)		\
	netif_printk(priv, type, KERN_INFO, (dev), fmt, ##args)

#if defined(DEBUG)
#define netif_dbg(priv, type, dev, format, args...)		\
	netif_printk(priv, type, KERN_DEBUG, dev, format, ##args)
#elif defined(CONFIG_DYNAMIC_DEBUG)
#define netif_dbg(priv, type, netdev, format, args...)		\
do {								\
	if (netif_msg_##type(priv))				\
		dynamic_dev_dbg((netdev)->dev.parent,		\
				"%s: " format,			\
				netdev_name(netdev), ##args);	\
} while (0)
#else
#define netif_dbg(priv, type, dev, format, args...)			\
({									\
	if (0)								\
		netif_printk(priv, type, KERN_DEBUG, dev, format, ##args); \
	0;								\
})
#endif

/* if @cond then downgrade to debug, else print at @level */
#define netif_cond_dbg(priv, type, netdev, cond, level, fmt, args...)     \
	do {                                                              \
		if (cond)                                                 \
			netif_dbg(priv, type, netdev, fmt, ##args);       \
		else                                                      \
			netif_ ## level(priv, type, netdev, fmt, ##args); \
	} while (0)

#if defined(VERBOSE_DEBUG)
#define netif_vdbg	netdev_dbg
#else
#define netif_vdbg(priv, type, dev, format, args...)		\
({								\
	if (0)							\
		netif_printk(priv, type, KERN_DEBUG, dev, format, ##args); \
	0;							\
})
#endif

#endif /* __KERNEL__ */

#endif	/* _LINUX_NETDEVICE_H */
