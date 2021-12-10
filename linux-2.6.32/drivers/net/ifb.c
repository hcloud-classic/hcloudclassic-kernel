/* drivers/net/ifb.c:

	The purpose of this driver is to provide a device that allows
	for sharing of resources:

	1) qdiscs/policies that are per device as opposed to system wide.
	ifb allows for a device which can be redirected to thus providing
	an impression of sharing.

	2) Allows for queueing incoming traffic for shaping instead of
	dropping.

	The original concept is based on what is known as the IMQ
	driver initially written by Martin Devera, later rewritten
	by Patrick McHardy and then maintained by Andre Correa.

	You need the tc action  mirror or redirect to feed this device
       	packets.

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version
	2 of the License, or (at your option) any later version.

  	Authors:	Jamal Hadi Salim (2005)

*/


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/u64_stats_sync.h>
#include <net/pkt_sched.h>
#include <net/net_namespace.h>

#define TX_TIMEOUT  (2*HZ)

#define TX_Q_LIMIT    32
struct ifb_private {
	struct tasklet_struct   ifb_tasklet;
	int     tasklet_pending;
	/* mostly debug stats leave in for now */
	unsigned long   st_task_enter; /* tasklet entered */
	unsigned long   st_txq_refl_try; /* transmit queue refill attempt */
	unsigned long   st_rxq_enter; /* receive queue entered */
	unsigned long   st_rx2tx_tran; /* receive to trasmit transfers */
	unsigned long   st_rxq_notenter; /*receiveQ not entered, resched */
	unsigned long   st_rx_frm_egr; /* received from egress path */
	unsigned long   st_rx_frm_ing; /* received from ingress path */
	unsigned long   st_rxq_check;
	unsigned long   st_rxq_rsch;

	struct u64_stats_sync	rsync;
	struct sk_buff_head     rq;
	u64 rx_packets;
	u64 rx_bytes;

	struct u64_stats_sync	tsync;
	struct sk_buff_head     tq;
	u64 tx_packets;
	u64 tx_bytes;
};

static int numifbs = 2;

static void ri_tasklet(unsigned long dev);
static netdev_tx_t ifb_xmit(struct sk_buff *skb, struct net_device *dev);
static int ifb_open(struct net_device *dev);
static int ifb_close(struct net_device *dev);

static void ri_tasklet(unsigned long dev)
{
	struct net_device *_dev = (struct net_device *)dev;
	struct ifb_private *dp = netdev_priv(_dev);
	struct netdev_queue *txq;
	struct sk_buff *skb;

	txq = netdev_get_tx_queue(_dev, 0);
	dp->st_task_enter++;
	if ((skb = skb_peek(&dp->tq)) == NULL) {
		dp->st_txq_refl_try++;
		if (__netif_tx_trylock(txq)) {
			dp->st_rxq_enter++;
			while ((skb = skb_dequeue(&dp->rq)) != NULL) {
				skb_queue_tail(&dp->tq, skb);
				dp->st_rx2tx_tran++;
			}
			__netif_tx_unlock(txq);
		} else {
			/* reschedule */
			dp->st_rxq_notenter++;
			goto resched;
		}
	}

	while ((skb = skb_dequeue(&dp->tq)) != NULL) {
		u32 from = G_TC_FROM(skb->tc_verd);

		skb->tc_verd = 0;
		skb->tc_verd = SET_TC_NCLS(skb->tc_verd);

		u64_stats_update_begin(&dp->tsync);
		dp->tx_packets++;
		dp->tx_bytes += skb->len;
		u64_stats_update_end(&dp->tsync);

		skb->dev = dev_get_by_index(&init_net, skb->iif);
		if (!skb->dev) {
			dev_kfree_skb(skb);
			_dev->stats.tx_dropped++;
			break;
		}
		dev_put(skb->dev);
		skb->iif = _dev->ifindex;

		if (from & AT_EGRESS) {
			dp->st_rx_frm_egr++;
			dev_queue_xmit(skb);
		} else if (from & AT_INGRESS) {
			dp->st_rx_frm_ing++;
			skb_pull(skb, skb->dev->hard_header_len);
			netif_rx(skb);
		} else
			BUG();
	}

	if (__netif_tx_trylock(txq)) {
		dp->st_rxq_check++;
		if ((skb = skb_peek(&dp->rq)) == NULL) {
			dp->tasklet_pending = 0;
			if (netif_queue_stopped(_dev))
				netif_wake_queue(_dev);
		} else {
			dp->st_rxq_rsch++;
			__netif_tx_unlock(txq);
			goto resched;
		}
		__netif_tx_unlock(txq);
	} else {
resched:
		dp->tasklet_pending = 1;
		tasklet_schedule(&dp->ifb_tasklet);
	}

}

static struct rtnl_link_stats64 *ifb_stats64(struct net_device *dev,
					     struct rtnl_link_stats64 *stats)
{
	struct ifb_private *dp = netdev_priv(dev);
	unsigned int start;

	do {
		start = u64_stats_fetch_begin_irq(&dp->rsync);
		stats->rx_packets = dp->rx_packets;
		stats->rx_bytes = dp->rx_bytes;
	} while (u64_stats_fetch_retry_irq(&dp->rsync, start));

	do {
		start = u64_stats_fetch_begin_irq(&dp->tsync);

		stats->tx_packets = dp->tx_packets;
		stats->tx_bytes = dp->tx_bytes;

	} while (u64_stats_fetch_retry_irq(&dp->tsync, start));

	stats->rx_dropped = dev->stats.rx_dropped;
	stats->tx_dropped = dev->stats.tx_dropped;

	return stats;
}


static const struct net_device_ops ifb_netdev_ops = {
	.ndo_open	= ifb_open,
	.ndo_stop	= ifb_close,
	.ndo_start_xmit	= ifb_xmit,
	.ndo_validate_addr = eth_validate_addr,
};

static const struct net_device_ops_ext ifb_netdev_ops_ext = {
	.size			= sizeof(struct net_device_ops_ext),
	.ndo_get_stats64	= ifb_stats64,
};

static void ifb_setup(struct net_device *dev)
{
	/* Initialize the device structure. */
	dev->destructor = free_netdev;
	dev->netdev_ops = &ifb_netdev_ops;
	set_netdev_ops_ext(dev, &ifb_netdev_ops_ext);

	/* Fill in device structure with ethernet-generic values. */
	ether_setup(dev);
	dev->tx_queue_len = TX_Q_LIMIT;

	dev->flags |= IFF_NOARP;
	dev->flags &= ~IFF_MULTICAST;
	dev->priv_flags &= ~IFF_XMIT_DST_RELEASE;
	netdev_extended(dev)->ext_priv_flags &= ~IFF_TX_SKB_SHARING;
	eth_hw_addr_random(dev);
}

static netdev_tx_t ifb_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct ifb_private *dp = netdev_priv(dev);
	u32 from = G_TC_FROM(skb->tc_verd);

	u64_stats_update_begin(&dp->rsync);
	dp->rx_packets++;
	dp->rx_bytes += skb->len;
	u64_stats_update_end(&dp->rsync);

	if (!(from & (AT_INGRESS|AT_EGRESS)) || !skb->iif) {
		dev_kfree_skb(skb);
		dev->stats.rx_dropped++;
		return NETDEV_TX_OK;
	}

	if (skb_queue_len(&dp->rq) >= dev->tx_queue_len) {
		netif_stop_queue(dev);
	}

	dev->trans_start = jiffies;
	skb_queue_tail(&dp->rq, skb);
	if (!dp->tasklet_pending) {
		dp->tasklet_pending = 1;
		tasklet_schedule(&dp->ifb_tasklet);
	}

	return NETDEV_TX_OK;
}

static int ifb_close(struct net_device *dev)
{
	struct ifb_private *dp = netdev_priv(dev);

	tasklet_kill(&dp->ifb_tasklet);
	netif_stop_queue(dev);
	skb_queue_purge(&dp->rq);
	skb_queue_purge(&dp->tq);
	return 0;
}

static int ifb_open(struct net_device *dev)
{
	struct ifb_private *dp = netdev_priv(dev);

	tasklet_init(&dp->ifb_tasklet, ri_tasklet, (unsigned long)dev);
	skb_queue_head_init(&dp->rq);
	skb_queue_head_init(&dp->tq);
	netif_start_queue(dev);

	return 0;
}

static int ifb_validate(struct nlattr *tb[], struct nlattr *data[])
{
	if (tb[IFLA_ADDRESS]) {
		if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
			return -EINVAL;
		if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
			return -EADDRNOTAVAIL;
	}
	return 0;
}

static struct rtnl_link_ops ifb_link_ops __read_mostly = {
	.kind		= "ifb",
	.priv_size	= sizeof(struct ifb_private),
	.setup		= ifb_setup,
	.validate	= ifb_validate,
};

/* Number of ifb devices to be set up by this module. */
module_param(numifbs, int, 0);
MODULE_PARM_DESC(numifbs, "Number of ifb devices");

static int __init ifb_init_one(int index)
{
	struct net_device *dev_ifb;
	int err;

	dev_ifb = alloc_netdev(sizeof(struct ifb_private),
				 "ifb%d", ifb_setup);

	if (!dev_ifb)
		return -ENOMEM;

	err = dev_alloc_name(dev_ifb, dev_ifb->name);
	if (err < 0)
		goto err;

	dev_ifb->rtnl_link_ops = &ifb_link_ops;
	err = register_netdevice(dev_ifb);
	if (err < 0)
		goto err;

	return 0;

err:
	free_netdev(dev_ifb);
	return err;
}

static int __init ifb_init_module(void)
{
	int i, err;

	rtnl_lock();
	err = __rtnl_link_register(&ifb_link_ops);

	for (i = 0; i < numifbs && !err; i++)
		err = ifb_init_one(i);
	if (err)
		__rtnl_link_unregister(&ifb_link_ops);
	rtnl_unlock();

	return err;
}

static void __exit ifb_cleanup_module(void)
{
	rtnl_link_unregister(&ifb_link_ops);
}

module_init(ifb_init_module);
module_exit(ifb_cleanup_module);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jamal Hadi Salim");
MODULE_ALIAS_RTNL_LINK("ifb");
