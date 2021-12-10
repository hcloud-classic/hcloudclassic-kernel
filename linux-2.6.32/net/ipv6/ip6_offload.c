/*
 *	IPV6 GSO/GRO offload support
 *	Linux INET6 implementation
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/printk.h>
#include <linux/nospec.h>

#include <net/protocol.h>
#include <net/ipv6.h>

#include "ip6_offload.h"

static int ipv6_gso_pull_exthdrs(struct sk_buff *skb, int proto)
{
	const struct net_offload *ops = NULL;
	const struct inet6_protocol *proto_ops = NULL;

	proto = array_index_nospec(proto, MAX_INET_PROTOS);

	for (;;) {
		struct ipv6_opt_hdr *opth;
		int len;

		if (proto != NEXTHDR_HOP) {
			ops = rcu_dereference(inet6_offloads[proto]);

			if (likely(ops)) {
				if (!(ops->flags & INET6_PROTO_GSO_EXTHDR))
					break;
			} else {
				proto_ops = rcu_dereference(inet6_protos[proto]);
				if (!proto_ops)
					break;

				if (!(proto_ops->flags & INET6_PROTO_GSO_EXTHDR))
					break;
			}
		}

		if (unlikely(!pskb_may_pull(skb, 8)))
			break;

		opth = (void *)skb->data;
		len = ipv6_optlen(opth);

		if (unlikely(!pskb_may_pull(skb, len)))
			break;

		proto = array_index_nospec(opth->nexthdr, MAX_INET_PROTOS);
		__skb_pull(skb, len);
	}

	return proto;
}

static int ipv6_gso_send_check(struct sk_buff *skb)
{
	struct ipv6hdr *ipv6h;
	const struct net_offload *ops;
	const struct inet6_protocol *proto_ops;
	int proto;
	int err = -EINVAL;

	if (unlikely(!pskb_may_pull(skb, sizeof(*ipv6h))))
		goto out;

	ipv6h = ipv6_hdr(skb);
	__skb_pull(skb, sizeof(*ipv6h));
	err = -EPROTONOSUPPORT;

	rcu_read_lock();
	proto = ipv6_gso_pull_exthdrs(skb, ipv6h->nexthdr);
	ops = rcu_dereference(inet6_offloads[proto]);

	if (likely(ops && ops->gso_send_check)) {
		skb_reset_transport_header(skb);
		err = ops->gso_send_check(skb);
	} else {
		proto_ops = rcu_dereference(inet6_protos[proto]);
		if (proto_ops && proto_ops->gso_send_check) {
			skb_reset_transport_header(skb);
			err = ops->gso_send_check(skb);
		}
	}

	rcu_read_unlock();

out:
	return err;
}

static struct sk_buff *ipv6_gso_segment(struct sk_buff *skb, int features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct ipv6hdr *ipv6h;
	const struct net_offload *ops;
	const struct inet6_protocol *proto_ops;
	int proto;
	struct frag_hdr *fptr;
	u8 *prevhdr;
	int offset = 0;

	if (unlikely(skb_shinfo(skb)->gso_type &
		     ~(SKB_GSO_UDP |
		       SKB_GSO_DODGY |
		       SKB_GSO_TCP_ECN |
		       SKB_GSO_GRE |
		       SKB_GSO_UDP_TUNNEL |
		       SKB_GSO_TCPV6 |
		       0)))
		goto out;

	skb_reset_network_header(skb);
	if (unlikely(!pskb_may_pull(skb, sizeof(*ipv6h))))
		goto out;

	ipv6h = ipv6_hdr(skb);
	__skb_pull(skb, sizeof(*ipv6h));
	segs = ERR_PTR(-EPROTONOSUPPORT);

	proto = ipv6_gso_pull_exthdrs(skb, ipv6h->nexthdr);
	rcu_read_lock();
	ops = rcu_dereference(inet6_offloads[proto]);
	if (likely(ops && ops->gso_segment)) {
		skb_reset_transport_header(skb);
		segs = ops->gso_segment(skb, features);
	} else {
		proto_ops = rcu_dereference(inet6_protos[proto]);
		if (proto_ops && proto_ops->gso_segment) {
			skb_reset_transport_header(skb);
			segs = proto_ops->gso_segment(skb, features);
		}
	}
	rcu_read_unlock();

	if (unlikely(IS_ERR(segs)))
		goto out;

	for (skb = segs; skb; skb = skb->next) {
		ipv6h = ipv6_hdr(skb);
		ipv6h->payload_len = htons(skb->len - skb->mac_len -
					   sizeof(*ipv6h));
		if (proto == IPPROTO_UDP) {
			int err = ip6_find_1stfragopt(skb, &prevhdr);
			if (err < 0) {
				kfree_skb_list(segs);
				return ERR_PTR(err);
			}
			fptr = (struct frag_hdr *)(skb_network_header(skb) + err);
			fptr->frag_off = htons(offset);
			if (skb->next != NULL)
				fptr->frag_off |= htons(IP6_MF);
			offset += (ntohs(ipv6h->payload_len) -
				   sizeof(struct frag_hdr));
		}
	}

out:
	return segs;
}

struct ipv6_gro_cb {
	struct napi_gro_cb napi;
	int proto;
};

#define IPV6_GRO_CB(skb) ((struct ipv6_gro_cb *)(skb)->cb)

static struct sk_buff **ipv6_gro_receive(struct sk_buff **head,
					 struct sk_buff *skb)
{
	const struct net_offload *ops;
	const struct inet6_protocol *proto_ops = NULL;
	struct sk_buff **pp = NULL;
	struct sk_buff *p;
	struct ipv6hdr *iph;
	unsigned int nlen;
	unsigned int hlen;
	unsigned int off;
	int flush = 1;
	int proto;
	__wsum csum;

	off = skb_gro_offset(skb);
	hlen = off + sizeof(*iph);
	iph = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, hlen)) {
		iph = skb_gro_header_slow(skb, hlen, off);
		if (unlikely(!iph))
			goto out;
	}

	skb_gro_pull(skb, sizeof(*iph));
	skb_set_transport_header(skb, skb_gro_offset(skb));

	flush += ntohs(iph->payload_len) != skb_gro_len(skb);

	rcu_read_lock();
	proto = iph->nexthdr;
	ops = rcu_dereference(inet6_offloads[proto]);
	if (!ops || !ops->gro_receive) {
		proto_ops = rcu_dereference(inet6_protos[proto]);
		if (proto_ops && proto_ops->gro_receive) {
			ops = NULL;
			goto found;
		}

		__pskb_pull(skb, skb_gro_offset(skb));
		proto = ipv6_gso_pull_exthdrs(skb, proto);
		skb_gro_pull(skb, -skb_transport_offset(skb));
		skb_reset_transport_header(skb);
		__skb_push(skb, skb_gro_offset(skb));

		ops = rcu_dereference(inet6_offloads[proto]);
		if (!ops || !ops->gro_receive) {
			proto_ops = rcu_dereference(inet6_protos[proto]);
			if (!proto_ops || !proto_ops->gro_receive)
				goto out_unlock;
			ops = NULL;
		}

		iph = ipv6_hdr(skb);
	}

found:
	IPV6_GRO_CB(skb)->proto = proto;

	flush--;
	nlen = skb_network_header_len(skb);

	for (p = *head; p; p = p->next) {
		struct ipv6hdr *iph2;

		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		iph2 = ipv6_hdr(p);

		/* All fields must match except length. */
		if (nlen != skb_network_header_len(p) ||
		    memcmp(iph, iph2, offsetof(struct ipv6hdr, payload_len)) ||
		    memcmp(&iph->nexthdr, &iph2->nexthdr,
			   nlen - offsetof(struct ipv6hdr, nexthdr))) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		NAPI_GRO_CB(p)->flush |= flush;
	}

	NAPI_GRO_CB(skb)->flush |= flush;

	csum = skb->csum;
	skb_postpull_rcsum(skb, iph, skb_network_header_len(skb));

	if (ops)
		pp = ops->gro_receive(head, skb);
	else
		pp = proto_ops->gro_receive(head, skb);

	skb->csum = csum;

out_unlock:
	rcu_read_unlock();

out:
	NAPI_GRO_CB(skb)->flush |= flush;

	return pp;
}

static int ipv6_gro_complete(struct sk_buff *skb)
{
	const struct net_offload *ops;
	const struct inet6_protocol *proto_ops;
	struct ipv6hdr *iph = ipv6_hdr(skb);
	int err = -ENOSYS;

	iph->payload_len = htons(skb->len - skb_network_offset(skb) -
				 sizeof(*iph));

	rcu_read_lock();
	ops = rcu_dereference(inet6_offloads[IPV6_GRO_CB(skb)->proto]);
	if (unlikely(!ops || !ops->gro_complete)) {
		proto_ops = rcu_dereference(inet6_protos[IPV6_GRO_CB(skb)->proto]);
		if (!proto_ops || !proto_ops->gro_complete) {
			WARN_ON(true);
			goto out_unlock;
		}
		err = proto_ops->gro_complete(skb);
	} else
		err = ops->gro_complete(skb);

out_unlock:
	rcu_read_unlock();

	return err;
}

static struct packet_offload ipv6_packet_offload __read_mostly = {
	.type = cpu_to_be16(ETH_P_IPV6),
	.gso_send_check = ipv6_gso_send_check,
	.gso_segment = ipv6_gso_segment,
	.gro_receive = ipv6_gro_receive,
	.gro_complete = ipv6_gro_complete,
};

static int __init ipv6_offload_init(void)
{
	initialize_hashidentrnd();

	if (tcpv6_offload_init() < 0)
		pr_crit("%s: Cannot add TCP protocol offload\n", __func__);
	if (udp_offload_init() < 0)
		pr_crit("%s: Cannot add UDP protocol offload\n", __func__);
	if (ipv6_exthdrs_offload_init() < 0)
		pr_crit("%s: Cannot add EXTHDRS protocol offload\n", __func__);

	dev_add_offload(&ipv6_packet_offload);
	return 0;
}

fs_initcall(ipv6_offload_init);
