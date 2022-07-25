// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 *
 * Neighbour Discovery for NewIP
 * Linux NewIP INET implementation
 *
 * Based on net/ipv6/ndisc.c
 */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/route.h>
#include <linux/init.h>
#include <linux/rcupdate.h>
#include <linux/nip.h>
#include <linux/nip_icmp.h>
#include <linux/jhash.h>
#include <net/sock.h>
#include <net/nip.h>
#include <net/nip_udp.h>
#include <net/protocol.h>
#include <net/nndisc.h>
#include <net/nip_route.h>
#include <net/addrconf.h>
#include <net/nip_fib.h>
#include <net/netlink.h>
#include <linux/rtnetlink.h>
#include <net/flow.h>
#include <net/inet_common.h>
#include <net/nip_addrconf.h>
#include <linux/newip_route.h>
#include <linux/netfilter.h>
#include "nip_hdr.h"
#include "nip_checksum.h"

/* NUD_INCOMPLETE
 * The neighbor request packet has been sent but no response has been received
 * NUD_REACHABLE
 * Reachable: Indicates that the neighbor is reachable
 * NUD_STAL
 * Idle state, which has not been confirmed for a long time,
 * and the idle time exceeds the rated time
 * NUD_DELAY
 * If the acknowledgment time expires but the idle time does not exceed the rated time,
 * you need to obtain the acknowledgment packet
 * NUD_PROBE
 * After NUD_DELAY does not receive confirmation for a long time, ARP request messages are sent
 * NUD_FAILED
 * The neighbor is unreachable
 * NUD_NOARP
 * Indicates the status of the neighbor that does not need the ARP status change
 * NUD_PERMANENT
 * Indicates that the status of the neighbor item is permanent and does not need to change
 * NUD_NONE
 * Initialization status of the neighbor item
 */
static void nndisc_solicit(struct neighbour *neigh, struct sk_buff *skb);

static u32 nndisc_hash(const void *pkey,
		       const struct net_device *dev, __u32 *fhash_rnd);
static bool nndisc_key_eq(const struct neighbour *neigh, const void *pkey);
static int nndisc_constructor(struct neighbour *neigh);

static void nndisc_error_report(struct neighbour *neigh, struct sk_buff *skb)
{
	kfree_skb(skb);
}

static const struct neigh_ops nndisc_generic_ops = {
	.family = AF_NINET,
	.solicit = nndisc_solicit,
	.output = neigh_resolve_output,
	.connected_output = neigh_connected_output,
};

static const struct neigh_ops nndisc_hh_ops = {
	.family = AF_NINET,
	.solicit = nndisc_solicit,
	.error_report = nndisc_error_report,
	.output = neigh_resolve_output,
	.connected_output = neigh_resolve_output,
};

static const struct neigh_ops nndisc_direct_ops = {
	.family = AF_NINET,
	.output = neigh_direct_output,
	.connected_output = neigh_direct_output,
};

#define NIP_NEIGH_MCAST_PROBES 4
#define NIP_NEIGH_UCAST_PROBES 4
#define NIP_NEIGH_DELAY_PROBE_TIME (5 * HZ)
#define NIP_NEIGH_GC_STALETIME (60 * HZ)
#define NIP_NEIGH_QUEUE_LEN_BYTES (64 * 1024)
#define NIP_NEIGH_PROXY_QLEN 64
#define NIP_NEIGH_ANYCAST_DELAY (1 * HZ)
#define NIP_NEIGH_PROXY_DELAY ((8 * HZ) / 10)
#define NIP_NEIGH_GC_INTERVAL (30 * HZ)
#define NIP_NEIGH_GC_THRESH_1 128
#define NIP_NEIGH_GC_THRESH_2 512
#define NIP_NEIGH_GC_THRESH_3 1024

struct neigh_table nnd_tbl = {
	.family = AF_NINET,
	.key_len = sizeof(struct nip_addr),
	.protocol = cpu_to_be16(ETH_P_NEWIP),
	.hash = nndisc_hash,
	.key_eq = nndisc_key_eq,
	.constructor = nndisc_constructor,
	.id = "nndisc_cache",
	.parms = {
		  .tbl = &nnd_tbl,
		  .reachable_time = ND_REACHABLE_TIME,
		  .data = {
			   [NEIGH_VAR_MCAST_PROBES] = NIP_NEIGH_MCAST_PROBES,
			   [NEIGH_VAR_UCAST_PROBES] = NIP_NEIGH_UCAST_PROBES,
			   [NEIGH_VAR_RETRANS_TIME] = ND_RETRANS_TIMER,
			   [NEIGH_VAR_BASE_REACHABLE_TIME] = ND_REACHABLE_TIME,
			   [NEIGH_VAR_DELAY_PROBE_TIME] = NIP_NEIGH_DELAY_PROBE_TIME,
			   [NEIGH_VAR_GC_STALETIME] = NIP_NEIGH_GC_STALETIME,
			   [NEIGH_VAR_QUEUE_LEN_BYTES] = NIP_NEIGH_QUEUE_LEN_BYTES,
			   [NEIGH_VAR_PROXY_QLEN] = NIP_NEIGH_PROXY_QLEN,
			   [NEIGH_VAR_ANYCAST_DELAY] = NIP_NEIGH_ANYCAST_DELAY,
			   [NEIGH_VAR_PROXY_DELAY] = NIP_NEIGH_PROXY_DELAY,
			   },
		   },
	.gc_interval = NIP_NEIGH_GC_INTERVAL,
	.gc_thresh1 = NIP_NEIGH_GC_THRESH_1,
	.gc_thresh2 = NIP_NEIGH_GC_THRESH_2,
	.gc_thresh3 = NIP_NEIGH_GC_THRESH_3,
};

static u32 nndisc_hash(const void *pkey,
		       const struct net_device *dev, __u32 *hash_rnd)
{
	return nndisc_hashfn(pkey, dev, hash_rnd);
}

static bool nndisc_key_eq(const struct neighbour *n, const void *pkey)
{
	return neigh_key_eq800(n, pkey);
}

static int nndisc_constructor(struct neighbour *neigh)
{
	struct nip_addr *addr = (struct nip_addr *)&neigh->primary_key;
	struct net_device *dev = neigh->dev;
	struct ninet_dev *nin_dev;
	struct neigh_parms *parms;
	bool is_broadcast = (bool)nip_addr_eq(addr, &nip_broadcast_addr_arp);

	nin_dev = nin_dev_get(dev);
	if (!nin_dev)
		return -EINVAL;

	parms = nin_dev->nd_parms;
	__neigh_parms_put(neigh->parms);
	neigh->parms = neigh_parms_clone(parms);
	neigh->type = RTN_UNICAST;
	if (!dev->header_ops) {
		neigh->nud_state = NUD_NOARP;
		neigh->ops = &nndisc_direct_ops;
		neigh->output = neigh_direct_output;
	} else {
		if (is_broadcast ||
		    (dev->flags & IFF_POINTOPOINT)) {
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->broadcast, dev->addr_len);
		} else if (dev->flags & (IFF_NOARP | IFF_LOOPBACK)) {
			neigh->nud_state = NUD_NOARP;
			memcpy(neigh->ha, dev->dev_addr, dev->addr_len);
			if (dev->flags & IFF_LOOPBACK)
				neigh->type = RTN_LOCAL;
		}

		if (dev->header_ops->cache)
			neigh->ops = &nndisc_hh_ops;
		else
			neigh->ops = &nndisc_generic_ops;

		if (neigh->nud_state & NUD_VALID)
			neigh->output = neigh->ops->connected_output;
		else
			neigh->output = neigh->ops->output;
	}

	nin_dev_put(nin_dev);

	return 0;
}

void nip_insert_nndisc_send_checksum(struct sk_buff *skb, u_short checksum)
{
#define NNDISC_CHECKSUM_BIAS 2
	*(__u16 *)(skb_transport_header(skb) + NNDISC_CHECKSUM_BIAS) =
	htons(checksum);
}

unsigned short nip_get_nndisc_send_checksum(struct sk_buff *skb,
					    struct nip_hdr_encap *head,
					    int payload_len)
{
	struct nip_pseudo_header nph = {0};

	nph.nexthdr = head->nexthdr;
	nph.saddr = head->saddr;
	nph.daddr = head->daddr;
	nph.check_len = htons(payload_len);
	return nip_check_sum_build(skb_transport_header(skb),
				   payload_len, &nph);
}

bool nip_get_nndisc_rcv_checksum(struct sk_buff *skb,
				 u_char *transport_tail)
{
	struct nip_pseudo_header nph = {0};
	unsigned short check_len = (unsigned short)(transport_tail - (skb_transport_header(skb)));

	nph.nexthdr = NIPCB(skb)->nexthdr;
	nph.saddr = NIPCB(skb)->srcaddr;
	nph.daddr = NIPCB(skb)->dstaddr;
	nph.check_len = htons(check_len);

	return nip_check_sum_parse(skb_transport_header(skb), check_len, &nph)
	       == 0xffff ? true : false;
}

static void nndisc_payload_ns_pack(const struct nip_addr *solicit,
				   struct sk_buff *skb)
{
	struct nnd_msg *msg = (struct nnd_msg *)skb->data;
	u_char *p = msg->data;

	memset(&msg->icmph, 0, sizeof(msg->icmph));
	msg->icmph.nip_icmp_type = NIP_ARP_NS;
	msg->icmph.nip_icmp_cksum = 0;
	p = build_nip_addr(solicit, p);
}

static struct dst_entry *nndisc_dst_alloc(struct net_device *dev)
{
	struct nip_rt_info *rt;
	struct net *net = dev_net(dev);

	rt = nip_dst_alloc(net, dev, 0);
	if (!rt)
		return NULL;

	rt->dst.flags |= DST_HOST;
	rt->dst.input = nip_input;
	rt->dst.output = nip_output;
	atomic_set(&rt->dst.__refcnt, 1);

	return &rt->dst;
}

static int get_ns_payload_len(const struct nip_addr *solicit)
{
	return sizeof(struct nip_icmp_hdr) + get_nip_addr_len(solicit);
}

static void nndisc_send_ns(struct net_device *dev,
			   const struct nip_addr *solicit,
			   const struct nip_addr *daddr,
			   const struct nip_addr *saddr)
{
	int ret;
	struct sk_buff *skb;
	struct dst_entry *dst;
	struct net *net;
	struct sock *sk = NULL;
	int payload_len = get_ns_payload_len(solicit);
	int len = NIP_ETH_HDR_LEN + NIP_HDR_MAX + payload_len;
	struct nip_hdr_encap head = {0};
	unsigned short checksum;

	head.saddr = *saddr;
	head.daddr = *daddr;
	head.ttl = NIP_ARP_DEFAULT_TTL;
	head.nexthdr = IPPROTO_NIP_ICMP;

	skb = alloc_skb(len, 0);
	if (!skb) {
		DEBUG("%s: no space for skbuff!", __func__);
		return;
	}

	skb->protocol = htons(ETH_P_NEWIP);
	skb->dev = dev;
	skb->ip_summed = CHECKSUM_NONE;
	skb->csum = 0;
	memset(NIPCB(skb), 0, sizeof(struct ninet_skb_parm));

	NIPCB(skb)->dstaddr = head.daddr;
	NIPCB(skb)->srcaddr = head.saddr;
	NIPCB(skb)->nexthdr = head.nexthdr;

	/* reserve space for hardware header */
	skb_reserve(skb, NIP_ETH_HDR_LEN);
	skb_reset_network_header(skb);

	/* build nwk header */
	head.hdr_buf = (unsigned char *)skb->data;
	nip_hdr_comm_encap(&head);
	head.total_len = head.hdr_buf_pos + payload_len;
	nip_update_total_len(&head, htons(head.total_len));
	skb_reserve(skb, head.hdr_buf_pos);
	skb_reset_transport_header(skb);

	/* build transport header */
	nndisc_payload_ns_pack(solicit, skb);
	skb_reserve(skb, payload_len);

	skb->data = skb_network_header(skb);
	skb->len = head.hdr_buf_pos + payload_len;

	dst = nndisc_dst_alloc(dev);
	if (!dst) {
		kfree_skb(skb);
		return;
	}

	/* add check sum*/
	checksum = nip_get_nndisc_send_checksum(skb, &head, payload_len);
	nip_insert_nndisc_send_checksum(skb, checksum);

	skb_dst_set(skb, dst);
	net = dev_net(skb->dev);

	/* DST is set to SKB, and output is used to release SKB regardless of success or failure */
	ret = dst_output(net, sk, skb);
	if (ret)
		DEBUG("%s: dst output fail.", __func__);
}

static void nndisc_solicit(struct neighbour *neigh, struct sk_buff *skb)
{
	struct net_device *dev = neigh->dev;
	struct nip_addr *target = (struct nip_addr *)&neigh->primary_key;
	struct nip_addr *saddr = NULL;
	struct ninet_dev *idev;

	/* Obtain the NewIP address from the current dev as
	 * the source address of the request packet
	 */
	rcu_read_lock();
	idev = __nin_dev_get(dev);
	if (idev) {
		read_lock_bh(&idev->lock);
		if (!list_empty(&idev->addr_list)) {
			struct ninet_ifaddr *ifp;

			list_for_each_entry(ifp, &idev->addr_list, if_list) {
				saddr = &ifp->addr;
				nndisc_send_ns(dev, target,
					       &nip_broadcast_addr_arp,
					       saddr);
			}
		}
		read_unlock_bh(&idev->lock);
	} else {
		DEBUG("%s:idev don't exist.", __func__);
	}
	rcu_read_unlock();
}

static void build_na_hdr(u_char *smac, u_char mac_len, struct sk_buff *skb)
{
	struct nnd_msg *msg = (struct nnd_msg *)skb->data;
	u_char *p = msg->data;

	memset(&msg->icmph, 0, sizeof(msg->icmph));
	msg->icmph.nip_icmp_type = NIP_ARP_NA;
	msg->icmph.nip_icmp_cksum = 0;
	*p = mac_len;
	p++;
	memcpy(p, smac, mac_len);
}

static int get_na_payload_len(struct net_device *dev)
{
	/* Icmp Header Length
	 * Number of bytes in the MAC address length field
	 * MAC Address Length
	 */
	return sizeof(struct nip_icmp_hdr) + 1 + dev->addr_len;
}

static void nndisc_send_na(struct net_device *dev,
			   const struct nip_addr *daddr,
			   const struct nip_addr *saddr)
{
	int ret;
	struct sk_buff *skb = NULL;
	struct dst_entry *dst = NULL;
	struct sock *sk = NULL;
	int csummode = CHECKSUM_NONE;
	int payload_len = get_na_payload_len(dev);
	int len = NIP_ETH_HDR_LEN + NIP_HDR_MAX + payload_len;
	u_char *smac = dev->dev_addr;
	struct nip_hdr_encap head = {0};
	u_short checksum = 0;

	head.saddr = *saddr;
	head.daddr = *daddr;
	head.ttl = NIP_ARP_DEFAULT_TTL;
	head.nexthdr = IPPROTO_NIP_ICMP;

	skb = alloc_skb(len, 0);
	if (!skb) {
		DEBUG("%s: no space for skbuff!", __func__);
		return;
	}
	skb->protocol = htons(ETH_P_NEWIP);
	skb->ip_summed = csummode;
	skb->csum = 0;
	skb->dev = dev;
	memset(NIPCB(skb), 0, sizeof(struct ninet_skb_parm));

	NIPCB(skb)->dstaddr = head.daddr;
	NIPCB(skb)->srcaddr = head.saddr;
	NIPCB(skb)->nexthdr = head.nexthdr;

	/* reserve space for hardware header */
	skb_reserve(skb, NIP_ETH_HDR_LEN);
	skb_reset_network_header(skb);

	/* build nwk header */
	head.hdr_buf = (unsigned char *)skb->data;
	nip_hdr_comm_encap(&head);
	head.total_len = head.hdr_buf_pos + payload_len;
	nip_update_total_len(&head, htons(head.total_len));
	skb_reserve(skb, head.hdr_buf_pos);
	skb_reset_transport_header(skb);

	/* build na header */
	build_na_hdr(smac, dev->addr_len, skb);

	/* skip transport hdr */
	skb_reserve(skb, payload_len);

	/* set skb->data to point network header */
	skb->data = skb_network_header(skb);
	skb->len = head.hdr_buf_pos + payload_len;

	dst = nndisc_dst_alloc(dev);
	if (!dst) {
		kfree_skb(skb);
		return;
	}

	/* add check sum*/
	checksum = nip_get_nndisc_send_checksum(skb, &head, payload_len);
	nip_insert_nndisc_send_checksum(skb, checksum);

	skb_dst_set(skb, dst);
	ret = dst_output(dev_net(skb->dev), sk, skb);
	if (ret)
		DEBUG("%s: dst output fail.", __func__);
}

bool nip_addr_local(struct net_device *dev, struct nip_addr *addr)
{
	struct ninet_dev *idev;
	bool ret = false;

	rcu_read_lock();
	idev = __nin_dev_get(dev);
	if (idev) {
		read_lock_bh(&idev->lock);
		if (!list_empty(&idev->addr_list)) {
			struct ninet_ifaddr *ifp;

			list_for_each_entry(ifp, &idev->addr_list, if_list) {
				if (nip_addr_eq(addr, &ifp->addr)) {
					ret = true;
					break;
				}
			}
		}
		read_unlock_bh(&idev->lock);
	}
	rcu_read_unlock();

	return ret;
}

int nndisc_rcv_ns(struct sk_buff *skb)
{
	struct nnd_msg *msg = (struct nnd_msg *)skb_transport_header(skb);
	u_char *p = msg->data;
	u_char *lladdr;
	struct nip_addr addr = {0};
	struct neighbour *neigh;
	struct ethhdr *eth;
	struct net_device *dev = skb->dev;
	int err = 0;

	p = decode_nip_addr(p, &addr);
	if (!p) {
		DEBUG("failure when decode source address!");
		err = -EFAULT;
		goto out;
	}

	if (nip_addr_invalid(&addr)) {
		DEBUG("%s: icmp hdr addr invalid.", __func__);
		err = -EFAULT;
		goto out;
	}

	if (!nip_addr_local(dev, &addr)) {
		err = -ENXIO;
		goto out;
	}

	eth = (struct ethhdr *)skb_mac_header(skb);
	lladdr = eth->h_source;

	/* checksum parse*/
	if (!nip_get_nndisc_rcv_checksum(skb, p)) {
		DEBUG("%s:ns ICMP checksum failed, drop the packet", __func__);
		err = -EINVAL;
		goto out;
	}

	neigh = __neigh_lookup(&nnd_tbl, &NIPCB(skb)->srcaddr, dev, lladdr ||
			       !dev->addr_len);
	if (neigh) {
		neigh_update(neigh, lladdr, NUD_STALE, NEIGH_UPDATE_F_OVERRIDE,
			     0);
		neigh_release(neigh);
	}

	nndisc_send_na(dev, &NIPCB(skb)->srcaddr, &addr);
out:
	kfree_skb(skb);
	return err;
}

int nndisc_rcv_na(struct sk_buff *skb)
{
	struct nnd_msg *msg = (struct nnd_msg *)skb_transport_header(skb);
	u_char *p = msg->data;
	u_char len;
	u8 lladdr[ALIGN(MAX_ADDR_LEN, sizeof(unsigned long))];
	struct net_device *dev = skb->dev;
	struct neighbour *neigh;

	len = *p;
	p++;
	memset(lladdr, 0, ALIGN(MAX_ADDR_LEN, sizeof(unsigned long)));
	memcpy(lladdr, p, len);

	if (!nip_get_nndisc_rcv_checksum(skb, p + len)) {
		DEBUG("%s:na ICMP checksum failed! drop the packet!"
		      , __func__);
		kfree_skb(skb);
		return 0;
	}

	neigh = neigh_lookup(&nnd_tbl, &NIPCB(skb)->srcaddr, dev);
	if (neigh) {
		neigh_update(neigh, lladdr, NUD_REACHABLE,
			     NEIGH_UPDATE_F_OVERRIDE, 0);
		neigh_release(neigh);
		kfree_skb(skb);
		return 0;
	}
	kfree_skb(skb);
	return -EFAULT;
}

int nndisc_rcv(struct sk_buff *skb)
{
	int ret = 0;
	struct nip_icmp_hdr *hdr = nip_icmp_header(skb);
	u8 type = hdr->nip_icmp_type;

	switch (type) {
	case NIP_ARP_NS:
		ret = nndisc_rcv_ns(skb);
		break;
	case NIP_ARP_NA:
		ret = nndisc_rcv_na(skb);
		break;
	default:
		DEBUG("arp packet type error");
	}

	return ret;
}

int __init nndisc_init(void)
{
	neigh_table_init(NEIGH_NND_TABLE, &nnd_tbl);
	return 0;
}
