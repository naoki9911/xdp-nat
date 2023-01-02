/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "parsing_helpers.h"

/* Defines xdp_stats_map */
#include "xdp_stats_kern_user.h"
#include "xdp_stats_kern.h"

#include "rewrite_helpers.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct config
{
	__u16 inner_if_index;
	__u16 outer_if_index;
	__u32 inner_addr;
	__u32 outer_addr;
};

struct bpf_map_def SEC("maps") configs = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct config),
	.max_entries = 1,
};

struct v4_tuple
{
	__u32 src_addr;
	__u32 dst_addr;
	__u16 src_port;
	__u16 dst_port;
};

struct v4_ct
{
	__u32 inner_addr;
	__u32 outer_addr;
	__u16 inner_port;
	__u16 outer_port;
	__u32 pkt_count;
};

struct bpf_map_def SEC("maps") inner2outer_v4_tcp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct v4_tuple),
	.value_size = sizeof(struct v4_ct),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") outer2inner_v4_tcp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct v4_tuple),
	.value_size = sizeof(struct v4_ct),
	.max_entries = 1024,
};

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	return ~((csum & 0xffff) + (csum >> 16));
}

/*
 * The icmp_checksum_diff function takes pointers to old and new structures and
 * the old checksum and returns the new checksum.  It uses the bpf_csum_diff
 * helper to compute the checksum difference. Note that the sizes passed to the
 * bpf_csum_diff helper should be multiples of 4, as it operates on 32-bit
 * words.
 */
static __always_inline __u16 icmp_checksum_diff(
	__u16 seed,
	struct icmphdr_common *icmphdr_new,
	struct icmphdr_common *icmphdr_old)
{
	__u32 csum, size = sizeof(struct icmphdr_common);

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}

static __always_inline __u16 csum16_add(__u16 csum, __u16 addend)
{
	csum += addend;
	return csum + (csum < addend);
}

/* from include/net/ip.h */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
	__u32 check = iph->check;
	check += bpf_htons(0x0100);
	iph->check = (__u16)(check + (check >= 0xFFFF));
	return --iph->ttl;
}

static __always_inline int parse_packet(
	struct xdp_md *ctx,
	struct ethhdr **ethhdr,
	struct iphdr **iphdr,
	struct icmphdr **icmphdr,
	struct udphdr **udphdr,
	struct tcphdr **tcphdr)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	int nh_type;

	nh.pos = data;
	nh_type = parse_ethhdr(&nh, data_end, ethhdr);

	if (nh_type != bpf_htons(ETH_P_IP))
	{
		return 0;
	}

	nh_type = parse_iphdr(&nh, data_end, iphdr);

	int res = -1;
	switch (nh_type)
	{
	case IPPROTO_ICMP:
		res = parse_icmphdr(&nh, data_end, icmphdr);
		if (res < 0)
		{
			return -1;
		}
		return nh_type;
	case IPPROTO_UDP:
		res = parse_udphdr(&nh, data_end, udphdr);
		if (res < 0)
		{
			return -1;
		}
		return nh_type;
	case IPPROTO_TCP:
		res = parse_tcphdr(&nh, data_end, tcphdr);
		if (res < 0)
		{
			return -1;
		}
		return nh_type;
	default:
		return -1;
	}
}

SEC("xdp_nat_inner2outer")
int xdp_nat_inner2outer_func(struct xdp_md *ctx)
{

	__u32 c_key = 0;
	struct config *c = (struct config *)bpf_map_lookup_elem(&configs, &c_key);
	if (c == NULL)
	{
		return XDP_PASS;
	}
	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct icmphdr *icmphdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	int proto;
	struct v4_tuple t, t2;
	struct v4_ct ct;
	int res = 0;
	struct bpf_fib_lookup fib_params;
	proto = parse_packet(ctx, &ethhdr, &iphdr, &icmphdr, &udphdr, &tcphdr);
	if (proto == 0)
	{
		return XDP_PASS;
	}
	switch (proto)
	{
	case IPPROTO_ICMP:
		break;
	case IPPROTO_UDP:
		break;
	case IPPROTO_TCP:
		if (iphdr == NULL)
		{
			return XDP_DROP;
		}
		if (iphdr->ttl <= 1)
		{
			return XDP_PASS;
		}
		__builtin_memset(&fib_params, 0, sizeof(fib_params));
		fib_params.family = AF_INET;
		fib_params.tos = iphdr->tos;
		fib_params.l4_protocol = iphdr->protocol;
		fib_params.sport = 0;
		fib_params.dport = 0;
		fib_params.tot_len = bpf_ntohs(iphdr->tot_len);
		fib_params.ipv4_src = iphdr->saddr;
		fib_params.ipv4_dst = iphdr->daddr;
		fib_params.ifindex = ctx->ingress_ifindex;

		int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
		if (rc != BPF_FIB_LKUP_RET_SUCCESS || fib_params.ifindex != c->outer_if_index)
		{
			return XDP_PASS;
		}

		t.src_addr = iphdr->saddr;
		t.dst_addr = iphdr->daddr;
		t.src_port = bpf_ntohs(tcphdr->source);
		t.dst_port = bpf_ntohs(tcphdr->dest);
		ct.inner_addr = iphdr->saddr;
		ct.outer_addr = c->outer_addr;
		ct.inner_port = bpf_ntohs(tcphdr->source);
		ct.outer_port = 10000;
		ct.pkt_count = 0;
		res = bpf_map_update_elem(&inner2outer_v4_tcp, &t, &ct, BPF_ANY);
		if (res < 0)
		{
			return XDP_DROP;
		}

		t2.src_addr = iphdr->daddr;
		t2.dst_addr = ct.outer_addr;
		t2.src_port = t.dst_port;
		t2.dst_port = ct.outer_port;
		res = bpf_map_update_elem(&outer2inner_v4_tcp, &t2, &ct, BPF_ANY);
		if (res < 0)
		{
			return XDP_DROP;
		}

		memcpy(ethhdr->h_source, fib_params.smac, ETH_ALEN);
		memcpy(ethhdr->h_dest, fib_params.dmac, ETH_ALEN);

		// update TCP header checksum
		__u32 csum = ~tcphdr->check;
		csum = csum16_add(csum, ~tcphdr->source);
		csum = csum16_add(csum, ~(__u16)(iphdr->saddr >> 16));
		csum = csum16_add(csum, ~(__u16)(iphdr->saddr));

		tcphdr->source = bpf_htons(ct.outer_port);

		csum = csum16_add(csum, tcphdr->source);
		csum = csum16_add(csum, (__u16)(ct.outer_addr >> 16));
		csum = csum16_add(csum, (__u16)(ct.outer_addr));
		tcphdr->check = ~csum;

		// update IP header checksum
		csum = ~iphdr->check;
		csum = csum16_add(csum, ~(__u16)(iphdr->saddr >> 16));
		csum = csum16_add(csum, ~(__u16)(iphdr->saddr));

		iphdr->saddr = ct.outer_addr;

		csum = csum16_add(csum, (__u16)(iphdr->saddr >> 16));
		csum = csum16_add(csum, (__u16)(iphdr->saddr));
		iphdr->check = ~csum;

		// decrease ip ttl
		ip_decrease_ttl(iphdr);

		return bpf_redirect(c->outer_if_index, 0);
		break;
	default:
		return XDP_DROP;
	}
	return XDP_PASS;
}

SEC("xdp_nat_outer2inner")
int xdp_nat_outer2inner_func(struct xdp_md *ctx)
{
	__u32 c_key = 0;
	struct config *c = (struct config *)bpf_map_lookup_elem(&configs, &c_key);
	if (c == NULL)
	{
		return XDP_PASS;
	}
	struct ethhdr *ethhdr;
	struct iphdr *iphdr;
	struct icmphdr *icmphdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	int proto;
	struct v4_tuple t;
	struct bpf_fib_lookup fib_params;
	proto = parse_packet(ctx, &ethhdr, &iphdr, &icmphdr, &udphdr, &tcphdr);
	if (proto == 0)
	{
		return XDP_PASS;
	}
	switch (proto)
	{
	case IPPROTO_ICMP:
		break;
	case IPPROTO_UDP:
		break;
	case IPPROTO_TCP:
		if (iphdr == NULL)
		{
			return XDP_DROP;
		}
		if (iphdr->ttl <= 1)
		{
			return XDP_PASS;
		}
		t.src_addr = iphdr->saddr;
		t.dst_addr = iphdr->daddr;
		t.src_port = bpf_ntohs(tcphdr->source);
		t.dst_port = bpf_ntohs(tcphdr->dest);
		struct v4_ct *ct = (struct v4_ct *)bpf_map_lookup_elem(&outer2inner_v4_tcp, &t);
		if (ct == NULL)
		{
			return XDP_PASS;
		}

		__builtin_memset(&fib_params, 0, sizeof(fib_params));
		fib_params.family = AF_INET;
		fib_params.tos = iphdr->tos;
		fib_params.l4_protocol = iphdr->protocol;
		fib_params.sport = 0;
		fib_params.dport = 0;
		fib_params.tot_len = bpf_ntohs(iphdr->tot_len);
		fib_params.ipv4_src = c->inner_addr;
		fib_params.ipv4_dst = ct->inner_addr;
		fib_params.ifindex = ctx->ingress_ifindex;

		int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
		if (rc != BPF_FIB_LKUP_RET_SUCCESS || fib_params.ifindex != c->inner_if_index)
		{
			return XDP_PASS;
		}

		memcpy(ethhdr->h_source, fib_params.smac, ETH_ALEN);
		memcpy(ethhdr->h_dest, fib_params.dmac, ETH_ALEN);

		// update TCP header checksum
		__u32 csum = ~tcphdr->check;
		csum = csum16_add(csum, ~tcphdr->dest);
		csum = csum16_add(csum, ~(__u16)(iphdr->daddr >> 16));
		csum = csum16_add(csum, ~(__u16)(iphdr->daddr));

		tcphdr->dest = bpf_htons(ct->inner_port);

		csum = csum16_add(csum, tcphdr->dest);
		csum = csum16_add(csum, (__u16)(ct->inner_addr >> 16));
		csum = csum16_add(csum, (__u16)(ct->inner_addr));
		tcphdr->check = ~csum;

		// update IP header checksum
		csum = ~iphdr->check;
		csum = csum16_add(csum, ~(__u16)(iphdr->daddr >> 16));
		csum = csum16_add(csum, ~(__u16)(iphdr->daddr));

		iphdr->daddr = ct->inner_addr;

		csum = csum16_add(csum, (__u16)(iphdr->daddr >> 16));
		csum = csum16_add(csum, (__u16)(iphdr->daddr));
		iphdr->check = ~csum;

		// decrease ip ttl
		ip_decrease_ttl(iphdr);

		return bpf_redirect(c->inner_if_index, 0);
		break;
	default:
		return XDP_DROP;
	}
	return XDP_PASS;
}

/* Implement packet03/assignment-1 in this section */
SEC("xdp_icmp_echo")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	__u16 echo_reply, old_csum;
	struct icmphdr_common *icmphdr, icmphdr_old;
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP))
	{
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	}
	else if (eth_type == bpf_htons(ETH_P_IPV6))
	{
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	}
	else
	{
		goto out;
	}

	/*
	 * We are using a special parser here which returns a stucture
	 * containing the "protocol-independent" part of an ICMP or ICMPv6
	 * header.  For purposes of this Assignment we are not interested in
	 * the rest of the structure.
	 */
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO)
	{
		/* Swap IP source and destination */
		swap_src_dst_ipv4(iphdr);
		echo_reply = ICMP_ECHOREPLY;
	}
	else if (eth_type == bpf_htons(ETH_P_IPV6) && icmp_type == ICMPV6_ECHO_REQUEST)
	{
		/* Swap IPv6 source and destination */
		swap_src_dst_ipv6(ipv6hdr);
		echo_reply = ICMPV6_ECHO_REPLY;
	}
	else
	{
		goto out;
	}

	/* Swap Ethernet source and destination */
	swap_src_dst_mac(eth);

	/* Assignment 1: patch the packet and update the checksum. You can use
	 * the echo_reply variable defined above to fix the ICMP Type field. */
	/* Patch the packet and update the checksum.*/
	old_csum = icmphdr->cksum;
	icmphdr->cksum = 0;
	icmphdr_old = *icmphdr;
	icmphdr->type = echo_reply;
	icmphdr->cksum = icmp_checksum_diff(~old_csum, icmphdr, &icmphdr_old);

	/* Another, less generic, but a bit more efficient way to update the
	 * checksum is listed below.  As only one 16-bit word changed, the sum
	 * can be patched using this formula: sum' = ~(~sum + ~m0 + m1), where
	 * sum' is a new sum, sum is an old sum, m0 and m1 are the old and new
	 * 16-bit words, correspondingly. In the formula above the + operation
	 * is defined as the following function:
	 *
	 *     static __always_inline __u16 csum16_add(__u16 csum, __u16 addend)
	 *     {
	 *         csum += addend;
	 *         return csum + (csum < addend);
	 *     }
	 *
	 * So an alternative code to update the checksum might look like this:
	 *
	 *     __u16 m0 = * (__u16 *) icmphdr;
	 *     icmphdr->type = echo_reply;
	 *     __u16 m1 = * (__u16 *) icmphdr;
	 *     icmphdr->checksum = ~(csum16_add(csum16_add(~icmphdr->checksum, ~m0), m1));
	 */

	action = XDP_TX;

out:
	return xdp_stats_record_action(ctx, action);
}

char _license[] SEC("license") = "GPL";
