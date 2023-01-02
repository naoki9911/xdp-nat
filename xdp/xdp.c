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
	__u32 addr;
	__u16 port;
	__u16 padding;
};


#define NAT_TYPE_SYMMETRIC (__u16)1

struct v4_ct
{
	__u32 inner_addr;
	__u32 outer_addr;
	__u32 end_addr;
	__u16 inner_port;
	__u16 outer_port;
	__u16 end_port;
	__u16 type; // symmetric or cone?
	__u32 pkt_count;
	__u64 ktime;
	__u8  inner_src_mac[6];
	__u8  inner_dst_mac[6];
	__u8  outer_src_mac[6];
	__u8  outer_dst_mac[6];

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

struct bpf_map_def SEC("maps") reserved_port_v4_tcp = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(__u16),
	.max_entries = 256
};

//static __always_inline __u16 csum_fold_helper(__u32 csum)
//{
//	return ~((csum & 0xffff) + (csum >> 16));
//}
//
///*
// * The icmp_checksum_diff function takes pointers to old and new structures and
// * the old checksum and returns the new checksum.  It uses the bpf_csum_diff
// * helper to compute the checksum difference. Note that the sizes passed to the
// * bpf_csum_diff helper should be multiples of 4, as it operates on 32-bit
// * words.
// */
//static __always_inline __u16 icmp_checksum_diff(
//	__u16 seed,
//	struct icmphdr_common *icmphdr_new,
//	struct icmphdr_common *icmphdr_old)
//{
//	__u32 csum, size = sizeof(struct icmphdr_common);
//
//	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
//	return csum_fold_helper(csum);
//}

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
	__builtin_memset(&ct, 0, sizeof(ct));
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

		__builtin_memset(&t, 0, sizeof(t));
		t.addr = iphdr->saddr;
		t.port = bpf_ntohs(tcphdr->source);

		struct v4_ct *tmp = (struct v4_ct *)bpf_map_lookup_elem(&inner2outer_v4_tcp, &t);
		if (tmp == NULL) {
			__u16 outer_port = 0;
			int rc = bpf_map_pop_elem(&reserved_port_v4_tcp, &outer_port);
			if (rc < 0)
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

			rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
			if (rc != BPF_FIB_LKUP_RET_SUCCESS || fib_params.ifindex != c->outer_if_index)
			{
				return XDP_PASS;
			}

			ct.inner_addr = iphdr->saddr;
			ct.outer_addr = c->outer_addr;
			ct.end_addr = iphdr->daddr;
			ct.inner_port = bpf_ntohs(tcphdr->source);
			ct.outer_port = outer_port;
			ct.end_port = bpf_ntohs(tcphdr->dest);
			ct.type = NAT_TYPE_SYMMETRIC;
			ct.pkt_count = 0;
			ct.ktime = bpf_ktime_get_ns();
			memcpy(ct.inner_src_mac, ethhdr->h_dest, ETH_ALEN);
			memcpy(ct.inner_dst_mac, ethhdr->h_source, ETH_ALEN);
			memcpy(ct.outer_src_mac, fib_params.smac, ETH_ALEN);
			memcpy(ct.outer_dst_mac, fib_params.dmac, ETH_ALEN);
			res = bpf_map_update_elem(&inner2outer_v4_tcp, &t, &ct, BPF_ANY);
			if (res < 0)
			{
				return XDP_DROP;
			}

			__builtin_memset(&t2, 0, sizeof(t2));
			t2.addr = ct.outer_addr;
			t2.port = ct.outer_port;
			res = bpf_map_update_elem(&outer2inner_v4_tcp, &t2, &ct, BPF_ANY);
			if (res < 0)
			{
				return XDP_DROP;
			}
		}
		else
		{
			ct = *tmp;
		}

		memcpy(ethhdr->h_source, ct.outer_src_mac, ETH_ALEN);
		memcpy(ethhdr->h_dest, ct.outer_dst_mac, ETH_ALEN);

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
		__builtin_memset(&t, 0, sizeof(t));
		t.addr = iphdr->daddr;
		t.port = bpf_ntohs(tcphdr->dest);
		struct v4_ct *ct = (struct v4_ct *)bpf_map_lookup_elem(&outer2inner_v4_tcp, &t);
		if (ct == NULL)
		{
			return XDP_PASS;
		}

		if (ct->type == NAT_TYPE_SYMMETRIC)
		{
			if (ct->end_addr != iphdr->saddr || ct->end_port != bpf_ntohs(tcphdr->source))
			{
				return XDP_DROP;
			}
		}
		else
		{
			return XDP_DROP;
		}

		memcpy(ethhdr->h_source, ct->inner_src_mac, ETH_ALEN);
		memcpy(ethhdr->h_dest, ct->inner_dst_mac, ETH_ALEN);

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

char _license[] SEC("license") = "GPL";
