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

#ifndef memset
#define memset(dest, v, n) __builtin_memset((dest), v, n)
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

enum nat_type
{
	NAT_TYPE_SYMMETRIC,
	NAT_TYPE_CONE_FULL,
	NAT_TYPE_CONE_ADDRESS_RESTRICTED,
	NAT_TYPE_CONE_PORT_RESTRICTED,
};

enum nat_state_tcp
{
	NAT_STATE_TCP_RECV_SYN,
	NAT_STATE_TCP_RECV_SYN_ACK,
	NAT_STATE_TCP_ESTABLISHED,
	NAT_STATE_TCP_RECV_INNER_FIN,
	NAT_STATE_TCP_RECV_OUTER_FIN,
	NAT_STATE_TCP_WAIT_INNER_FIN2,
	NAT_STATE_TCP_RECV_INNER_FIN2,
	NAT_STATE_TCP_WAIT_OUTER_FIN2,
	NAT_STATE_TCP_RECV_OUTER_FIN2,
	NAT_STATE_TCP_CLOSED,
	NAT_STATE_TCP_RESET,
};

struct v4_ct
{
	__u8 inner_src_mac[6];
	__u8 inner_dst_mac[6];
	__u8 outer_src_mac[6];
	__u8 outer_dst_mac[6];
	__u32 inner_addr;
	__u32 outer_addr;

	__u32 end_addr;
	__u16 inner_port; // or id(for ICMP)
	__u16 outer_port;

	__u16 end_port;
	__u16 type; // symmetric or cone?
	__u32 padding;

	__u64 ktime;
	__u64 pkt_count;
	__u64 oct_count;
};

struct state
{
	__u16 state;
	// struct bpf_spin_lock lock;
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

struct bpf_map_def SEC("maps") state_v4_tcp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct v4_tuple),
	.value_size = sizeof(struct state),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") reserved_port_v4_tcp = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(__u16),
	.max_entries = 256};

struct bpf_map_def SEC("maps") inner2outer_v4_udp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct v4_tuple),
	.value_size = sizeof(struct v4_ct),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") outer2inner_v4_udp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct v4_tuple),
	.value_size = sizeof(struct v4_ct),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") reserved_port_v4_udp = {
	.type = BPF_MAP_TYPE_QUEUE,
	.key_size = 0,
	.value_size = sizeof(__u16),
	.max_entries = 256};

struct bpf_map_def SEC("maps") inner2outer_v4_icmp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct v4_tuple),
	.value_size = sizeof(struct v4_ct),
	.max_entries = 1024,
};

struct bpf_map_def SEC("maps") outer2inner_v4_icmp = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct v4_tuple),
	.value_size = sizeof(struct v4_ct),
	.max_entries = 1024,
};

// static __always_inline __u16 csum_fold_helper(__u32 csum)
//{
//	return ~((csum & 0xffff) + (csum >> 16));
// }
//
///*
// * The icmp_checksum_diff function takes pointers to old and new structures and
// * the old checksum and returns the new checksum.  It uses the bpf_csum_diff
// * helper to compute the checksum difference. Note that the sizes passed to the
// * bpf_csum_diff helper should be multiples of 4, as it operates on 32-bit
// * words.
// */
// static __always_inline __u16 icmp_checksum_diff(
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
	struct v4_ct *ct;
	struct v4_tuple t, t2;
	int res = 0;
	struct bpf_fib_lookup fib_params;
	__u32 csum;
	proto = parse_packet(ctx, &ethhdr, &iphdr, &icmphdr, &udphdr, &tcphdr);
	if (proto == 0 || iphdr == NULL)
	{
		return XDP_PASS;
	}
	if (iphdr->daddr == c->inner_addr)
	{
		return XDP_PASS;
	}
	if (iphdr->ttl <= 1)
	{
		return XDP_PASS;
	}

	memset(&t, 0, sizeof(t));
	t.addr = iphdr->saddr;
	switch (proto)
	{
	case IPPROTO_ICMP:
		if (icmphdr->type != ICMP_ECHO && icmphdr->type != ICMP_ECHOREPLY)
		{
			return XDP_PASS;
		}
		t.port = bpf_ntohs(icmphdr->un.echo.id);
		ct = (struct v4_ct *)bpf_map_lookup_elem(&inner2outer_v4_icmp, &t);
		if (ct == NULL)
		{
			memset(&fib_params, 0, sizeof(fib_params));
			fib_params.family = AF_INET;
			fib_params.tos = iphdr->tos;
			fib_params.l4_protocol = iphdr->protocol;
			fib_params.tot_len = bpf_ntohs(iphdr->tot_len);
			fib_params.ipv4_src = iphdr->saddr;
			fib_params.ipv4_dst = iphdr->daddr;
			fib_params.ifindex = ctx->ingress_ifindex;

			int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);
			if (rc != BPF_FIB_LKUP_RET_SUCCESS || fib_params.ifindex != c->outer_if_index)
			{
				return XDP_PASS;
			}

			struct v4_ct ct_new;
			memset(&ct_new, 0, sizeof(ct_new));
			ct_new.inner_addr = iphdr->saddr;
			ct_new.outer_addr = c->outer_addr;
			ct_new.end_addr = iphdr->daddr;
			ct_new.inner_port = t.port;
			ct_new.outer_port = t.port;
			ct_new.type = NAT_TYPE_SYMMETRIC;
			ct_new.pkt_count = 1;
			ct_new.oct_count = ctx->data_end - ctx->data;
			ct_new.ktime = bpf_ktime_get_ns();
			memcpy(ct_new.inner_src_mac, ethhdr->h_dest, ETH_ALEN);
			memcpy(ct_new.inner_dst_mac, ethhdr->h_source, ETH_ALEN);
			memcpy(ct_new.outer_src_mac, fib_params.smac, ETH_ALEN);
			memcpy(ct_new.outer_dst_mac, fib_params.dmac, ETH_ALEN);
			res = bpf_map_update_elem(&inner2outer_v4_icmp, &t, &ct_new, BPF_ANY);
			if (res < 0)
			{
				return XDP_DROP;
			}

			memset(&t2, 0, sizeof(t2));
			t2.addr = ct_new.outer_addr;
			t2.port = ct_new.outer_port;
			res = bpf_map_update_elem(&outer2inner_v4_icmp, &t2, &ct_new, BPF_ANY);
			if (res < 0)
			{
				return XDP_DROP;
			}
			ct = &ct_new;
		}
		else
		{
			ct->pkt_count += 1;
			ct->oct_count += ctx->data_end - ctx->data;
			ct->ktime = bpf_ktime_get_ns();
		}
		break;
	case IPPROTO_UDP:
		t.port = bpf_ntohs(udphdr->source);
		ct = (struct v4_ct *)bpf_map_lookup_elem(&inner2outer_v4_udp, &t);
		if (ct == NULL)
		{
			__u16 outer_port = 0;
			int rc = bpf_map_pop_elem(&reserved_port_v4_udp, &outer_port);
			if (rc < 0)
			{
				return XDP_PASS;
			}
			memset(&fib_params, 0, sizeof(fib_params));
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

			struct v4_ct ct_new;
			memset(&ct_new, 0, sizeof(ct_new));
			ct_new.inner_addr = iphdr->saddr;
			ct_new.outer_addr = c->outer_addr;
			ct_new.end_addr = iphdr->daddr;
			ct_new.inner_port = bpf_ntohs(udphdr->source);
			ct_new.outer_port = outer_port;
			ct_new.end_port = bpf_ntohs(udphdr->dest);
			ct_new.type = NAT_TYPE_SYMMETRIC;
			ct_new.pkt_count = 1;
			ct_new.oct_count = ctx->data_end - ctx->data;
			ct_new.ktime = bpf_ktime_get_ns();
			memcpy(ct_new.inner_src_mac, ethhdr->h_dest, ETH_ALEN);
			memcpy(ct_new.inner_dst_mac, ethhdr->h_source, ETH_ALEN);
			memcpy(ct_new.outer_src_mac, fib_params.smac, ETH_ALEN);
			memcpy(ct_new.outer_dst_mac, fib_params.dmac, ETH_ALEN);
			res = bpf_map_update_elem(&inner2outer_v4_udp, &t, &ct_new, BPF_ANY);
			if (res < 0)
			{
				return XDP_DROP;
			}

			memset(&t2, 0, sizeof(t2));
			t2.addr = ct_new.outer_addr;
			t2.port = ct_new.outer_port;
			res = bpf_map_update_elem(&outer2inner_v4_udp, &t2, &ct_new, BPF_ANY);
			if (res < 0)
			{
				return XDP_DROP;
			}
			ct = &ct_new;
		}
		else
		{
			ct->pkt_count += 1;
			ct->oct_count += ctx->data_end - ctx->data;
			ct->ktime = bpf_ktime_get_ns();
		}

		// update UDP header checksum
		csum = ~udphdr->check;
		csum = csum16_add(csum, ~udphdr->source);
		csum = csum16_add(csum, ~(__u16)(iphdr->saddr >> 16));
		csum = csum16_add(csum, ~(__u16)(iphdr->saddr));

		udphdr->source = bpf_htons(ct->outer_port);

		csum = csum16_add(csum, udphdr->source);
		csum = csum16_add(csum, (__u16)(ct->outer_addr >> 16));
		csum = csum16_add(csum, (__u16)(ct->outer_addr));
		udphdr->check = ~csum;
		break;
	case IPPROTO_TCP:
		t.port = bpf_ntohs(tcphdr->source);

		ct = (struct v4_ct *)bpf_map_lookup_elem(&inner2outer_v4_tcp, &t);
		if (ct == NULL)
		{
			if (tcphdr->syn == 0)
			{
				return XDP_DROP;
			}
			__u16 outer_port = 0;
			int rc = bpf_map_pop_elem(&reserved_port_v4_tcp, &outer_port);
			if (rc < 0)
			{
				return XDP_PASS;
			}
			memset(&fib_params, 0, sizeof(fib_params));
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

			struct state st;
			memset(&st, 0, sizeof(st));
			st.state = NAT_STATE_TCP_RECV_SYN;
			res = bpf_map_update_elem(&state_v4_tcp, &t, &st, BPF_ANY);
			if (res < 0)
			{
				return XDP_DROP;
			}

			struct v4_ct ct_new;
			memset(&ct_new, 0, sizeof(ct_new));
			ct_new.inner_addr = iphdr->saddr;
			ct_new.outer_addr = c->outer_addr;
			ct_new.end_addr = iphdr->daddr;
			ct_new.inner_port = bpf_ntohs(tcphdr->source);
			ct_new.outer_port = outer_port;
			ct_new.end_port = bpf_ntohs(tcphdr->dest);
			ct_new.type = NAT_TYPE_SYMMETRIC;
			ct_new.pkt_count = 1;
			ct_new.oct_count = ctx->data_end - ctx->data;
			ct_new.ktime = bpf_ktime_get_ns();
			memcpy(ct_new.inner_src_mac, ethhdr->h_dest, ETH_ALEN);
			memcpy(ct_new.inner_dst_mac, ethhdr->h_source, ETH_ALEN);
			memcpy(ct_new.outer_src_mac, fib_params.smac, ETH_ALEN);
			memcpy(ct_new.outer_dst_mac, fib_params.dmac, ETH_ALEN);
			res = bpf_map_update_elem(&inner2outer_v4_tcp, &t, &ct_new, BPF_ANY);
			if (res < 0)
			{
				return XDP_DROP;
			}

			memset(&t2, 0, sizeof(t2));
			t2.addr = ct_new.outer_addr;
			t2.port = ct_new.outer_port;
			res = bpf_map_update_elem(&outer2inner_v4_tcp, &t2, &ct_new, BPF_ANY);
			if (res < 0)
			{
				return XDP_DROP;
			}
			ct = &ct_new;
		}
		else
		{
			struct state *st = (struct state *)bpf_map_lookup_elem(&state_v4_tcp, &t);
			if (st == NULL)
			{
				return XDP_DROP;
			}
			if (st->state == NAT_STATE_TCP_RESET || st->state == NAT_STATE_TCP_CLOSED)
			{
				return XDP_DROP;
			}
			if (tcphdr->rst)
			{
				st->state = NAT_STATE_TCP_RESET;
			}
			if (tcphdr->fin)
			{
				if (st->state == NAT_STATE_TCP_WAIT_INNER_FIN2)
				{
					st->state = NAT_STATE_TCP_RECV_INNER_FIN2;
				}
				else
				{
					st->state = NAT_STATE_TCP_RECV_INNER_FIN;
				}
			}
			else if (st->state == NAT_STATE_TCP_RECV_OUTER_FIN && tcphdr->ack)
			{
				st->state = NAT_STATE_TCP_WAIT_INNER_FIN2;
			}
			else if (st->state == NAT_STATE_TCP_RECV_OUTER_FIN2 && tcphdr->ack)
			{
				st->state = NAT_STATE_TCP_CLOSED;
			}
			else if (st->state == NAT_STATE_TCP_RECV_SYN_ACK && tcphdr->ack)
			{
				st->state = NAT_STATE_TCP_ESTABLISHED;
			}

			// update TCP header checksum
			csum = ~tcphdr->check;
			csum = csum16_add(csum, ~tcphdr->source);
			csum = csum16_add(csum, ~(__u16)(iphdr->saddr >> 16));
			csum = csum16_add(csum, ~(__u16)(iphdr->saddr));

			tcphdr->source = bpf_htons(ct->outer_port);

			csum = csum16_add(csum, tcphdr->source);
			csum = csum16_add(csum, (__u16)(ct->outer_addr >> 16));
			csum = csum16_add(csum, (__u16)(ct->outer_addr));
			tcphdr->check = ~csum;
		}

		break;
	default:
		return XDP_DROP;
	}
	memcpy(ethhdr->h_source, ct->outer_src_mac, ETH_ALEN);
	memcpy(ethhdr->h_dest, ct->outer_dst_mac, ETH_ALEN);

	// update IP header checksum
	csum = ~iphdr->check;
	csum = csum16_add(csum, ~(__u16)(iphdr->saddr >> 16));
	csum = csum16_add(csum, ~(__u16)(iphdr->saddr));

	iphdr->saddr = ct->outer_addr;

	csum = csum16_add(csum, (__u16)(iphdr->saddr >> 16));
	csum = csum16_add(csum, (__u16)(iphdr->saddr));
	iphdr->check = ~csum;

	// decrease ip ttl
	ip_decrease_ttl(iphdr);

	return bpf_redirect(c->outer_if_index, 0);
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
	struct v4_ct *ct;
	struct v4_tuple t;
	__u32 csum;
	proto = parse_packet(ctx, &ethhdr, &iphdr, &icmphdr, &udphdr, &tcphdr);
	if (proto == 0 || iphdr == NULL)
	{
		return XDP_PASS;
	}
	if (iphdr->ttl <= 1)
	{
		return XDP_PASS;
	}

	memset(&t, 0, sizeof(t));
	t.addr = iphdr->daddr;

	switch (proto)
	{
	case IPPROTO_ICMP:
		if (icmphdr->type != ICMP_ECHO && icmphdr->type != ICMP_ECHOREPLY)
		{
			return XDP_PASS;
		}
		t.port = bpf_ntohs(icmphdr->un.echo.id);
		ct = (struct v4_ct *)bpf_map_lookup_elem(&outer2inner_v4_icmp, &t);
		if (ct == NULL)
		{
			return XDP_PASS;
		}
		break;
	case IPPROTO_UDP:
		t.port = bpf_ntohs(udphdr->dest);
		ct = (struct v4_ct *)bpf_map_lookup_elem(&outer2inner_v4_udp, &t);
		if (ct == NULL)
		{
			return XDP_PASS;
		}
		if (ct->type == NAT_TYPE_SYMMETRIC)
		{
			if (ct->end_addr != iphdr->saddr || ct->end_port != bpf_ntohs(udphdr->source))
			{
				return XDP_DROP;
			}
		}
		else
		{
			return XDP_DROP;
		}

		// update UDP header checksum
		csum = ~udphdr->check;
		csum = csum16_add(csum, ~udphdr->dest);
		csum = csum16_add(csum, ~(__u16)(iphdr->daddr >> 16));
		csum = csum16_add(csum, ~(__u16)(iphdr->daddr));

		udphdr->dest = bpf_htons(ct->inner_port);

		csum = csum16_add(csum, udphdr->dest);
		csum = csum16_add(csum, (__u16)(ct->inner_addr >> 16));
		csum = csum16_add(csum, (__u16)(ct->inner_addr));
		udphdr->check = ~csum;

		break;
	case IPPROTO_TCP:
		t.port = bpf_ntohs(tcphdr->dest);
		ct = (struct v4_ct *)bpf_map_lookup_elem(&outer2inner_v4_tcp, &t);
		if (ct == NULL)
		{
			return XDP_PASS;
		}

		struct v4_tuple t2;
		memset(&t2, 0, sizeof(t2));
		t2.addr = ct->inner_addr;
		t2.port = ct->inner_port;
		struct state *st = (struct state *)bpf_map_lookup_elem(&state_v4_tcp, &t2);
		if (st == NULL)
		{
			return XDP_DROP;
		}
		if (st->state == NAT_STATE_TCP_RESET || st->state == NAT_STATE_TCP_CLOSED)
		{
			return XDP_DROP;
		}

		if (tcphdr->rst)
		{
			st->state = NAT_STATE_TCP_RESET;
		}
		if (tcphdr->fin)
		{
			if (st->state == NAT_STATE_TCP_WAIT_OUTER_FIN2)
			{
				st->state = NAT_STATE_TCP_RECV_OUTER_FIN2;
			}
			else
			{
				st->state = NAT_STATE_TCP_RECV_OUTER_FIN;
			}
		}
		else if (st->state == NAT_STATE_TCP_RECV_INNER_FIN && tcphdr->ack)
		{
			st->state = NAT_STATE_TCP_WAIT_OUTER_FIN2;
		}
		else if (st->state == NAT_STATE_TCP_RECV_INNER_FIN2 && tcphdr->ack)
		{
			st->state = NAT_STATE_TCP_CLOSED;
		}
		else if (st->state == NAT_STATE_TCP_RECV_SYN)
		{
			if (tcphdr->syn && tcphdr->ack)
			{
				st->state = NAT_STATE_TCP_RECV_SYN_ACK;
			}
			else
			{
				return XDP_DROP;
			}
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

		// update TCP header checksum
		csum = ~tcphdr->check;
		csum = csum16_add(csum, ~tcphdr->dest);
		csum = csum16_add(csum, ~(__u16)(iphdr->daddr >> 16));
		csum = csum16_add(csum, ~(__u16)(iphdr->daddr));

		tcphdr->dest = bpf_htons(ct->inner_port);

		csum = csum16_add(csum, tcphdr->dest);
		csum = csum16_add(csum, (__u16)(ct->inner_addr >> 16));
		csum = csum16_add(csum, (__u16)(ct->inner_addr));
		tcphdr->check = ~csum;

		break;
	default:
		return XDP_DROP;
	}

	memcpy(ethhdr->h_source, ct->inner_src_mac, ETH_ALEN);
	memcpy(ethhdr->h_dest, ct->inner_dst_mac, ETH_ALEN);

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

	ct->pkt_count += 1;
	ct->oct_count += ctx->data_end - ctx->data;
	ct->ktime = bpf_ktime_get_ns();

	return bpf_redirect(c->inner_if_index, 0);
}

char _license[] SEC("license") = "GPL";
