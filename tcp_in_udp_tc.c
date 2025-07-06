/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct tinuhdr {
	struct udphdr udphdr;
	__be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16 res1:4,
	    doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16 doff:4,
	    res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16 window;
	__be32 seq;
};

#define TCP_MAX_HEADER	60
#define PORT		5201

enum side {
	SERVER,
	CLIENT,
};

enum direction {
	EGRESS,
	INGRESS,
};

static __always_inline void tinu_to_tcp(struct __sk_buff *skb_addr,
					struct iphdr *iphdr_addr,
					struct ipv6hdr *ipv6hdr_addr,
					struct tinuhdr *tinuhdr_addr,
					void *data_hdr_end_addr)
{
	int tinu_hdr_len = data_hdr_end_addr - (void *)tinuhdr_addr;
	void *data_addr = (void *)(long)skb_addr->data;
	char buffer[TCP_MAX_HEADER];
	struct tcphdr *tcphdr_addr;
	__u8 proto = IPPROTO_TCP;

	bpf_skb_load_bytes(skb_addr, (void *)tinuhdr_addr - data_addr, buffer,
			   tinu_hdr_len);
	tcphdr_addr = (struct tcphdr *)buffer;
	tcphdr_addr->seq = tinuhdr_addr->seq;
	tcphdr_addr->check = 0;
	tcphdr_addr->urg_ptr = 0;
	bpf_skb_store_bytes(skb_addr, (void *)tinuhdr_addr - data_addr,
			    buffer, tinu_hdr_len, 0);

	/* Change protocol from UDP to TCP on the IP header. */
	if (iphdr_addr) {
		__u8 proto_old = IPPROTO_UDP;

		bpf_skb_store_bytes(skb_addr,
				    (void *)&iphdr_addr->protocol - data_addr,
				    &proto, sizeof(proto), 0);

		bpf_l3_csum_replace(skb_addr,
				    (void *)&iphdr_addr->check - data_addr,
				    bpf_htons(proto_old), bpf_htons(proto), 2);
	} else if (ipv6hdr_addr) {
		bpf_skb_store_bytes(skb_addr,
				    (void *)&ipv6hdr_addr->nexthdr -
				    data_addr, &proto, sizeof(proto), 0);
	}
}

static __always_inline void tcp_to_tinu(struct __sk_buff *skb_addr,
					struct iphdr *iphdr_addr,
					struct ipv6hdr *ipv6hdr_addr,
					struct tcphdr *tcphdr_addr,
					void *data_hdr_end_addr)
{
	int ip_payload_len =
	    (void *)(long)skb_addr->data_end - (void *)tcphdr_addr;
	int tcp_hdr_len = data_hdr_end_addr - (void *)tcphdr_addr;
	__u8 proto = IPPROTO_UDP, proto_old = IPPROTO_TCP;
	void *data_addr = (void *)(long)skb_addr->data;
	unsigned char tcp_hdr_max[TCP_MAX_HEADER];
	struct tcphdr *cpy_tcphdr_addr;
	struct tinuhdr *tinuhdr_addr;
	__sum16 csum;
	__be32 seq;

	/* Change protocol from TCP to UDP on the IP header. */
	if (iphdr_addr) {
		bpf_l3_csum_replace(skb_addr,
				    (void *)&iphdr_addr->check - data_addr,
				    bpf_htons(proto_old), bpf_htons(proto), 2);

		bpf_skb_store_bytes(skb_addr,
				    (void *)&iphdr_addr->protocol - data_addr,
				    &proto, sizeof(proto), 0);
	} else if (ipv6hdr_addr) {
		bpf_skb_store_bytes(skb_addr,
				    (void *)&ipv6hdr_addr->nexthdr -
				    data_addr, &proto, sizeof(proto), 0);
	}

	bpf_l4_csum_replace(skb_addr,
			    (void *)&tcphdr_addr->check - data_addr,
			    bpf_htons(proto_old), bpf_htons(proto),
			    BPF_F_PSEUDO_HDR | 2);

	bpf_l4_csum_replace(skb_addr,
			    (void *)&tcphdr_addr->check - data_addr,
			    0, bpf_htons(ip_payload_len), BPF_F_PSEUDO_HDR | 2);

	bpf_skb_load_bytes(skb_addr, (void *)tcphdr_addr - data_addr,
			   tcp_hdr_max, tcp_hdr_len);
	cpy_tcphdr_addr = (struct tcphdr *)tcp_hdr_max;
	csum = cpy_tcphdr_addr->check;
	seq = cpy_tcphdr_addr->seq;
	tinuhdr_addr = (struct tinuhdr *)tcp_hdr_max;
	tinuhdr_addr->udphdr.len = bpf_htons(ip_payload_len);
	tinuhdr_addr->udphdr.check = csum;
	tinuhdr_addr->seq = seq;
	bpf_skb_store_bytes(skb_addr, (void *)tcphdr_addr - data_addr,
			    tcp_hdr_max, tcp_hdr_len, 0);
}

int tc_action(struct __sk_buff *skb_addr, enum direction dir, enum side side)
{
	void *data_end_addr = (void *)(long)skb_addr->data_end;
	struct ipv6hdr *ipv6hdr_addr = NULL;
	struct iphdr *iphdr_addr = NULL;
	struct tinuhdr *tinuhdr_addr;
	struct ethhdr *ethhdr_addr;
	struct tcphdr *tcphdr_addr;
	void *data_hdr_end_addr;
	int l4_proto;

	ethhdr_addr = (struct ethhdr *)(long)skb_addr->data;
	data_hdr_end_addr = (void *)ethhdr_addr + sizeof(struct ethhdr);

	/* Exit if data address plus ethhdr structure length exceeds data end
	 * address.
	 */
	if (data_hdr_end_addr > data_end_addr)
		goto out;

	if (ethhdr_addr->h_proto == bpf_htons(ETH_P_IP)) {
		iphdr_addr = (struct iphdr *)data_hdr_end_addr;
		data_hdr_end_addr = (void *)iphdr_addr + sizeof(struct iphdr);

		/* Exit if data address plus ethhdr & iphdr structure lengths
		 * exceeds data end address.
		 */
		if (data_hdr_end_addr > data_end_addr)
			goto out;

		data_hdr_end_addr = (void *)iphdr_addr + (iphdr_addr->ihl << 2);
		l4_proto = iphdr_addr->protocol;
	} else if (ethhdr_addr->h_proto == bpf_htons(ETH_P_IPV6)) {
		ipv6hdr_addr = (struct ipv6hdr *)data_hdr_end_addr;
		data_hdr_end_addr =
		    (void *)ipv6hdr_addr + sizeof(struct ipv6hdr);

		/* Exit if data address plus ethhdr & ipv6hdr structure lengths
		 * exceeds data end address.
		 */
		if (data_hdr_end_addr > data_end_addr)
			goto out;

		// TODO: Can support IPv6 extensions here.

		l4_proto = ipv6hdr_addr->nexthdr;
	} else {
		goto out;
	}

	switch (dir) {
	case EGRESS:
		if (l4_proto != IPPROTO_TCP)
			goto out;

		tcphdr_addr = (struct tcphdr *)data_hdr_end_addr;
		data_hdr_end_addr = (void *)tcphdr_addr + sizeof(struct tcphdr);

		/* Exit if data address plus ethhdr, iphdr/ipv6hdr, & tcphdr
		 * structure lengths exceeds data end address, or TCP Data
		 * Offset is less than tcphdr structure length.
		 */
		if (data_hdr_end_addr > data_end_addr ||
		    (tcphdr_addr->doff << 2) < sizeof(struct tcphdr) ||
		    (tcphdr_addr->doff << 2) > TCP_MAX_HEADER)
			goto out;

		data_hdr_end_addr =
		    (void *)tcphdr_addr + (tcphdr_addr->doff << 2);

		switch (side) {
		case SERVER:
			if (tcphdr_addr->source != bpf_htons(PORT))
				goto out;
			break;
		case CLIENT:
			if (tcphdr_addr->dest != bpf_htons(PORT))
				goto out;
			break;
		}

		if (tcphdr_addr->urg) {
			if (iphdr_addr) {
				bpf_printk
				    ("tcp-udp: Skip: %pI4:%u -> %pI4:%u: urgent\n",
				     bpf_ntohl(iphdr_addr->saddr),
				     bpf_ntohs(tcphdr_addr->source),
				     bpf_ntohl(iphdr_addr->daddr),
				     bpf_ntohs(tcphdr_addr->dest));
			} else if (ipv6hdr_addr) {
				bpf_printk
				    ("tcp-udp: Skip: %pI6c:%u -> %pI6c:%u: urgent\n",
				     &ipv6hdr_addr->saddr,
				     bpf_ntohs(tcphdr_addr->source),
				     &ipv6hdr_addr->daddr,
				     bpf_ntohs(tcphdr_addr->dest));
			}

			goto out;	/* TODO: or set to 0 and adapt checksum? */
		}

		if (skb_addr->gso_segs > 1) {
			bpf_printk
			    ("tcp-udp: WARNING, GSO/TSO should be disabled: length:%u, segs:%u, size:%u\n",
			     skb_addr->len, skb_addr->gso_segs,
			     skb_addr->gso_size);
			goto out;
		}

		tcp_to_tinu(skb_addr, iphdr_addr, ipv6hdr_addr, tcphdr_addr,
			    data_hdr_end_addr);
		break;
	case INGRESS:
		if (l4_proto != IPPROTO_UDP)
			goto out;

		tinuhdr_addr = (struct tinuhdr *)data_hdr_end_addr;
		data_hdr_end_addr =
		    (void *)tinuhdr_addr + sizeof(struct tinuhdr);

		/* Exit if data address plus ethhdr, iphdr/ipv6hdr, & tinuhdr
		 * structure lengths exceeds data end address.
		 */
		if (data_hdr_end_addr > data_end_addr ||
		    (tinuhdr_addr->doff << 2) < sizeof(struct tinuhdr) ||
		    (tinuhdr_addr->doff << 2) > TCP_MAX_HEADER)
			goto out;

		data_hdr_end_addr =
		    (void *)tinuhdr_addr + (tinuhdr_addr->doff << 2);

		switch (side) {
		case SERVER:
			if (tinuhdr_addr->udphdr.dest != bpf_htons(PORT))
				goto out;
			break;
		case CLIENT:
			if (tinuhdr_addr->udphdr.source != bpf_htons(PORT))
				goto out;
			break;
		}

		if (skb_addr->gso_segs > 1) {
			bpf_printk
			    ("udp-tcp: WARNING, GRO/LRO should be disabled: length:%u, segs:%u, size:%u\n",
			     skb_addr->len, skb_addr->gso_segs,
			     skb_addr->gso_size);
			goto out;
		}

		tinu_to_tcp(skb_addr, iphdr_addr, ipv6hdr_addr, tinuhdr_addr,
			    data_hdr_end_addr);
		break;
	}
out:
	return TC_ACT_OK;
}

SEC("tc_client_egress")
int client_egress(struct __sk_buff *skb_addr)
{
	return tc_action(skb_addr, EGRESS, CLIENT);
}

SEC("tc_client_ingress")
int client_ingress(struct __sk_buff *skb_addr)
{
	return tc_action(skb_addr, INGRESS, CLIENT);
}

SEC("tc_server_egress")
int server_egress(struct __sk_buff *skb_addr)
{
	return tc_action(skb_addr, EGRESS, SERVER);
}

SEC("tc_server_ingress")
int server_ingress(struct __sk_buff *skb_addr)
{
	return tc_action(skb_addr, INGRESS, SERVER);
}

char _license[] SEC("license") = "GPL";
