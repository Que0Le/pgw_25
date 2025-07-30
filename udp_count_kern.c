// udp_count_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>  // struct ethhdr, ETH_P_IP
#include <linux/ip.h>        // struct iphdr, IPPROTO_UDP
#include <linux/udp.h>       // struct udphdr

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define UDP_PORT 2152

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} udp_count_map SEC(".maps");

SEC("xdp")
int xdp_udp_counter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Filter only IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->dest != __constant_htons(UDP_PORT))
        return XDP_PASS;

    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&udp_count_map, &key);
    if (value)
        __sync_fetch_and_add(value, 1);

    bpf_printk("UDP packet to port %d received\n", UDP_PORT);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
