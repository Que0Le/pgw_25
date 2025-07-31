// udp_count_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>  // struct ethhdr, ETH_P_IP
#include <linux/ip.h>        // struct iphdr, IPPROTO_UDP
#include <linux/udp.h>       // struct udphdr

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define UDP_PORT_PGW_REG 3000
#define UDP_PORT 2152
#define MAX_LENGTH__PGW_INSTANCE 4
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pgw__udp_count_map SEC(".maps");

/**
 * COnfig map for the PGW.
 * Index 0: number of PGW instances
 * Index 1:
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} pgw__config_map SEC(".maps");

struct pgw__config {
    __u32 id;
    __u32 weight;
    __u32 ipv4_addr;
    __u16 port;
    __u16 reserved;
    __u64 last_used;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, struct pgw__config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pgw__instances_list_map SEC(".maps");



static __always_inline int register_pgw(__u32 weight, __u32 ipv4_addr, __u16 port) {
#pragma unroll
    for (int i = 0; i < MAX_LENGTH__PGW_INSTANCE; i++) {
        __u32 key = i;
        struct pgw__config *conf = bpf_map_lookup_elem(&pgw__instances_list_map, &key);
        if (!conf)
            continue; // skip if lookup failed

        if (conf->ipv4_addr == 0) {
            conf->id = i;
            conf->weight = weight;
            conf->ipv4_addr = ipv4_addr;
            conf->port = port;
            conf->last_used = 9999;
            return i; // success
        }
    }

    return -1; // no free slot found
}

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

    __u8 *payload = (__u8 *)(udp + 1);
    if ((void *)(payload + sizeof(__u32)) > data_end)
        return XDP_DROP;

    __u32 val;
    __builtin_memcpy(&val, payload, sizeof(__u32));

    int ret;
    if (udp->dest == __constant_htons(UDP_PORT_PGW_REG)) {
        ret = register_pgw(val, ip->saddr, udp->source);
        if (ret >= 0)
            bpf_printk("Registered id=%d Payload=%u saddr=%x sport=%u\n", 
                ret, val, __builtin_bswap32(ip->saddr), __builtin_bswap16(udp->source));
        else
            bpf_printk("Error registering Payload=%u saddr=%x sport=%u\n", 
                val, __builtin_bswap32(ip->saddr), __builtin_bswap16(udp->source));
        return XDP_DROP;
    } else if (udp->dest != __constant_htons(UDP_PORT)) {
        return XDP_PASS;
    }

    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&pgw__udp_count_map, &key);
    if (value)
        __sync_fetch_and_add(value, 1);

    // bpf_printk("UDP packet to port %d received\n", UDP_PORT);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
