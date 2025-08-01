// udp_count_kern.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>  // struct ethhdr, ETH_P_IP
#include <linux/ip.h>        // struct iphdr, IPPROTO_UDP
#include <linux/udp.h>       // struct udphdr
#include <bpf/bpf_endian.h>

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define UDP_PORT_PGW_REG 3000
#define UDP_PORT 2152
#define MAX_LENGTH__PGW_INSTANCE 8

/* Counting map */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pgw__udp_count_map SEC(".maps");

struct pgw__config {
    __u32 id;           // usually just index in the array
    __u32 weight;
    __u32 ipv4_addr;
    __u16 port;
    __u16 reserved;     // reserved mem. ALso for (not sure) minimizing padding for last 16bytes.
    __u64 pkt_count;
    __u64 last_used;
    __u64 last_seen;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_LENGTH__PGW_INSTANCE);
    __type(key, __u32);
    __type(value, struct pgw__config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pgw__instances_list_map SEC(".maps");

/**
 * Register a gateway.
 * Add contact data of gateway to the instances list.
 * Timestamps and count are set to default.
 */
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
            conf->pkt_count = 0;
            conf->last_used = 9999;
            conf->last_seen = bpf_ktime_get_ns();
            return i; // success
        }
    }

    return -1; // no free slot found
}

/**
 * Calculate index of next best gateway candidate for sending this packet.
 * This is a naive function with the following criterions:
 * - CHeck from the head of the array. Item with empt iphdr is treated as invalid. 
 * - A valid gateway with count == 0 will end the search.
 * - Pick the gw with lowest <count / weight>. 
 * - Prefer gw with oldest last_used (gw that has been idle the longest)
 */
static __always_inline int select_pgw_instance(void) {
    int best_index = -1;
    __u64 best_pkt = 0;
    __u64 best_weight = 1; // avoid div-by-zero
    __u64 best_last_used = ~0ULL;

#pragma unroll
    for (int i = 0; i < MAX_LENGTH__PGW_INSTANCE; i++)
    {
        __u32 key = i;
        struct pgw__config *conf = bpf_map_lookup_elem(&pgw__instances_list_map, &key);
        if (!conf || conf->ipv4_addr == 0)
            continue;

        if (conf->pkt_count == 0)
            return i;

        __u64 pkt = conf->pkt_count;
        // Divide by 0 is bad. Assume that lowest possible weight == 1.
        __u64 weight = conf->weight == 0 ? 1 : conf->weight;    
        
        // Simulate division to avoid floating op.
        if (best_index == -1 ||
            (pkt * best_weight < best_pkt * weight) ||  // ratio = conf->pkt_count / conf->weight;
            (pkt * best_weight == best_pkt * weight && conf->last_used < best_last_used))
        {
            best_index = i;
            best_pkt = pkt;
            best_weight = weight;
            best_last_used = conf->last_used;
        }
    }

    return best_index;
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
        /* Handle registration packets */
        ret = register_pgw(val, ip->saddr, udp->source);
        if (ret >= 0)
            bpf_printk("Registered id=%d Payload=%u saddr=%x sport=%u\n", 
                ret, val, __builtin_bswap32(ip->saddr), __builtin_bswap16(udp->source));
        else
            bpf_printk("Error registering Payload=%u saddr=%x sport=%u\n", 
                val, __builtin_bswap32(ip->saddr), __builtin_bswap16(udp->source));
        return XDP_DROP;
    } else if (udp->dest != __constant_htons(UDP_PORT)) {
        /* Allow non GTP pkt to pass */
        return XDP_PASS;
    }

    /* Counting GTP pkt for debugging purpose */
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&pgw__udp_count_map, &key);
    if (value)
        __sync_fetch_and_add(value, 1);

    /* Who to handle this packet */
    int selected_pgw_id = select_pgw_instance() ;
    if (selected_pgw_id < 0) {
        bpf_printk("Couldn't find best pgw: %d\n", select_pgw_instance);
        return XDP_ABORTED;
    }
    struct pgw__config *target_conf = bpf_map_lookup_elem(&pgw__instances_list_map, &selected_pgw_id);
    if (!target_conf) {
        return XDP_ABORTED;
    }

    /* 
     * Update the packet headers to respect the requirements.
     * Change UDP destination and source. No changes on IP header. 
     * Copied from ChatGPT
     */
    __u32 csum = (__u32)~bpf_ntohs(udp->check);
    csum += (__u32)~bpf_ntohs(udp->source) + UDP_PORT_PGW_REG;
    csum += (__u32)~bpf_ntohs(udp->dest) + bpf_ntohs(target_conf->port);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    udp->check = bpf_htons((__u16)~csum);
    udp->source = bpf_htons(UDP_PORT_PGW_REG);
    udp->dest   = target_conf->port;

    /* Update gw stat */
    target_conf->pkt_count++;
    target_conf->last_used = bpf_ktime_get_ns();

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
