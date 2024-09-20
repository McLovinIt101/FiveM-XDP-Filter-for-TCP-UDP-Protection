#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

#define FIVEM_SERVER_IP 0x7F000001  // 127.0.0.1 in hexadecimal (loopback)
#define FIVEM_SERVER_PORT 30120     // FiveM server port
#define MAX_PACKET_RATE 13000       // Max packets per second for rate-limiting
#define BLOCKED_IP_LIST_MAX 128     // Max number of IPs in blocklist

// Per-CPU map for rate limiting per CPU core
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} rate_limit_map SEC(".maps");

// Blocklist map (dynamic, can be updated by user-space)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP address
    __type(value, __u8); // Block flag (1 = blocked)
    __uint(max_entries, BLOCKED_IP_LIST_MAX);
} blocklist_map SEC(".maps");

// Allowlist map for trusted IP addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // IP address
    __type(value, __u8); // Allow flag (1 = allowed)
    __uint(max_entries, BLOCKED_IP_LIST_MAX);
} allowlist_map SEC(".maps");

// Connection tracking map (to track stateful UDP/TCP connections)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64);  // Flow key (combination of src/dst IP, ports)
    __type(value, __u64); // Last seen timestamp
    __uint(max_entries, 4096); // Max number of tracked connections
} conntrack_map SEC(".maps");

// Helper function for parsing UDP
static __always_inline struct udphdr *parse_udp(void *data, void *data_end, struct ethhdr *eth, struct iphdr *ip) {
    struct udphdr *udp = (struct udphdr *)((__u8 *)ip + sizeof(struct iphdr));
    if ((void *)(udp + 1) > data_end) {
        return NULL;  // Bounds check failed
    }
    return udp;
}

// Helper function for parsing TCP
static __always_inline struct tcphdr *parse_tcp(void *data, void *data_end, struct ethhdr *eth, struct iphdr *ip) {
    struct tcphdr *tcp = (struct tcphdr *)((__u8 *)ip + sizeof(struct iphdr));
    if ((void *)(tcp + 1) > data_end) {
        return NULL;  // Bounds check failed
    }
    return tcp;
}

// Hash function for connection tracking (simple XOR of IP and port)
static __always_inline __u64 generate_flow_key(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr ^ ((__u64)sport << 16) ^ dport);
}

SEC("xdp_program")
int fivem_xdp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_ABORTED;
    }

    // Only process IP packets
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)((__u8 *)eth + sizeof(struct ethhdr));
    if ((void *)(ip + 1) > data_end) {
        return XDP_ABORTED;
    }

    // Check if the source IP is blocked
    __u8 *blocked = bpf_map_lookup_elem(&blocklist_map, &ip->saddr);
    if (blocked && *blocked == 1) {
        return XDP_DROP;  // Drop packet from blocked IP
    }

    // Check if the source IP is allowed (bypass filtering)
    __u8 *allowed = bpf_map_lookup_elem(&allowlist_map, &ip->saddr);
    if (allowed && *allowed == 1) {
        return XDP_PASS;  // Allow packet from trusted IP
    }

    // UDP or TCP handling
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_seen;
    __u64 flow_key;

    if (ip->protocol == IPPROTO_UDP) {
        // Parse UDP header with bounds checking
        struct udphdr *udp = parse_udp(data, data_end, eth, ip);
        if (!udp) {
            return XDP_ABORTED;
        }

        // Check if the packet is destined for the FiveM server
        if (ip->daddr != htonl(FIVEM_SERVER_IP) || udp->dest != htons(FIVEM_SERVER_PORT)) {
            return XDP_PASS;  // Let other packets through
        }

        // Generate flow key and track the connection
        flow_key = generate_flow_key(ip->saddr, ip->daddr, udp->source, udp->dest);
    } 
    else if (ip->protocol == IPPROTO_TCP) {
        // Parse TCP header with bounds checking
        struct tcphdr *tcp = parse_tcp(data, data_end, eth, ip);
        if (!tcp) {
            return XDP_ABORTED;
        }

        // Check if the packet is destined for the FiveM server
        if (ip->daddr != htonl(FIVEM_SERVER_IP) || tcp->dest != htons(FIVEM_SERVER_PORT)) {
            return XDP_PASS;  // Let other packets through
        }

        // Generate flow key and track the connection
        flow_key = generate_flow_key(ip->saddr, ip->daddr, tcp->source, tcp->dest);

        // TCP-specific handling (e.g., SYN/ACK filtering)
        if (tcp->syn) {
            // Drop SYN flood attempts (you can further refine this)
            return XDP_DROP;
        }
    } 
    else {
        return XDP_PASS;  // Allow non-UDP, non-TCP traffic
    }

    // Connection tracking: lookup last seen timestamp for this flow
    last_seen = bpf_map_lookup_elem(&conntrack_map, &flow_key);
    if (!last_seen) {
        // New connection, track it
        bpf_map_update_elem(&conntrack_map, &flow_key, &now, BPF_ANY);
    } else {
        // Update the timestamp for this flow (for further tracking or connection timeouts)
        bpf_map_update_elem(&conntrack_map, &flow_key, &now, BPF_ANY);
    }

    // Rate-limiting logic
    __u32 rate_limit_key = 0;
    __u64 *rate_limit_value = bpf_map_lookup_elem(&rate_limit_map, &rate_limit_key);
    if (!rate_limit_value) {
        return XDP_ABORTED;
    }

    __u64 last_packet_time = *rate_limit_value;
    if (now - last_packet_time < (1000000000 / MAX_PACKET_RATE)) {
        return XDP_DROP;  // Drop packets that exceed the rate limit
    }

    // Update rate-limit map with current time
    bpf_map_update_elem(&rate_limit_map, &rate_limit_key, &now, BPF_ANY);

    // Allow the packet through
    return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
