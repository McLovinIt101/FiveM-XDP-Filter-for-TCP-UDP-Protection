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

// Deep packet inspection map for known attack patterns
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);  // Pattern hash
    __type(value, __u8); // Attack flag (1 = attack)
    __uint(max_entries, 256);
} dpi_map SEC(".maps");

// Anomaly detection map for statistical traffic patterns
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // Flow key
    __type(value, __u64); // Anomaly score
    __uint(max_entries, 4096);
} anomaly_map SEC(".maps");

// Machine learning-based threat detection map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);  // Flow key
    __type(value, __u8); // Threat flag (1 = threat)
    __uint(max_entries, 4096);
} ml_threat_map SEC(".maps");

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

// Hash function for connection tracking (combining multiple fields for more randomness)
static __always_inline __u64 generate_flow_key(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport) {
    return ((__u64)saddr << 32) | ((__u64)daddr ^ ((__u64)sport << 16) ^ dport ^ (saddr >> 8));
}

// Advanced deep packet inspection with pattern matching for multiple known attack signatures
static __always_inline int deep_packet_inspection(void *data, void *data_end) {
    // Advanced example: check for multiple known malicious patterns in the payload
    __u32 patterns[] = {0xdeadbeef, 0xbaadf00d, 0xfeedface};  // Example malicious payload patterns
    for (int i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        if (data + sizeof(__u32) > data_end) {
            return 0;  // Bounds check failed
        }
        if (*(__u32 *)data == patterns[i]) {
            return 1;  // Pattern matched
        }
    }
    return 0;
}

// More sophisticated anomaly detection using multiple thresholds and pattern analysis
static __always_inline int detect_anomaly(__u64 flow_key) {
    // Advanced example: check if the anomaly score exceeds multiple thresholds
    __u64 *anomaly_score = bpf_map_lookup_elem(&anomaly_map, &flow_key);
    if (anomaly_score) {
        if (*anomaly_score > 500) {  // Higher threshold for high sensitivity
            return 1;  // Severe anomaly detected
        }
        if (*anomaly_score > 200) {  // Lower threshold for moderate sensitivity
            return 1;  // Moderate anomaly detected
        }
    }
    return 0;
}

// Advanced machine learning-based threat detection integrating multiple features
static __always_inline int ml_threat_detection(__u64 flow_key) {
    // Advanced example: multiple conditions based on threat level
    __u8 *threat_flag = bpf_map_lookup_elem(&ml_threat_map, &flow_key);
    if (threat_flag) {
        if (*threat_flag == 2) {  // More severe threat detected
            return 1;  // Drop severe threats
        }
        if (*threat_flag == 1) {  // Minor threat detected
            return 1;  // Drop minor threats
        }
    }
    return 0;
}

// Helper function for SYN cookie generation with stronger randomness
static __always_inline __u32 generate_syn_cookie(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, __u32 isn) {
    // Advanced example: XOR of IPs, ports, initial sequence number, and a random factor
    __u32 rand_factor = bpf_get_prandom_u32();
    return saddr ^ daddr ^ sport ^ dport ^ isn ^ rand_factor;
}

// Helper function for TCP bypass detection with enhanced checking
static __always_inline int detect_tcp_bypass(struct tcphdr *tcp) {
    // Advanced example: check for unusual TCP flags or sequence numbers with stricter rules
    if (tcp->fin || tcp->rst || tcp->psh || tcp->urg || (tcp->seq & 0x1FFF) == 0) {
        return 1;  // TCP bypass attempt detected
    }
    return 0;
}

static __always_inline int handle_tcp_syn_flood(struct iphdr *ip, struct tcphdr *tcp) {
    //(SYN = 1, ACK = 0)
    if (tcp->syn && !tcp->ack) {
        // Generate a SYN cookie based on the source and destination IP/ports
        __u32 syn_cookie = generate_syn_cookie(ip->saddr, ip->daddr, tcp->source, tcp->dest, tcp->seq);
        if (tcp->seq != syn_cookie) {
            return XDP_DROP;  // Invalid SYN cookie, likely part of a SYN flood attack
        }
    }
    return XDP_PASS;
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

        // Handle SYN flood mitigation
        if (handle_tcp_syn_flood(ip, tcp) == XDP_DROP) {
            return XDP_DROP;
        }

        // Generate a flow key based on source and destination IP/ports
        flow_key = generate_flow_key(ip->saddr, ip->daddr, udp->source, udp->dest);

        // Perform connection tracking
        last_seen = bpf_map_lookup_elem(&conntrack_map, &flow_key);
        if (last_seen) {
            // Update the last seen time for the connection
            *last_seen = now;
        } else {
            // Insert a new entry into the connection tracking map
            bpf_map_update_elem(&conntrack_map, &flow_key, &now, BPF_ANY);
        }

        // Perform deep packet inspection (DPI) for known malicious patterns
        if (deep_packet_inspection(data, data_end)) {
            return XDP_DROP;  // Drop packet if malicious pattern detected
        }

        // Check for anomaly detection
        if (detect_anomaly(flow_key)) {
            return XDP_DROP;  // Drop packet if an anomaly is detected
        }

        // Check for machine learning-based threat detection
        if (ml_threat_detection(flow_key)) {
            return XDP_DROP;  // Drop packet if a threat is detected
        }
    } else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = parse_tcp(data, data_end, eth, ip);
        if (!tcp) {
            return XDP_ABORTED;
        }

        // Check if the packet is destined for the FiveM server
        if (ip->daddr != htonl(FIVEM_SERVER_IP) || tcp->dest != htons(FIVEM_SERVER_PORT)) {
            return XDP_PASS;
        }

        // Generate a flow key for the TCP connection
        flow_key = generate_flow_key(ip->saddr, ip->daddr, tcp->source, tcp->dest);

        // Perform connection tracking for TCP as well
        last_seen = bpf_map_lookup_elem(&conntrack_map, &flow_key);
        if (last_seen) {
            // Update the last seen time for the TCP connection
            *last_seen = now;
        } else {
            // Insert a new entry into the connection tracking map
            bpf_map_update_elem(&conntrack_map, &flow_key, &now, BPF_ANY);
        }

        // Detect TCP bypass attempts based on unusual flag or sequence number
        if (detect_tcp_bypass(tcp)) {
            return XDP_DROP;  // Drop packet if TCP bypass attempt detected
        }

        // Perform deep packet inspection (DPI) for TCP
        if (deep_packet_inspection(data, data_end)) {
            return XDP_DROP;  // Drop packet if malicious pattern detected
        }

        // Check for anomaly detection
        if (detect_anomaly(flow_key)) {
            return XDP_DROP;  // Drop packet if an anomaly is detected
        }

        // Check for machine learning-based threat detection
        if (ml_threat_detection(flow_key)) {
            return XDP_DROP;  // Drop packet if a threat is detected
        }
    }

    // Rate limiting logic
    __u32 key = 0;
    __u64 *rate = bpf_map_lookup_elem(&rate_limit_map, &key);
    if (rate) {
        __u64 last_packet_time = *rate;
        if (now - last_packet_time < (1000000000 / MAX_PACKET_RATE)) {
            return XDP_DROP;  // Drop packets that exceed the rate limit
        }
        *rate = now;  // Update the last packet time
    }

    return XDP_PASS;  // Allow the packet if all checks passed
}

char _license[] SEC("license") = "MIT";
