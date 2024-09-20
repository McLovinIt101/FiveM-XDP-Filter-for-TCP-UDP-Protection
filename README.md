# FiveM XDP Filter for TCP/UDP Protection

This project is an XDP (eXpress Data Path) program designed to provide advanced protection for FiveM game servers, filtering both TCP and UDP traffic. It includes connection tracking, rate limiting, and blocklist/allowlist mechanisms to mitigate DDoS attacks and enhance server security.

## Features

- **TCP/UDP Filtering**: Inspects both UDP and TCP packets for traffic destined to the FiveM server.
- **Rate Limiting**: Limits the number of packets per second allowed to the FiveM server, protecting against flood attacks.
- **Connection Tracking**: Tracks both TCP and UDP flows using a flow key derived from IP addresses and ports.
- **SYN Flood Protection**: Drops excessive TCP SYN packets to mitigate SYN flood attacks.
- **Dynamic Blocklist/Allowlist**: Allows blocking and allowing IP addresses dynamically via BPF maps.
- **High Performance**: Runs in the kernel using XDP, which offers high-speed packet filtering before traffic reaches user space.

## How It Works

1. **Packet Inspection**:
   - The filter parses Ethernet, IP, TCP, and UDP headers to ensure proper bounds and checks for target IP and port (FiveM server).
   
2. **Rate Limiting**:
   - A per-CPU rate limiting mechanism ensures that no more than a defined number of packets per second are allowed to the server.
   
3. **Blocklist/Allowlist**:
   - The filter checks incoming packets against a dynamically updated blocklist/allowlist of IP addresses. Blocked IP addresses will have their packets dropped, while allowed IP addresses bypass all filters.

4. **Connection Tracking**:
   - The filter tracks active UDP and TCP connections using an LRU hash map to maintain flow state and enhance stateful filtering capabilities.
   
5. **SYN Flood Protection**:
   - The filter detects and drops TCP SYN packets to prevent SYN flood attacks on the server, a common DDoS vector.

## Installation Guide

### Prerequisites

1. **Kernel with XDP Support**:
   - Ensure your Linux kernel supports XDP (`iproute2` tools with XDP support is a requirement).
   - Kernel versions 4.18+ are recommended.

2. **BPF Compiler**:
   - Install the `clang` and `llvm` tools to compile the XDP program.

3. **iproute2**:
   - Install `iproute2` utilities to manage XDP programs.

```bash
sudo apt-get update
sudo apt-get install clang llvm libelf-dev iproute2
```

4. **libbpf**:
   - You will also need the libbpf library to handle BPF map interactions.
   ```bash
   sudo apt-get install libbpf-dev
   ```

### Building and Loading the XDP Filter

1. Clone the Repository:
   ```bash
   git clone https://github.com/McLovinIt101/FiveM-XDP-Filter-for-TCP-UDP-Protection.git
   cd FiveM-XDP-Filter-for-TCP-UDP-Protection
   ```

2. Compile the XDP Program:
   - You can compile the XDP filter using clang and llvm. Ensure you target the BPF architecture.
   ```bash
   clang -O2 -target bpf -c fivem_xdp.c -o fivem_xdp.o
   ```

3. Load the XDP Program:
   - Use the ip utility to attach the XDP program to a network interface (replace eth0 with the appropriate network interface on your machine).
   ```bash
   sudo ip link set dev eth0 xdp obj fivem_xdp.o sec xdp_program
   ```
   - This will load the XDP program and start filtering packets on the specified interface.

4. Verifying XDP Program Status:
   - You can verify that the XDP program is successfully attached using:
   ```bash
   ip -details link show dev eth0
   ```
   - Look for the xdp section in the output to confirm that the program is running.

### Managing the Blocklist and Allowlist

The blocklist and allowlist are managed through BPF maps that can be accessed from user space. You can dynamically add or remove IP addresses from these lists using tools like bpftool.

1. Adding IP to Blocklist:
   ```bash
   bpftool map update id <map_id> key <ip_address_in_hex> value 1
   ```

2. Adding IP to Allowlist:
   ```bash
   bpftool map update id <map_id> key <ip_address_in_hex> value 1
   ```

3. Deleting IP from Blocklist/Allowlist:
   ```bash
   bpftool map delete id <map_id> key <ip_address_in_hex>
   ```

   - To find the map ID, run:
   ```bash
   bpftool map show
   ```

### Unloading the XDP Program

To unload the XDP program from the interface, run:
```bash
sudo ip link set dev eth0 xdp off
```
This will remove the XDP program from the specified interface.

## Configuration

- **FIVEM_SERVER_IP**: The IP address of your FiveM server (default is 127.0.0.1 for local testing).
- **FIVEM_SERVER_PORT**: The UDP and TCP port number your FiveM server uses (default is 30120).
- **MAX_PACKET_RATE**: The maximum number of packets per second allowed from each connection (default is 13000).
- **BLOCKED_IP_LIST_MAX**: The maximum number of entries in the blocklist/allowlist (default is 128).

You can modify these parameters directly in the fivem_xdp.c file and recompile the program.

## Debugging

You can use the bpf_trace_printk() function in the XDP program to print debug messages to the kernel log. This is useful for debugging packet flows and understanding how your filter is performing.

To view the kernel log:
```bash
sudo dmesg | tail
```