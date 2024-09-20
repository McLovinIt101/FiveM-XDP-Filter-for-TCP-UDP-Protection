# FiveM XDP Filter for TCP/UDP Protection

This project is an XDP (eXpress Data Path) program designed to provide advanced protection for FiveM game servers, filtering both TCP and UDP traffic. It includes connection tracking, rate limiting, and blocklist/allowlist mechanisms to mitigate DDoS attacks and enhance server security.

## Features

- **TCP/UDP Filtering**: Inspects both UDP and TCP packets for traffic destined to the FiveM server.
- **Rate Limiting**: Limits the number of packets per second allowed to the FiveM server, protecting against flood attacks.
- **Connection Tracking**: Tracks both TCP and UDP flows using a flow key derived from IP addresses and ports.
- **SYN Flood Protection**: Drops excessive TCP SYN packets to mitigate SYN flood attacks.
- **Dynamic Blocklist/Allowlist**: Allows blocking and allowing IP addresses dynamically via BPF maps.
- **High Performance**: Runs in the kernel using XDP, which offers high-speed packet filtering before traffic reaches user space.
- **Deep Packet Inspection**: Analyzes packet payloads for known attack patterns.
- **Anomaly Detection**: Identifies unusual traffic patterns using statistical methods.
- **Machine Learning-Based Threat Detection**: Uses a trained model to detect threats based on normal and attack traffic patterns.

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

6. **Deep Packet Inspection**:
   - The filter analyzes packet payloads for known attack patterns using a hash map of known patterns.

7. **Anomaly Detection**:
   - The filter uses statistical methods to identify unusual traffic patterns and assigns anomaly scores to flows.

8. **Machine Learning-Based Threat Detection**:
   - The filter uses a trained machine learning model to detect threats based on normal and attack traffic patterns.

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

5. **Python**:
   - Install Python and necessary libraries for training the machine learning model.
   ```bash
   sudo apt-get install python3 python3-pip
   pip3 install scikit-learn numpy pandas
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

## Training and Using the Machine Learning Model

### Training the Model

1. **Collect Data**:
   - Collect normal and attack traffic data. Save the data in CSV format with appropriate labels.

2. **Train the Model**:
   - Use the following Python script to train a machine learning model using scikit-learn:

   ```python
   import pandas as pd
   from sklearn.model_selection import train_test_split
   from sklearn.ensemble import RandomForestClassifier
   from sklearn.metrics import accuracy_score
   import joblib

   # Load data
   data = pd.read_csv('traffic_data.csv')
   X = data.drop('label', axis=1)
   y = data['label']

   # Split data into training and testing sets
   X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

   # Train the model
   model = RandomForestClassifier(n_estimators=100, random_state=42)
   model.fit(X_train, y_train)

   # Evaluate the model
   y_pred = model.predict(X_test)
   print(f'Accuracy: {accuracy_score(y_test, y_pred)}')

   # Save the model
   joblib.dump(model, 'ml_model.joblib')
   ```

3. **Deploy the Model**:
   - Convert the trained model to a format that can be used in the XDP program. This may involve exporting the model to a C header file or using a custom format.

### Using the Model in the XDP Program

1. **Load the Model**:
   - Load the trained model into the XDP program. This may involve reading the model from a file or embedding it directly in the code.

2. **Feature Extraction**:
   - Extract features from incoming packets and use the model to predict whether the packet is a threat.

3. **Threat Detection**:
   - Use the model's predictions to drop packets flagged as threats.

## Debugging

You can use the bpf_trace_printk() function in the XDP program to print debug messages to the kernel log. This is useful for debugging packet flows and understanding how your filter is performing.

To view the kernel log:
```bash
sudo dmesg | tail
```
