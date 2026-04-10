# Advanced Subnet Sweep Scanner

A Python-based subnet scanner that uses multiple detection techniques to discover alive hosts, even when ICMP ping is blocked.

## Features

- **Multiple Detection Methods:**
  - ICMP Ping
  - TCP Port Scanning (14 common ports)
  - ARP Table Checking (for local network)

- **Concurrent Scanning:** Multi-threaded for fast scanning
- **Organized Output:** Subnet-wise results saved in separate files
- **Detailed Logging:** Shows detection methods used for each host
- **IP-Only Export:** Generates clean IP lists for further processing

## Common Ports Scanned

```
80 (HTTP), 443 (HTTPS), 22 (SSH), 445 (SMB), 139 (NetBIOS)
3389 (RDP), 21 (FTP), 23 (Telnet), 25 (SMTP), 53 (DNS)
135 (RPC), 3306 (MySQL), 5900 (VNC), 8080 (HTTP-Alt)
```

## Installation

```bash
# No external dependencies required - uses Python standard library
chmod +x advanced_subnet_sweep.py
```

## Usage

### Basic Usage

```bash
python3 advanced_subnet_sweep.py -f subnets.txt
```

### Advanced Options

```bash
# Custom output directory
python3 advanced_subnet_sweep.py -f subnets.txt -o my_results

# Increase threads for faster scanning
python3 advanced_subnet_sweep.py -f subnets.txt -t 100

# Full example
python3 advanced_subnet_sweep.py -f subnets.txt -o scan_results -t 75
```

## Subnets File Format

Create a text file with one subnet per line:

```
# Example subnets.txt
192.168.1.0/24
10.0.0.0/16
172.16.0.0/24
192.168.100.50/32
```

## Output Files

For each subnet, the script creates two files:

### 1. Detailed Results File
```
192.168.1.0_24_20241127_143022.txt
```
Contains:
- Scan metadata
- IP addresses with detection methods
- Port information

Example content:
```
Subnet Scan Results
============================================================
Subnet: 192.168.1.0/24
Scan Date: 2024-11-27 14:30:22
Total Alive Hosts: 5
============================================================

IP Address              Detection Methods
------------------------------------------------------------
192.168.1.1             ICMP, TCP, Ports:80,443,22
192.168.1.10            TCP, Ports:445,139
192.168.1.50            ICMP, ARP
```

### 2. IP-Only File
```
192.168.1.0_24_20241127_143022_ips_only.txt
```
Contains only IP addresses (one per line) for easy import into other tools:
```
192.168.1.1
192.168.1.10
192.168.1.50
```

## Command-Line Options

```
-f, --file FILE       File containing list of subnets (required)
-o, --output DIR      Output directory for results (default: scan_results)
-t, --threads NUM     Number of concurrent threads (default: 50)
-h, --help           Show help message
```

## Performance Tips

1. **Thread Count:**
   - Default: 50 threads
   - Increase for faster scanning: `-t 100`
   - Don't exceed 200 on most systems

2. **Network Considerations:**
   - Local networks: Use higher thread counts
   - Remote networks: Use lower thread counts to avoid rate limiting
   - VPN connections: Reduce threads to 20-30

3. **Large Subnets:**
   - /16 networks = 65,534 hosts (may take 10-30 minutes)
   - /24 networks = 254 hosts (typically 30 seconds - 2 minutes)

## Use Cases

### 1. Network Discovery
```bash
# Discover all active hosts in corporate network
python3 advanced_subnet_sweep.py -f corporate_subnets.txt -o discovery_results
```

### 2. Vulnerability Assessment Preparation
```bash
# Get alive hosts before running Nmap or vulnerability scanners
python3 advanced_subnet_sweep.py -f target_networks.txt -t 100

# Use the _ips_only.txt files with other tools
nmap -iL scan_results/192.168.1.0_24_*_ips_only.txt -sV
```

### 3. Network Monitoring
```bash
# Regular scans to track network changes
python3 advanced_subnet_sweep.py -f monitored_subnets.txt -o "scans/$(date +%Y%m%d)"
```

### 4. Penetration Testing
```bash
# Initial reconnaissance phase
python3 advanced_subnet_sweep.py -f scope.txt -o pentest_results

# Use results for further enumeration
while read ip; do 
    echo "Scanning $ip..."
    nmap -sC -sV -oA "detailed_$ip" $ip
done < scan_results/*_ips_only.txt
```

## Detection Method Explanations

### ICMP
- Standard ping probe
- May be blocked by firewalls
- Fast and efficient when allowed

### TCP
- Attempts connection to common ports
- Works even when ICMP is blocked
- Detects services running on hosts

### ARP
- Checks local ARP cache
- Only works for same subnet
- Very reliable for local network

## Troubleshooting

### No hosts found
1. Check if you have network connectivity
2. Verify subnet notation is correct
3. Try increasing timeout values (edit script)
4. Check firewall rules

### Permission errors
```bash
# Some operations may require root privileges
sudo python3 advanced_subnet_sweep.py -f subnets.txt
```

### Slow scanning
1. Increase thread count: `-t 100`
2. Reduce common ports list in script
3. Remove ARP checks if not on local network

## Integration Examples

### With Nmap
```bash
# Get alive hosts first
python3 advanced_subnet_sweep.py -f subnets.txt

# Full port scan on alive hosts
nmap -p- -iL scan_results/*_ips_only.txt -oA full_scan
```

### With Masscan
```bash
# High-speed follow-up scanning
masscan -iL scan_results/*_ips_only.txt -p0-65535 --rate 10000
```

### With Custom Tools
```python
# Read results in Python
with open('scan_results/192.168.1.0_24_ips_only.txt') as f:
    alive_hosts = [line.strip() for line in f]

# Process each host
for host in alive_hosts:
    # Your custom enumeration here
    pass
```

## Security Considerations

- Always get proper authorization before scanning
- Be aware of rate limiting and IDS/IPS
- Some networks may flag aggressive scanning
- Use appropriate thread counts for the environment
- Consider impact on network performance

## Advanced Customization

Edit the script to:
- Add more ports: Modify `self.common_ports` list
- Adjust timeouts: Change timeout values in check functions
- Add new detection methods: Extend `check_host_alive()` method
- Custom output formats: Modify `save_results()` method

## License

Free to use for security assessments and network administration.

## Disclaimer

This tool is for authorized network security assessments only. 
Unauthorized network scanning may be illegal. Always obtain proper 
authorization before scanning networks you don't own or administer.
