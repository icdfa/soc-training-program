# Week 8 Lab: Detecting Command and Control (C2) Traffic

## Learning Outcomes

By the end of this lab, you will be able to:

- Identify characteristics of C2 traffic including beaconing, DNS tunneling, and data exfiltration
- Analyze network traffic patterns to detect C2 communication channels
- Use Wireshark, Zeek, and statistical analysis to identify C2 activity
- Differentiate between legitimate and malicious network traffic
- Extract IOCs from C2 communications
- Create detection rules for C2 traffic
- Generate comprehensive C2 analysis reports

## Objective

Master advanced techniques for detecting Command and Control (C2) communications through network traffic analysis, pattern recognition, and behavioral analysis of compromised systems.

## Scenario

You are a Senior SOC Analyst at SecureBank Corporation. The Security Operations Center received an alert from the EDR system indicating potential malware execution on a workstation in the finance department. The incident response team has captured network traffic from the affected system over the past 24 hours. Your task is to analyze this traffic to determine if the system is communicating with a C2 server, identify the C2 infrastructure, extract IOCs, and assess the scope of the compromise.

## Prerequisites

- Wireshark installed and configured
- Basic understanding of network protocols (TCP/IP, DNS, HTTP/HTTPS)
- Familiarity with malware behavior and C2 concepts
- Python (optional, for statistical analysis)
- Zeek/Bro (optional, for advanced analysis)

## Lab Duration

Approximately 4-5 hours

---

## Part 1: Understanding C2 Communication (45 minutes)

### Step 1: What is Command and Control (C2)?

**Command and Control (C2)** is the mechanism by which an attacker maintains communication with compromised systems to:
- Send commands to infected hosts
- Receive stolen data
- Update malware
- Coordinate multi-system attacks
- Maintain persistence

### Step 2: Common C2 Techniques

| Technique | Description | Detection Difficulty |
|-----------|-------------|---------------------|
| **HTTP/HTTPS Beaconing** | Regular callbacks to C2 server | Medium |
| **DNS Tunneling** | Data exfiltration via DNS queries | High |
| **ICMP Tunneling** | Commands/data in ICMP packets | Medium |
| **Domain Generation Algorithm (DGA)** | Algorithmically generated domains | Medium |
| **Fast Flux** | Rapidly changing DNS/IP associations | High |
| **Encrypted Channels** | SSL/TLS encrypted C2 | High |
| **Social Media C2** | Commands via Twitter, Telegram, etc. | Very High |
| **Cloud Services** | Legitimate services (Dropbox, Google Drive) | Very High |

### Step 3: C2 Traffic Characteristics

**Beaconing Indicators:**
- Regular, periodic connections (e.g., every 60 seconds)
- Small, consistent packet sizes
- Connections to same destination repeatedly
- Long-duration connections with minimal data transfer

**DNS Tunneling Indicators:**
- Unusually long domain names (>50 characters)
- High entropy in subdomain names (random-looking)
- Excessive DNS queries to single domain
- Large TXT or NULL record responses
- Non-existent domain (NXDOMAIN) responses

**Data Exfiltration Indicators:**
- Large outbound data transfers
- Transfers to unusual destinations
- Encrypted uploads to unknown servers
- Transfers during off-hours

### Step 4: Download Sample PCAP Files

```bash
mkdir -p ~/soc-labs/week8-c2
cd ~/soc-labs/week8-c2
```

**Download sample C2 traffic:**

**Option 1: Use provided samples**
```bash
cp /path/to/soc-training-program/Lab-Resources/Sample-Data/c2-traffic.pcap .
```

**Option 2: Download public samples**
```bash
# Malware Traffic Analysis samples
wget https://www.malware-traffic-analysis.net/2024/01/20/2024-01-20-Emotet-infection-traffic.pcap.zip

# Or use these resources:
# - https://www.netresec.com/?page=PcapFiles
# - https://www.malware-traffic-analysis.net/
```

---

## Part 2: Detecting HTTP/HTTPS Beaconing (60 minutes)

### Exercise 1: Identify Beaconing Patterns

**Open PCAP in Wireshark:**
```bash
wireshark c2-traffic.pcap &
```

**Filter for HTTP traffic:**
```
http
```

**Look for regular patterns:**
1. **Statistics → Conversations → TCP**
2. **Sort by Packets or Duration**
3. **Look for:**
   - Same source/destination IP pairs
   - Similar packet counts
   - Long duration connections

**Identify beaconing interval:**
1. **Select a suspicious connection**
2. **Right-click → Follow → TCP Stream**
3. **Note the timestamps of requests**
4. **Calculate intervals:**
   ```
   Request 1: 10:00:00
   Request 2: 10:01:00  (60 seconds)
   Request 3: 10:02:00  (60 seconds)
   Request 4: 10:03:00  (60 seconds)
   ```

**Wireshark filter for specific IP:**
```
ip.addr == 203.0.113.50 && http
```

### Exercise 2: Analyze HTTP Beacons

**Examine HTTP requests:**
```
http.request
```

**Suspicious indicators:**

**1. Unusual User-Agents:**
```
http.user_agent
```

Look for:
- Empty User-Agent
- Outdated browsers (IE 6.0)
- Programming languages (Python-urllib, curl)
- Generic strings ("Mozilla/4.0")

**2. Suspicious URIs:**
```
http.request.uri
```

Look for:
- Base64 encoded strings
- Random-looking paths
- Consistent patterns (e.g., /api/check, /update/status)

**3. Small, consistent responses:**
```
http.response
```

C2 beacons often receive small responses (e.g., "OK", "200", commands)

**Example suspicious pattern:**
```
GET /api/beacon?id=abc123 HTTP/1.1
Host: malicious-c2.com
User-Agent: Mozilla/4.0

HTTP/1.1 200 OK
Content-Length: 2
OK
```

### Exercise 3: Statistical Analysis of Beaconing

**Export HTTP conversations to CSV:**
1. **Statistics → Conversations → TCP**
2. **Copy → CSV**
3. **Save as `tcp_conversations.csv`**

**Create Python script for beacon detection:**

```python
#!/usr/bin/env python3
"""
Beacon Detection Script
Identifies periodic network connections (beaconing)
"""

import pandas as pd
import numpy as np
from datetime import datetime

def detect_beacons(pcap_file):
    """
    Analyze PCAP for beaconing behavior
    """
    # This is a simplified example
    # In practice, use pyshark or scapy for PCAP parsing
    
    print("Analyzing for beaconing patterns...")
    
    # Example: Analyze time intervals
    timestamps = []  # Extract from PCAP
    
    if len(timestamps) < 3:
        print("Insufficient data")
        return
    
    # Calculate intervals
    intervals = []
    for i in range(1, len(timestamps)):
        interval = timestamps[i] - timestamps[i-1]
        intervals.append(interval)
    
    # Calculate statistics
    mean_interval = np.mean(intervals)
    std_interval = np.std(intervals)
    
    # Beaconing detection criteria
    # Low standard deviation indicates regular intervals
    if std_interval < (mean_interval * 0.1):  # 10% variance
        print(f"BEACON DETECTED!")
        print(f"Mean Interval: {mean_interval:.2f} seconds")
        print(f"Std Deviation: {std_interval:.2f} seconds")
        print(f"Regularity: {(1 - std_interval/mean_interval) * 100:.1f}%")
    else:
        print("No clear beaconing pattern detected")

if __name__ == "__main__":
    detect_beacons("c2-traffic.pcap")
```

**Save as `detect_beacons.py` and run:**
```bash
python3 detect_beacons.py
```

### Exercise 4: HTTPS C2 Detection

**Filter for SSL/TLS traffic:**
```
ssl || tls
```

**Analyze SSL certificates:**
1. **Expand packet details:** Secure Sockets Layer → Handshake Protocol → Certificate
2. **Check:**
   - Issuer (self-signed?)
   - Subject (matches domain?)
   - Validity period (recently issued?)
   - Subject Alternative Names

**Suspicious SSL indicators:**
- Self-signed certificates
- Certificates issued in last 7 days
- Common Name mismatch
- Unusual issuer (not trusted CA)

**Extract SSL certificate info:**
```
tls.handshake.certificate
```

**Check JA3 fingerprints (advanced):**
```bash
# Install ja3
pip3 install pyja3

# Generate JA3 hashes
ja3 c2-traffic.pcap > ja3_hashes.txt

# Check against known malware JA3 signatures
# https://github.com/salesforce/ja3
```

---

## Part 3: Detecting DNS Tunneling (60 minutes)

### Exercise 5: Identify DNS Tunneling

**Filter for DNS traffic:**
```
dns
```

**DNS tunneling characteristics:**
1. **Long domain names**
2. **High query frequency**
3. **Unusual record types (TXT, NULL)**
4. **High entropy (randomness) in subdomains**

**Find long DNS queries:**
```
dns.qry.name && (frame.len > 100)
```

**Example normal DNS:**
```
www.google.com
mail.company.com
```

**Example DNS tunneling:**
```
4a3f2e1d9c8b7a6e5f4d3c2b1a0e9d8c7b6a5f4e3d2c1b0a.malicious-tunnel.com
ZGF0YV90b19leGZpbHRyYXRl.exfil-domain.com (Base64 encoded)
```

### Exercise 6: Analyze DNS Query Patterns

**Count DNS queries per domain:**

**Using tshark (command-line Wireshark):**
```bash
tshark -r c2-traffic.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -20
```

**Expected output:**
```
    523 suspicious-domain.com
     45 google.com
     23 facebook.com
```

If one domain has significantly more queries than others, investigate further.

**Extract all DNS queries:**
```bash
tshark -r c2-traffic.pcap -Y "dns.flags.response == 0" -T fields -e frame.time -e dns.qry.name > dns_queries.txt
```

### Exercise 7: Calculate DNS Query Entropy

**Create entropy calculation script:**

```python
#!/usr/bin/env python3
"""
DNS Entropy Calculator
High entropy indicates random/encoded data (potential tunneling)
"""

import math
from collections import Counter

def calculate_entropy(string):
    """
    Calculate Shannon entropy of a string
    """
    if not string:
        return 0
    
    # Count character frequency
    counter = Counter(string)
    length = len(string)
    
    # Calculate entropy
    entropy = 0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy

def analyze_dns_queries(filename):
    """
    Analyze DNS queries for high entropy (potential tunneling)
    """
    print("Analyzing DNS queries for tunneling indicators...\n")
    
    # Read DNS queries from file
    with open(filename, 'r') as f:
        queries = [line.strip() for line in f if line.strip()]
    
    suspicious = []
    
    for query in queries:
        # Extract subdomain (before first dot)
        subdomain = query.split('.')[0]
        
        # Calculate entropy
        entropy = calculate_entropy(subdomain)
        
        # High entropy threshold (>3.5 is suspicious)
        if entropy > 3.5 and len(subdomain) > 20:
            suspicious.append((query, entropy, len(subdomain)))
    
    # Sort by entropy
    suspicious.sort(key=lambda x: x[1], reverse=True)
    
    print(f"Found {len(suspicious)} suspicious DNS queries:\n")
    print(f"{'Domain':<50} {'Entropy':<10} {'Length'}")
    print("-" * 70)
    
    for domain, entropy, length in suspicious[:10]:
        print(f"{domain:<50} {entropy:<10.2f} {length}")

if __name__ == "__main__":
    # First extract DNS queries with tshark
    import subprocess
    subprocess.run([
        "tshark", "-r", "c2-traffic.pcap",
        "-Y", "dns.flags.response == 0",
        "-T", "fields", "-e", "dns.qry.name"
    ], stdout=open("dns_queries_only.txt", "w"))
    
    analyze_dns_queries("dns_queries_only.txt")
```

**Save as `dns_entropy.py` and run:**
```bash
python3 dns_entropy.py
```

### Exercise 8: Detect DNS Tunneling with Zeek

**If you have Zeek installed:**

```bash
# Analyze PCAP with Zeek
zeek -r c2-traffic.pcap

# Check dns.log
cat dns.log | zeek-cut query | awk 'length > 50' | sort | uniq
```

**Look for:**
- Queries longer than 50 characters
- Queries with high frequency
- Queries to uncommon TLDs

---

## Part 4: Detecting Data Exfiltration (45 minutes)

### Exercise 9: Identify Large Outbound Transfers

**Find large outbound connections:**

**In Wireshark:**
1. **Statistics → Conversations → TCP**
2. **Sort by Bytes (descending)**
3. **Look for:**
   - Large amounts of data sent FROM internal IPs
   - Transfers to unusual external IPs
   - Transfers on non-standard ports

**Filter for large packets:**
```
ip.len > 1400 && ip.src == 192.168.1.100
```

**Analyze upload patterns:**
```
http.request.method == "POST"
```

**Follow TCP stream for POST requests:**
1. **Right-click on POST request**
2. **Follow → TCP Stream**
3. **Check if sensitive data is being uploaded**

### Exercise 10: Detect ICMP Tunneling

**Filter for ICMP traffic:**
```
icmp
```

**Normal ICMP:**
- Ping requests/replies
- Small payload (usually 32-64 bytes)
- Standard ICMP types (8=echo request, 0=echo reply)

**Suspicious ICMP:**
- Large payloads (>100 bytes)
- Unusual data in payload
- High frequency
- ICMP to unusual destinations

**Check ICMP payload:**
```
icmp && data.len > 100
```

**Examine payload:**
1. **Expand:** Internet Control Message Protocol → Data
2. **Look for:**
   - ASCII text
   - Base64 encoded data
   - Encrypted data (high entropy)

---

## Part 5: Advanced C2 Detection (60 minutes)

### Exercise 11: Domain Generation Algorithm (DGA) Detection

**DGA characteristics:**
- Random-looking domain names
- High entropy
- Multiple failed DNS lookups (NXDOMAIN)
- Domains not in Alexa/Majestic top lists

**Filter for NXDOMAIN responses:**
```
dns.flags.rcode == 3
```

**Extract failed DNS queries:**
```bash
tshark -r c2-traffic.pcap -Y "dns.flags.rcode == 3" -T fields -e dns.qry.name | sort | uniq > nxdomains.txt
```

**Analyze for DGA patterns:**
```bash
cat nxdomains.txt | head -20
```

**Example DGA domains:**
```
xj4k2l9m3n.com
p8q2r5t1w3.net
a9b3c7d2e6.org
```

**Create DGA detection script:**

```python
#!/usr/bin/env python3
"""
DGA Domain Detector
Identifies algorithmically generated domains
"""

import re
from collections import Counter

def is_dga(domain):
    """
    Heuristic DGA detection
    """
    # Remove TLD
    name = domain.split('.')[0]
    
    # Check length
    if len(name) < 8:
        return False
    
    # Calculate vowel ratio
    vowels = sum(1 for c in name.lower() if c in 'aeiou')
    vowel_ratio = vowels / len(name)
    
    # DGA domains often have low vowel ratio
    if vowel_ratio < 0.2:
        return True
    
    # Check for digit ratio
    digits = sum(1 for c in name if c.isdigit())
    digit_ratio = digits / len(name)
    
    if digit_ratio > 0.3:
        return True
    
    # Check for consecutive consonants
    consonant_runs = re.findall(r'[^aeiou]{4,}', name.lower())
    if consonant_runs:
        return True
    
    return False

def analyze_domains(filename):
    """
    Analyze domains for DGA patterns
    """
    with open(filename, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
    dga_domains = [d for d in domains if is_dga(d)]
    
    print(f"Analyzed {len(domains)} domains")
    print(f"Found {len(dga_domains)} potential DGA domains:\n")
    
    for domain in dga_domains[:20]:
        print(f"  {domain}")

if __name__ == "__main__":
    analyze_domains("nxdomains.txt")
```

### Exercise 12: Behavioral Analysis

**Create timeline of suspicious activity:**

1. **First C2 connection**
2. **Beaconing established**
3. **Data exfiltration**
4. **Additional malware downloads**

**Use Wireshark IO Graph:**
1. **Statistics → I/O Graph**
2. **Add filters for:**
   - HTTP traffic: `http`
   - DNS traffic: `dns`
   - Suspicious IP: `ip.addr == 203.0.113.50`
3. **Analyze patterns over time**

### Exercise 13: Extract IOCs

**Create comprehensive IOC list:**

**IP Addresses:**
```bash
tshark -r c2-traffic.pcap -Y "ip.dst != 192.168.0.0/16" -T fields -e ip.dst | sort -u > iocs_ips.txt
```

**Domains:**
```bash
tshark -r c2-traffic.pcap -Y "dns" -T fields -e dns.qry.name | sort -u > iocs_domains.txt
```

**URLs:**
```bash
tshark -r c2-traffic.pcap -Y "http.request" -T fields -e http.host -e http.request.uri | awk '{print $1$2}' | sort -u > iocs_urls.txt
```

**User-Agents:**
```bash
tshark -r c2-traffic.pcap -Y "http" -T fields -e http.user_agent | sort -u > iocs_user_agents.txt
```

---

## Part 6: Creating Detection Rules (30 minutes)

### Exercise 14: Create Suricata Rules

**HTTP Beaconing Rule:**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Possible C2 Beaconing Detected"; flow:established,to_server; content:"GET"; http_method; content:"/api/beacon"; http_uri; threshold:type both, track by_src, count 10, seconds 600; classtype:trojan-activity; sid:1000001; rev:1;)
```

**DNS Tunneling Rule:**
```
alert dns $HOME_NET any -> any 53 (msg:"Possible DNS Tunneling - Long Query"; dns_query; content:"."; pcre:"/^.{50,}/"; classtype:trojan-activity; sid:1000002; rev:1;)
```

**Suspicious User-Agent Rule:**
```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Suspicious User-Agent - Python"; flow:established,to_server; content:"Python"; http_user_agent; classtype:trojan-activity; sid:1000003; rev:1;)
```

### Exercise 15: Create Splunk Alerts

**If using Splunk:**

**Beaconing Detection:**
```spl
index=network sourcetype=pcap
| stats count by src_ip, dst_ip, dst_port
| where count > 100
| table src_ip, dst_ip, dst_port, count
```

**DNS Tunneling Detection:**
```spl
index=network sourcetype=dns
| eval query_length=len(query)
| where query_length > 50
| table _time, src_ip, query, query_length
```

---

## Deliverables

Submit the following:

1. **C2-Detection-Report.md** - Comprehensive C2 analysis report
2. **Screenshots/** - Directory containing:
   - Beaconing patterns in Wireshark
   - DNS tunneling evidence
   - Data exfiltration analysis
   - Statistical analysis results
3. **IOCs/** - Directory containing:
   - `iocs_ips.txt` - Malicious IP addresses
   - `iocs_domains.txt` - Malicious domains
   - `iocs_urls.txt` - Malicious URLs
   - `iocs_user_agents.txt` - Suspicious User-Agents
4. **Scripts/** - Directory containing:
   - `detect_beacons.py` - Beacon detection script
   - `dns_entropy.py` - DNS tunneling detection
   - `dga_detector.py` - DGA domain detection
5. **Rules/** - Directory containing:
   - Suricata/Snort rules
   - Splunk detection queries

## Report Template

```markdown
# C2 Traffic Detection Report

**Analyst:** [Your Name]  
**Date:** [Date]  
**PCAP File:** c2-traffic.pcap  
**Analysis Duration:** [Hours]

---

## Executive Summary

[2-3 sentence summary of C2 activity detected]

**Key Findings:**
- C2 Server Identified: [IP/Domain]
- C2 Technique: [Beaconing/DNS Tunneling/etc.]
- Compromised Host: [IP Address]
- Data Exfiltrated: [Amount/Type]

---

## 1. Compromised Host Identification

**Host IP:** 192.168.1.100  
**MAC Address:** [MAC]  
**First Suspicious Activity:** [Timestamp]  
**Last Suspicious Activity:** [Timestamp]

---

## 2. C2 Infrastructure

### C2 Server
**IP Address:** 203.0.113.50  
**Domain:** malicious-c2.com  
**Geolocation:** [Country]  
**ISP:** [ISP Name]  
**Reputation:** Malicious (VirusTotal: 45/70)

### C2 Communication Method
- [X] HTTP/HTTPS Beaconing
- [ ] DNS Tunneling
- [ ] ICMP Tunneling
- [ ] Other: __________

---

## 3. Beaconing Analysis

### Pattern Detected
- **Beacon Interval:** 60 seconds
- **Regularity:** 95% (very consistent)
- **Protocol:** HTTP
- **URI Pattern:** /api/beacon?id=[random]

### Evidence
**Screenshot:**
![Beaconing Pattern](screenshots/beaconing.png)

**Wireshark Filter Used:**
```
ip.addr == 192.168.1.100 && ip.addr == 203.0.113.50 && http
```

---

## 4. Data Exfiltration

### Exfiltration Detected
- **Method:** HTTP POST
- **Volume:** 2.5 MB
- **Destination:** 203.0.113.50:443
- **Timeframe:** [Start] to [End]

### Exfiltrated Data Type
[Documents / Credentials / Database / Unknown]

---

## 5. IOCs Identified

### IP Addresses
```
203.0.113.50 (C2 Server)
198.51.100.25 (Secondary C2)
```

### Domains
```
malicious-c2.com
backup-c2.net
```

### URLs
```
http://malicious-c2.com/api/beacon
https://malicious-c2.com/upload
```

### User-Agents
```
Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Python-urllib/3.8
```

---

## 6. Attack Timeline

| Time | Event |
|------|-------|
| 08:15:23 | Initial malware execution |
| 08:16:00 | First C2 beacon |
| 08:20:00 | Beaconing established (60s interval) |
| 10:30:00 | Data exfiltration begins |
| 12:45:00 | Exfiltration complete |

---

## 7. Recommendations

### Immediate Actions
1. **Isolate compromised host** (192.168.1.100)
2. **Block C2 infrastructure:**
   - IP: 203.0.113.50
   - Domain: malicious-c2.com
3. **Scan all systems** for same malware
4. **Reset credentials** for affected user

### Detection Rules
[Include Suricata/Snort rules]

### Long-term Improvements
1. Deploy IDS/IPS with C2 detection rules
2. Implement DNS filtering/monitoring
3. Deploy EDR on all endpoints
4. Enhance network segmentation

---

## Appendix

### Tools Used
- Wireshark
- tshark
- Python (custom scripts)
- Zeek (optional)

### References
- [MITRE ATT&CK: C2](https://attack.mitre.org/tactics/TA0011/)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
```

---

## Evaluation Criteria

- **C2 Detection:** Successfully identified C2 communication
- **Analysis Depth:** Thorough investigation of traffic patterns
- **IOC Extraction:** Comprehensive list of indicators
- **Detection Rules:** Effective rules for future detection
- **Documentation:** Professional, detailed report

---

## Additional Resources

- [MITRE ATT&CK: Command and Control](https://attack.mitre.org/tactics/TA0011/)
- [Palo Alto Networks: C2 Detection](https://www.paloaltonetworks.com/cyberpedia/command-and-control-explained)
- [SANS: Detecting DNS Tunneling](https://www.sans.org/reading-room/whitepapers/dns/detecting-dns-tunneling-34152)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Advanced
