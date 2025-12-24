# Week 5 Lab: Packet Analysis with Wireshark

## Learning Outcomes

By the end of this lab, you will be able to:

- Navigate the Wireshark interface and apply display filters effectively
- Identify and analyze common network protocols (DNS, HTTP, HTTPS, TCP, UDP)
- Reconstruct and extract files from network traffic captures
- Follow TCP streams to understand communication flows
- Identify suspicious network activity and indicators of compromise (IOCs)
- Export objects and analyze malicious payloads
- Create professional packet analysis reports

## Objective

Master Wireshark for network traffic analysis to detect malicious activity, extract IOCs, and investigate security incidents through hands-on packet capture analysis.

## Scenario

You are a SOC analyst at TechCorp investigating a security incident. A user's workstation triggered multiple security alerts, and the network team captured traffic from the affected system. You need to analyze the packet capture (PCAP) file to determine what happened, identify any malicious activity, extract IOCs, and assess the scope of the compromise.

## Prerequisites

- Wireshark installed (latest version)
- Basic understanding of TCP/IP networking
- Sample PCAP files (provided or downloadable)
- Text editor for documentation

## Lab Duration

Approximately 3-4 hours

---

## Part 1: Wireshark Installation and Interface (30 minutes)

### Step 1: Install Wireshark

**Windows:**
1. Download from: https://www.wireshark.org/download.html
2. Run the installer
3. Install with default options
4. Install Npcap when prompted (required for packet capture)

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install wireshark
sudo usermod -aG wireshark $USER
# Log out and back in for group changes to take effect
```

**macOS:**
```bash
brew install wireshark
# Or download DMG from wireshark.org
```

### Step 2: Understanding the Wireshark Interface

**Launch Wireshark** and familiarize yourself with the interface:

**Main Components:**

1. **Menu Bar** - File operations, capture controls, analysis tools
2. **Main Toolbar** - Quick access to common functions
3. **Filter Toolbar** - Apply display filters to captured packets
4. **Packet List Pane** - Shows all captured packets
5. **Packet Details Pane** - Detailed protocol information for selected packet
6. **Packet Bytes Pane** - Raw hexadecimal and ASCII data
7. **Status Bar** - Capture statistics and information

### Step 3: Download Sample PCAP Files

For this lab, we'll use multiple PCAP files:

**Option 1: Use provided samples**
```bash
# From the course repository
cd ~/soc-labs/week5
cp /path/to/soc-training-program/Lab-Resources/Sample-Data/*.pcap .
```

**Option 2: Download public samples**
```bash
# Malware traffic analysis samples
wget https://www.malware-traffic-analysis.net/2024/01/15/2024-01-15-traffic-analysis-exercise.pcap.zip

# Or use these public repositories:
# - https://www.netresec.com/?page=PcapFiles
# - https://www.malware-traffic-analysis.net/training-exercises.html
```

**For this lab, we'll analyze:** `suspicious-traffic.pcap`

---

## Part 2: Basic Wireshark Operations (45 minutes)

### Exercise 1: Open and Explore a PCAP File

1. **Open Wireshark**
2. **File → Open** (or Ctrl+O)
3. **Select:** `suspicious-traffic.pcap`

**Initial Observations:**
- How many packets are in the capture?
- What is the time span of the capture?
- What protocols do you see?

**View capture statistics:**
- **Statistics → Capture File Properties**

**Note:**
- File size
- First packet time
- Last packet time
- Total packets
- Average packets/sec

### Exercise 2: Navigate the Packet List

**Click on different packets** and observe:
- **Packet List Pane:** Summary information
- **Packet Details Pane:** Expandable protocol layers
- **Packet Bytes Pane:** Raw data

**Protocol Layers (OSI Model):**
```
Frame (Layer 1-2: Physical/Data Link)
└── Ethernet II
    └── Internet Protocol (Layer 3: Network)
        └── Transmission Control Protocol (Layer 4: Transport)
            └── Hypertext Transfer Protocol (Layer 7: Application)
```

### Exercise 3: Basic Display Filters

Display filters show only packets matching specific criteria.

**Common Display Filters:**

| Filter | Description |
|--------|-------------|
| `ip.addr == 192.168.1.100` | Show packets to/from this IP |
| `ip.src == 192.168.1.100` | Show packets from this IP |
| `ip.dst == 192.168.1.100` | Show packets to this IP |
| `tcp.port == 80` | Show HTTP traffic |
| `tcp.port == 443` | Show HTTPS traffic |
| `dns` | Show DNS traffic |
| `http` | Show HTTP traffic |
| `http.request` | Show HTTP requests only |
| `tcp.flags.syn == 1` | Show TCP SYN packets |
| `frame.time >= "2024-01-01 00:00:00"` | Time-based filter |

**Try these filters:**

1. **Show all HTTP traffic:**
   ```
   http
   ```

2. **Show DNS queries:**
   ```
   dns.flags.response == 0
   ```

3. **Show traffic to/from specific IP:**
   ```
   ip.addr == 192.168.1.100
   ```

4. **Combine filters with AND:**
   ```
   ip.src == 192.168.1.100 && tcp.port == 80
   ```

5. **Combine filters with OR:**
   ```
   tcp.port == 80 || tcp.port == 443
   ```

**Filter Syntax:**
- `==` equals
- `!=` not equals
- `&&` AND
- `||` OR
- `!` NOT

---

## Part 3: Protocol Analysis (60 minutes)

### Exercise 4: DNS Analysis

**Question:** What domain names were queried?

**Filter for DNS queries:**
```
dns.flags.response == 0
```

**Analyze DNS traffic:**
1. Look at the **Packet Details Pane**
2. Expand **Domain Name System (query)**
3. Find **Queries → Name**

**Extract all queried domains:**
- **Statistics → DNS**
- Review the DNS statistics

**Identify suspicious domains:**
- Look for:
  - Random-looking domain names (DGA - Domain Generation Algorithm)
  - Unusual TLDs (.tk, .xyz, .top)
  - Typosquatting domains
  - Recently registered domains

**Example suspicious patterns:**
```
xj4k2l9m3n.com
update-windows-security.tk
microsfot.com (typosquatting)
```

### Exercise 5: HTTP Analysis

**Question:** What HTTP requests were made?

**Filter for HTTP requests:**
```
http.request
```

**Analyze HTTP requests:**
1. Look for the **Request Method** (GET, POST, etc.)
2. Check the **Host** header
3. Examine the **User-Agent**
4. Review the **Request URI**

**Extract HTTP hosts:**
```
http.host
```

**Right-click on a packet → Follow → HTTP Stream** to see the full conversation.

**Identify suspicious HTTP activity:**
- Unusual User-Agents
- Requests to IP addresses instead of domains
- Suspicious file downloads (.exe, .dll, .scr)
- Base64 encoded data in URLs
- POST requests with sensitive data

### Exercise 6: TCP Stream Analysis

**Follow TCP streams** to reconstruct conversations:

1. **Find an HTTP packet**
2. **Right-click → Follow → TCP Stream**
3. **Analyze the conversation**

**TCP Stream window shows:**
- **Red text:** Data from client to server
- **Blue text:** Data from server to client

**Use cases:**
- Reconstruct HTTP conversations
- Extract credentials from cleartext protocols
- Analyze malware C2 communication
- View file transfers

**Example: Extract credentials from HTTP POST**
```
Filter: http.request.method == "POST"
Follow TCP stream
Look for: username, password, credentials
```

### Exercise 7: File Extraction

**Extract files transferred over HTTP:**

1. **File → Export Objects → HTTP**
2. **Review the list of objects**
3. **Select suspicious files**
4. **Save them for analysis**

**Look for:**
- Executable files (.exe, .dll, .scr)
- Office documents with macros (.doc, .xls)
- Archive files (.zip, .rar)
- Scripts (.ps1, .bat, .vbs)

**After extraction:**
```bash
# Calculate file hash
sha256sum downloaded_file.exe

# Check on VirusTotal
# https://www.virustotal.com/
```

---

## Part 4: Detecting Malicious Activity (60 minutes)

### Exercise 8: Identify the User's Computer

**Question:** What is the IP address of the user's computer?

**Method 1: Look for private IP addresses**
```
ip.src == 192.168.0.0/16 || ip.src == 10.0.0.0/8 || ip.src == 172.16.0.0/12
```

**Method 2: Find DHCP traffic**
```
dhcp
```
Look for DHCP Request/Acknowledgment

**Method 3: Look for HTTP requests**
```
http.request
```
The source IP of HTTP requests is likely the user's computer.

**Document:** The user's IP address (e.g., 192.168.1.100)

### Exercise 9: Identify DNS Server

**Question:** What DNS server was used?

**Filter:**
```
dns
```

**Look at DNS queries:**
- **Source IP** = Client (user's computer)
- **Destination IP** = DNS server

**Common DNS servers:**
- 8.8.8.8 (Google)
- 1.1.1.1 (Cloudflare)
- 192.168.1.1 (Local router)

### Exercise 10: Identify Malicious Domains

**Question:** What suspicious domains were accessed?

**Filter for DNS queries:**
```
dns.flags.response == 0
```

**Analyze each domain:**
1. **Copy the domain name**
2. **Check reputation:**
   - VirusTotal: https://www.virustotal.com/
   - URLhaus: https://urlhaus.abuse.ch/
   - AbuseIPDB: https://www.abuseipdb.com/

**Indicators of malicious domains:**
- Recently registered (check WHOIS)
- Low reputation score
- Associated with malware campaigns
- DGA patterns

### Exercise 11: Identify C2 Communication

**Command and Control (C2) indicators:**

**1. Beaconing behavior:**
```
# Look for regular, periodic connections
Statistics → Conversations → TCP
Sort by Packets or Bytes
Look for:
- Regular intervals (e.g., every 60 seconds)
- Small packet sizes
- Long duration connections
```

**2. Unusual ports:**
```
tcp.port != 80 && tcp.port != 443 && tcp.port != 53
```

**3. Suspicious User-Agents:**
```
http.user_agent
```

Look for:
- Empty or unusual User-Agents
- Programming language identifiers (Python, curl, etc.)
- Outdated browser versions

**4. Encrypted traffic to unusual destinations:**
```
ssl
```

Check SSL certificates:
- Self-signed certificates
- Mismatched common names
- Recently issued certificates

### Exercise 12: Detect Data Exfiltration

**Look for large outbound transfers:**

**Method 1: Conversations analysis**
```
Statistics → Conversations → TCP
Sort by Bytes (descending)
```

Look for:
- Large amounts of data sent TO external IPs
- Unusual protocols
- Connections to cloud storage services

**Method 2: Filter for large packets**
```
ip.len > 1000
```

**Method 3: Look for POST requests**
```
http.request.method == "POST"
```

Follow TCP stream to see what data was sent.

---

## Part 5: Advanced Analysis Techniques (45 minutes)

### Exercise 13: Protocol Hierarchy Statistics

**Understand traffic composition:**

1. **Statistics → Protocol Hierarchy**
2. **Analyze the distribution:**
   - What percentage is HTTP vs HTTPS?
   - Any unusual protocols?
   - Unexpected protocol usage?

**Red flags:**
- High percentage of encrypted traffic to unknown destinations
- Unusual protocols (IRC, Telnet, FTP)
- Protocols on non-standard ports

### Exercise 14: Endpoint Analysis

**Identify all communicating hosts:**

1. **Statistics → Endpoints → IPv4**
2. **Sort by Packets or Bytes**
3. **Identify:**
   - Internal hosts (private IPs)
   - External hosts (public IPs)
   - Most active hosts

**For each external IP:**
- Check reputation (AbuseIPDB, VirusTotal)
- Identify geolocation
- Determine purpose (CDN, cloud, suspicious)

### Exercise 15: Timeline Analysis

**Create a timeline of events:**

1. **Filter for the user's IP:**
   ```
   ip.addr == 192.168.1.100
   ```

2. **Sort by Time** (already default)

3. **Document the sequence:**
   - DNS query for malicious domain
   - HTTP request to malicious site
   - File download
   - C2 connection established
   - Data exfiltration

**Use Time Display Format:**
- **View → Time Display Format → Date and Time of Day**

### Exercise 16: Create IOC List

**Extract all Indicators of Compromise:**

**IP Addresses:**
```
Statistics → Conversations → IPv4
Export → Copy → CSV
```

**Domains:**
```
Statistics → Resolved Addresses
```

**File Hashes:**
- Export objects
- Calculate hashes
- Document in report

**URLs:**
- Extract from HTTP requests
- Document full URLs

---

## Part 6: Creating Your Analysis Report (30 minutes)

### Exercise 17: Document Your Findings

Create a comprehensive report: `Packet-Analysis-Report.md`

**Report Template:**

```markdown
# Packet Analysis Report

**Analyst:** [Your Name]  
**Date:** [Analysis Date]  
**PCAP File:** suspicious-traffic.pcap  
**Capture Duration:** [Start Time] to [End Time]  
**Total Packets:** [Number]

---

## Executive Summary

[2-3 sentence summary of the incident]

---

## 1. Network Information

### User's Computer
**IP Address:** 192.168.1.100  
**MAC Address:** [MAC]  
**Hostname:** [if available]

### DNS Server
**IP Address:** 8.8.8.8

### Gateway
**IP Address:** 192.168.1.1

---

## 2. Timeline of Events

| Time | Event | Details |
|------|-------|---------|
| 10:15:23 | DNS Query | Queried malicious domain: evil.com |
| 10:15:24 | HTTP Request | Connected to 203.0.113.50 |
| 10:15:30 | File Download | Downloaded malware.exe (SHA256: abc123...) |
| 10:16:00 | C2 Connection | Established connection to 198.51.100.25:8080 |

---

## 3. Malicious Activity Detected

### Malicious Domain Access
**Domain:** evil.com  
**IP Address:** 203.0.113.50  
**VirusTotal Score:** 45/70 malicious

**Screenshot:**
![DNS Query](screenshots/dns-query.png)

### File Download
**Filename:** update.exe  
**Size:** 245,760 bytes  
**MD5:** d41d8cd98f00b204e9800998ecf8427e  
**SHA256:** [full hash]  
**VirusTotal:** [link to VT analysis]

**Screenshot:**
![HTTP Object Export](screenshots/http-export.png)

### Command and Control Communication
**C2 Server:** 198.51.100.25:8080  
**Protocol:** HTTP  
**Beaconing Interval:** Every 60 seconds  
**Data Exfiltrated:** ~2.5 MB

**Screenshot:**
![C2 Traffic](screenshots/c2-traffic.png)

---

## 4. Indicators of Compromise (IOCs)

### Domains
```
evil.com
malware-distribution.tk
c2-server.xyz
```

### IP Addresses
```
203.0.113.50
198.51.100.25
192.0.2.100
```

### File Hashes (SHA256)
```
abc123def456... (malware.exe)
789ghi012jkl... (payload.dll)
```

### URLs
```
http://evil.com/download/update.exe
http://198.51.100.25:8080/beacon
```

---

## 5. Attack Chain Analysis

1. **Initial Access:** User visited malicious website (evil.com)
2. **Execution:** Downloaded and executed malware.exe
3. **Persistence:** [Evidence of persistence mechanisms]
4. **Command and Control:** Established connection to C2 server
5. **Exfiltration:** Sent data to external server

**MITRE ATT&CK Mapping:**
- T1566 - Phishing
- T1204 - User Execution
- T1071 - Application Layer Protocol (C2)
- T1041 - Exfiltration Over C2 Channel

---

## 6. Recommendations

### Immediate Actions
1. **Isolate the affected system** (192.168.1.100)
2. **Block IOCs** at firewall/proxy:
   - IPs: 203.0.113.50, 198.51.100.25
   - Domains: evil.com, c2-server.xyz
3. **Scan all systems** for malware.exe hash
4. **Reset credentials** for the affected user

### Long-term Improvements
1. **Implement web filtering** to block malicious domains
2. **Deploy EDR solution** for better endpoint visibility
3. **Enhance user security awareness training**
4. **Implement application whitelisting**

---

## 7. Appendix

### Wireshark Filters Used
```
http
dns
ip.addr == 192.168.1.100
http.request.method == "POST"
tcp.port == 8080
```

### Tools Used
- Wireshark 4.0.x
- VirusTotal
- URLhaus
- AbuseIPDB

---

**Analysis Completed:** [Date/Time]  
**Report Version:** 1.0
```

---

## Deliverables

Submit the following:

1. **Packet-Analysis-Report.md** - Your complete analysis report
2. **Screenshots/** - Directory containing:
   - DNS queries to malicious domains
   - HTTP object exports
   - TCP stream reconstructions
   - C2 traffic evidence
   - Timeline screenshots
3. **IOCs.txt** - Text file with all extracted IOCs
4. **extracted-files/** - Any files extracted from the PCAP (in a safe, isolated environment)

---

## Evaluation Criteria

- **Thoroughness:** Did you analyze all aspects of the traffic?
- **Accuracy:** Are your findings correct and well-supported?
- **IOC Extraction:** Did you identify and document all IOCs?
- **Documentation:** Is your report professional and complete?
- **Screenshots:** Do screenshots clearly support your findings?
- **Recommendations:** Are your recommendations actionable?

---

## Additional Challenges (Optional)

1. **Decrypt HTTPS traffic** using provided SSL keys
2. **Analyze a malware PCAP** from malware-traffic-analysis.net
3. **Create Snort/Suricata rules** based on your findings
4. **Automate IOC extraction** using tshark (command-line Wireshark)
5. **Correlate with SIEM logs** if available

---

## Additional Resources

- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark Display Filters Reference](https://www.wireshark.org/docs/dfref/)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/)
- [NETRESEC PCAP Files](https://www.netresec.com/?page=PcapFiles)
- [PacketLife Cheat Sheets](https://packetlife.net/library/cheat-sheets/)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Beginner to Intermediate
