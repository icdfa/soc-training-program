# Week 6 Lab: Introduction to Security Onion

## Learning Outcomes

By the end of this lab, you will be able to:

- Install and configure Security Onion as a Network Security Monitoring (NSM) platform
- Understand the Security Onion architecture and components
- Generate and capture network traffic for analysis
- Analyze security alerts using Kibana and Security Onion Console (SOC)
- Pivot from alerts to full packet captures (PCAP) for deep analysis
- Use Suricata IDS rules to detect attacks
- Investigate security incidents using multiple data sources

## Objective

Deploy Security Onion as a complete Network Security Monitoring solution and use it to detect, analyze, and investigate simulated attacks in a controlled lab environment.

## Scenario

You are a SOC analyst at CyberDefense Corp, and your organization has decided to deploy Security Onion as its primary Network Security Monitoring platform. Your manager has tasked you with setting up a proof-of-concept deployment, generating test traffic, and demonstrating the platform's detection and analysis capabilities to the security team.

## Prerequisites

- VirtualBox or VMware with sufficient resources
- Host system with:
  - **CPU:** 4+ cores
  - **RAM:** 16GB+ (32GB recommended)
  - **Storage:** 200GB+ free space
- Kali Linux VM (from Week 2 lab)
- Metasploitable 2 or 3 VM (target system)
- Basic understanding of networking and IDS/IPS concepts

## Lab Duration

Approximately 4-5 hours (including installation)

---

## Part 1: Understanding Security Onion (30 minutes)

### Step 1: What is Security Onion?

**Security Onion** is a free, open-source Linux distribution for Network Security Monitoring (NSM), enterprise security monitoring, and log management.

**Key Components:**

| Component | Purpose | Technology |
|-----------|---------|------------|
| **IDS/IPS** | Intrusion detection/prevention | Suricata |
| **NIDS** | Network intrusion detection | Zeek (formerly Bro) |
| **SIEM** | Security information and event management | Elasticsearch, Logstash |
| **Visualization** | Data visualization and analysis | Kibana |
| **Alert Management** | Alert triage and investigation | Security Onion Console (SOC) |
| **PCAP Storage** | Full packet capture | Stenographer |
| **Log Aggregation** | Centralized logging | Elastic Stack |

**Security Onion Architecture:**

```
┌─────────────────────────────────────────────────────────┐
│                    Security Onion                        │
│  ┌────────────┐  ┌────────────┐  ┌─────────────────┐   │
│  │  Suricata  │  │    Zeek    │  │  Stenographer   │   │
│  │    IDS     │  │   (Bro)    │  │  (PCAP Store)   │   │
│  └──────┬─────┘  └──────┬─────┘  └────────┬────────┘   │
│         │                │                  │            │
│         └────────┬───────┴──────────────────┘            │
│                  ▼                                       │
│         ┌────────────────┐                               │
│         │  Elasticsearch │◄──── Logstash                │
│         └────────┬───────┘                               │
│                  │                                       │
│         ┌────────▼───────┐                               │
│         │     Kibana     │                               │
│         │       &        │                               │
│         │      SOC       │                               │
│         └────────────────┘                               │
└─────────────────────────────────────────────────────────┘
```

### Step 2: Security Onion Deployment Types

**Standalone:** All components on one system (suitable for labs and small networks)
**Distributed:** Manager node + multiple sensor nodes (enterprise deployments)

**For this lab:** We'll deploy a **Standalone** installation.

---

## Part 2: Security Onion Installation (90 minutes)

### Step 3: Download Security Onion

1. **Go to:** https://securityonionsolutions.com/software
2. **Download:** Security Onion 2.4.x ISO (latest stable version)
3. **File size:** ~4GB

**Verify the download (optional but recommended):**
```bash
sha256sum securityonion-2.4.x.iso
# Compare with official checksum
```

### Step 4: Create Security Onion VM

**In VirtualBox:**

1. **Click "New"**
2. **Configuration:**
   - **Name:** SecurityOnion
   - **Type:** Linux
   - **Version:** Ubuntu (64-bit)
   - **Memory:** 8192 MB (8GB) minimum, 16384 MB (16GB) recommended
   - **Hard Disk:** Create virtual hard disk, VDI, Dynamically allocated, **200 GB**

3. **VM Settings:**
   - **System → Processor:** 4 CPUs
   - **System → Acceleration:** Enable VT-x/AMD-V
   - **Display → Video Memory:** 128 MB

4. **Network Configuration (CRITICAL):**
   
   **Adapter 1 (Management Interface):**
   - Enable Network Adapter: ✓
   - Attached to: **Bridged Adapter** or **NAT**
   - Purpose: Management access, internet connectivity

   **Adapter 2 (Monitoring Interface):**
   - Enable Network Adapter: ✓
   - Attached to: **Internal Network** or **Host-only Adapter**
   - Name: `SOC-Monitor-Net`
   - Promiscuous Mode: **Allow All**
   - Purpose: Sniffing traffic from target systems

### Step 5: Install Security Onion

1. **Start the VM**
2. **Mount the Security Onion ISO**
3. **Boot from ISO**

**Installation Steps:**

1. **Welcome Screen:**
   - Select language: **English**
   - Click **Install Security Onion**

2. **Keyboard Layout:**
   - Select your keyboard layout
   - Click **Continue**

3. **Network Configuration:**
   - Select management interface (usually `enp0s3`)
   - Configure IP (DHCP or static)
   - Click **Continue**

4. **Disk Partitioning:**
   - Select **Erase disk and install Security Onion**
   - Click **Install Now**
   - Confirm partitioning

5. **Location:**
   - Select your timezone
   - Click **Continue**

6. **User Creation:**
   - Your name: `SOC Admin`
   - Computer name: `securityonion`
   - Username: `socadmin`
   - Password: [Choose strong password]
   - Click **Continue**

7. **Installation Progress:**
   - Wait 10-15 minutes for installation
   - Click **Restart Now** when complete
   - Remove ISO

### Step 6: Initial Security Onion Setup

After reboot, log in and run the setup:

1. **Login** with your credentials

2. **Start the setup wizard:**
   ```bash
   sudo so-setup
   ```

3. **Setup Type:**
   - Select: **STANDALONE**
   - Press Enter

4. **Agree to License:**
   - Read and accept the license

5. **Hostname:**
   - Accept default or customize
   - Press Enter

6. **Management Interface:**
   - Select your management interface (enp0s3)
   - Configure IP address (static recommended)
   - Example: `192.168.1.100/24`
   - Gateway: `192.168.1.1`
   - DNS: `8.8.8.8`

7. **Monitoring Interface:**
   - Select your monitoring interface (enp0s8)
   - This interface will be in promiscuous mode

8. **OS Patch Schedule:**
   - Select: **Automatic** (recommended)

9. **Install Method:**
   - Select: **QUICK** (for lab)
   - Or **CUSTOM** for more control

10. **Admin Email:**
    - Enter your email for SOC access

11. **Admin Password:**
    - Set a strong password for web interface

12. **Web Interface Access:**
    - Select: **IP** (allow access from specific IP)
    - Or **ALL** (allow from any IP - less secure)

13. **NTP Server:**
    - Accept default or specify custom

14. **Confirmation:**
    - Review settings
    - Confirm to proceed

15. **Installation:**
    - Wait 30-60 minutes for component installation
    - Docker containers will be downloaded and configured

16. **Completion:**
    - Note the web interface URL
    - Note your credentials

### Step 7: Verify Installation

1. **Check service status:**
   ```bash
   sudo so-status
   ```

   All services should show as "OK" or "running".

2. **Access web interface:**
   - Open browser on your host machine
   - Navigate to: `https://[SecurityOnion-IP]`
   - Accept self-signed certificate warning
   - Login with admin credentials

3. **Verify components:**
   - **SOC (Security Onion Console):** Alert management
   - **Kibana:** Data visualization
   - **Suricata:** IDS alerts
   - **Zeek:** Network logs

---

## Part 3: Target System Setup (30 minutes)

### Step 8: Deploy Metasploitable 2

**Download Metasploitable 2:**
1. Go to: https://sourceforge.net/projects/metasploitable/
2. Download: `metasploitable-linux-2.0.0.zip`
3. Extract the ZIP file

**Import to VirtualBox:**
1. **Machine → Add**
2. **Select:** `Metasploitable.vmdk`
3. **Configuration:**
   - Memory: 512 MB
   - Network: **Internal Network** (`SOC-Monitor-Net`) - same as Security Onion's monitoring interface

4. **Start the VM**
5. **Login:**
   - Username: `msfadmin`
   - Password: `msfadmin`

6. **Configure static IP:**
   ```bash
   sudo nano /etc/network/interfaces
   ```

   Add:
   ```
   auto eth0
   iface eth0 inet static
       address 192.168.100.10
       netmask 255.255.255.0
   ```

   Restart networking:
   ```bash
   sudo /etc/init.d/networking restart
   ```

### Step 9: Configure Kali Linux

Ensure your Kali VM is on the same network as Metasploitable:

1. **Network Settings:**
   - Adapter 1: **Internal Network** (`SOC-Monitor-Net`)

2. **Configure static IP:**
   ```bash
   sudo ip addr add 192.168.100.20/24 dev eth0
   ```

3. **Verify connectivity:**
   ```bash
   ping 192.168.100.10  # Metasploitable
   ```

---

## Part 4: Generating Attack Traffic (60 minutes)

### Exercise 1: Network Reconnaissance (Nmap Scan)

**From Kali Linux:**

1. **Basic port scan:**
   ```bash
   nmap 192.168.100.10
   ```

2. **Aggressive scan:**
   ```bash
   nmap -A -T4 192.168.100.10
   ```

3. **Full TCP scan:**
   ```bash
   sudo nmap -sS -p- 192.168.100.10
   ```

4. **Service version detection:**
   ```bash
   nmap -sV 192.168.100.10
   ```

5. **OS detection:**
   ```bash
   sudo nmap -O 192.168.100.10
   ```

**Expected alerts in Security Onion:**
- ET SCAN Potential SSH Scan
- GPL SCAN nmap XMAS
- ET SCAN Nmap Scripting Engine User-Agent Detected

### Exercise 2: Vulnerability Exploitation (Metasploit)

**Launch Metasploit:**
```bash
msfconsole
```

**Exploit 1: VSFTPd Backdoor**

```bash
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.100.10
set RPORT 21
exploit
```

**If successful:**
```bash
whoami
id
uname -a
```

**Exploit 2: Samba Username Map Script**

```bash
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.100.10
set RPORT 139
exploit
```

**Exploit 3: UnrealIRCd Backdoor**

```bash
use exploit/unix/irc/unreal_ircd_3281_backdoor
set RHOSTS 192.168.100.10
set RPORT 6667
exploit
```

**Expected alerts:**
- ET EXPLOIT Possible Samba Username Map Script Command Execution
- GPL SHELLCODE x86 NOOP
- ET EXPLOIT Metasploit Payload Common Construct

### Exercise 3: Web Application Attacks

**SQL Injection Test:**
```bash
# Using sqlmap
sqlmap -u "http://192.168.100.10/mutillidae/index.php?page=user-info.php&username=test&password=test" --dbs
```

**Directory Traversal:**
```bash
curl "http://192.168.100.10/dvwa/vulnerabilities/fi/?page=../../../../etc/passwd"
```

**XSS Test:**
```bash
curl "http://192.168.100.10/mutillidae/index.php?page=dns-lookup.php&target_host=<script>alert('XSS')</script>"
```

### Exercise 4: Brute Force Attack

**SSH Brute Force:**
```bash
hydra -l msfadmin -P /usr/share/wordlists/rockyou.txt 192.168.100.10 ssh
```

**FTP Brute Force:**
```bash
hydra -l admin -P /usr/share/wordlists/fasttrack.txt 192.168.100.10 ftp
```

---

## Part 5: Alert Analysis in Security Onion (60 minutes)

### Exercise 5: Access Security Onion Console (SOC)

1. **Open browser:** `https://[SecurityOnion-IP]`
2. **Login** with admin credentials
3. **Navigate to:** **Alerts** dashboard

### Exercise 6: Analyze Nmap Scan Alerts

**Filter for scan alerts:**
1. In SOC, use search: `event.module:suricata AND alert.signature:*scan*`
2. **Review alerts:**
   - Signature name
   - Source IP (Kali)
   - Destination IP (Metasploitable)
   - Timestamp
   - Severity

**Pivot to Kibana:**
1. Click on an alert
2. Select **View in Kibana**
3. **Analyze:**
   - Timeline of events
   - Related alerts
   - Full packet details

### Exercise 7: Investigate Metasploit Exploitation

**Search for exploit alerts:**
```
event.module:suricata AND alert.signature:*exploit*
```

**Analyze the alert:**
1. **Signature:** ET EXPLOIT Metasploit...
2. **Source IP:** 192.168.100.20 (Kali)
3. **Destination IP:** 192.168.100.10 (Metasploitable)
4. **Destination Port:** 21, 139, or 6667

**Pivot to PCAP:**
1. Click on alert
2. Select **PCAP**
3. **Download PCAP** for offline analysis
4. **Open in Wireshark**

**In Wireshark:**
```
Follow TCP Stream
Analyze the exploit payload
Extract IOCs
```

### Exercise 8: Zeek Log Analysis

**Access Zeek logs in Kibana:**
1. Navigate to **Discover**
2. Select index: `logs-zeek-*`
3. **Explore log types:**
   - `conn.log` - Connection summaries
   - `http.log` - HTTP requests
   - `dns.log` - DNS queries
   - `files.log` - File transfers
   - `ssl.log` - SSL/TLS connections

**Analyze HTTP traffic:**
```
event.dataset:zeek.http
```

**Look for:**
- User-Agents (identify scanning tools)
- Requested URIs
- Response codes
- File downloads

### Exercise 9: Create Custom Hunt

**Hunt for SSH brute force:**
1. **Kibana → Discover**
2. **Filter:**
   ```
   event.dataset:zeek.conn AND destination.port:22
   ```
3. **Visualize:**
   - Group by source IP
   - Count connections
   - Look for high connection counts

**Create visualization:**
1. **Kibana → Visualize**
2. **Create new visualization**
3. **Type:** Data table
4. **Metrics:** Count
5. **Buckets:** Terms aggregation on `source.ip`
6. **Save** as "SSH Connection Attempts"

---

## Part 6: Advanced Analysis (45 minutes)

### Exercise 10: Correlation Analysis

**Correlate multiple data sources:**

1. **Find initial scan (Suricata alert)**
2. **Pivot to Zeek conn logs** (same timeframe)
3. **Identify exploitation attempt** (Suricata alert)
4. **Check for successful connection** (Zeek conn.log with long duration)
5. **Look for data exfiltration** (Zeek files.log)

**Create timeline:**
- 10:15:00 - Nmap scan detected
- 10:16:30 - Metasploit exploit attempt
- 10:16:45 - Successful shell connection
- 10:17:00 - Commands executed
- 10:18:00 - File downloaded

### Exercise 11: PCAP Analysis

**Extract PCAP for specific alert:**
1. **SOC → Alerts**
2. **Select alert**
3. **Actions → PCAP**
4. **Specify time range** (±5 minutes)
5. **Download PCAP**

**Analyze in Wireshark:**
```bash
wireshark alert-pcap.pcap
```

**Look for:**
- Exploit payload
- Shell commands
- Data exfiltration
- Persistence mechanisms

### Exercise 12: Rule Tuning

**Disable noisy rules:**

1. **Identify noisy signature:**
   - Example: "ET INFO Session Traversal Utilities for NAT"

2. **Disable in SOC:**
   ```bash
   sudo so-rule-update
   ```

3. **Or create local rule:**
   ```bash
   sudo nano /opt/so/saltstack/local/salt/idstools/local.rules
   ```

   Add:
   ```
   # Disable noisy rule
   suppress gen_id 1, sig_id 2100498
   ```

4. **Apply changes:**
   ```bash
   sudo so-rule-update
   ```

---

## Deliverables

Submit the following:

1. **Security-Onion-Report.md** - Comprehensive analysis report
2. **Screenshots/** - Directory containing:
   - Security Onion installation completion
   - SOC dashboard with alerts
   - Nmap scan alerts
   - Metasploit exploit alerts
   - Kibana visualizations
   - Zeek log analysis
   - PCAP analysis in Wireshark
3. **PCAPs/** - Extracted PCAP files for key alerts
4. **IOCs.txt** - List of indicators of compromise identified

## Report Template

```markdown
# Security Onion Analysis Report

**Analyst:** [Your Name]  
**Date:** [Date]  
**Lab Environment:** Security Onion 2.4.x

---

## Executive Summary

[Summary of attacks detected and analyzed]

---

## 1. Security Onion Deployment

### Installation Details
- Version: 2.4.x
- Deployment Type: Standalone
- Management IP: [IP]
- Monitoring Interface: [Interface]

### Components Verified
- [x] Suricata IDS
- [x] Zeek (Bro)
- [x] Elasticsearch
- [x] Kibana
- [x] SOC
- [x] Stenographer

---

## 2. Attack Scenarios

### Scenario 1: Network Reconnaissance
**Attack:** Nmap scan from Kali (192.168.100.20) to Metasploitable (192.168.100.10)

**Alerts Generated:**
- [List alerts with signatures]

**Screenshot:**
![Nmap Alerts](screenshots/nmap-alerts.png)

### Scenario 2: Exploitation
**Attack:** Metasploit exploitation attempts

**Alerts Generated:**
- [List exploit alerts]

**Screenshot:**
![Exploit Alerts](screenshots/exploit-alerts.png)

---

## 3. Analysis Findings

### Zeek Log Analysis
[Findings from Zeek logs]

### PCAP Analysis
[Findings from packet captures]

---

## 4. IOCs Identified

**IP Addresses:**
- 192.168.100.20 (Attacker)

**Signatures:**
- [List Suricata signatures triggered]

---

## 5. Recommendations

1. [Recommendation 1]
2. [Recommendation 2]
```

---

## Evaluation Criteria

- **Installation:** Successfully deployed Security Onion
- **Alert Generation:** Generated multiple types of alerts
- **Analysis:** Thoroughly analyzed alerts using SOC and Kibana
- **PCAP Analysis:** Successfully extracted and analyzed PCAPs
- **Documentation:** Professional, complete report

---

## Additional Resources

- [Security Onion Documentation](https://docs.securityonion.net/)
- [Suricata Rules](https://suricata.readthedocs.io/)
- [Zeek Documentation](https://docs.zeek.org/)
- [Elastic Stack Documentation](https://www.elastic.co/guide/)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Intermediate to Advanced
