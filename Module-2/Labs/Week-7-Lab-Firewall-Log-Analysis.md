# Week 7 Lab: Firewall Log Analysis

## Learning Outcomes

By the end of this lab, you will be able to:

- Parse and analyze firewall logs from multiple vendors (pfSense, Cisco ASA, Fortinet)
- Identify port scanning and reconnaissance activity from firewall logs
- Detect brute-force attacks and unauthorized access attempts
- Correlate firewall logs with threat intelligence
- Use command-line tools and SIEM for firewall log analysis
- Create firewall rules based on analysis findings
- Generate professional firewall analysis reports

## Objective

Master firewall log analysis techniques to detect network-based attacks, identify malicious actors, and recommend security improvements through comprehensive log investigation.

## Scenario

You are a SOC analyst at GlobalTech Corporation. The network security team has detected unusual traffic patterns on the perimeter firewall protecting the company's public-facing web servers. Multiple blocked connection attempts have been logged, and management is concerned about a potential targeted attack. You need to analyze the firewall logs to determine the nature and scope of the activity, identify the attackers, and provide recommendations for enhanced security measures.

## Prerequisites

- Linux system (Ubuntu VM from Week 2 lab)
- Basic understanding of TCP/IP, ports, and firewall concepts
- Familiarity with command-line tools (grep, awk, sed)
- Access to Splunk (optional, from Week 2 lab)
- Text editor for documentation

## Lab Duration

Approximately 3-4 hours

---

## Part 1: Understanding Firewall Logs (30 minutes)

### Step 1: Firewall Log Formats

Different firewall vendors use different log formats. Understanding these formats is crucial for analysis.

**pfSense/OPNsense (BSD-based):**
```
Jan 15 10:23:45 firewall filterlog: 5,,,1000000103,em0,match,block,in,4,0x0,,64,12345,0,none,6,tcp,60,203.0.113.50,192.0.2.10,54321,22,0,S,1234567890,,64240,,mss
```

**Cisco ASA:**
```
%ASA-4-106023: Deny tcp src outside:203.0.113.50/54321 dst inside:192.0.2.10/22 by access-group "outside_in" [0x0, 0x0]
```

**Fortinet FortiGate:**
```
date=2024-01-15 time=10:23:45 devname="FGT60D" logid="0000000013" type="traffic" subtype="forward" level="notice" srcip=203.0.113.50 srcport=54321 dstip=192.0.2.10 dstport=22 action="deny"
```

**Common Fields Across Vendors:**

| Field | Description | Example |
|-------|-------------|---------|
| Timestamp | When the event occurred | 2024-01-15 10:23:45 |
| Action | Allow, Deny, Block, Drop | deny, block |
| Source IP | Originating IP address | 203.0.113.50 |
| Source Port | Originating port number | 54321 |
| Destination IP | Target IP address | 192.0.2.10 |
| Destination Port | Target port number | 22 (SSH) |
| Protocol | TCP, UDP, ICMP | tcp |
| Interface | Ingress/egress interface | eth0, outside |
| Rule | Firewall rule that matched | outside_in |

### Step 2: Common Port Numbers

Understanding common ports helps identify attack targets:

| Port | Service | Common Attacks |
|------|---------|----------------|
| 21 | FTP | Brute force, anonymous access |
| 22 | SSH | Brute force, credential stuffing |
| 23 | Telnet | Brute force, cleartext credentials |
| 25 | SMTP | Spam relay, email attacks |
| 53 | DNS | DNS amplification, tunneling |
| 80 | HTTP | Web attacks, SQL injection |
| 443 | HTTPS | Web attacks, encrypted tunneling |
| 445 | SMB | WannaCry, EternalBlue |
| 1433 | MS SQL | SQL injection, brute force |
| 3306 | MySQL | SQL injection, brute force |
| 3389 | RDP | Brute force, BlueKeep |
| 8080 | HTTP Alt | Web attacks, proxy abuse |

### Step 3: Download Sample Firewall Logs

Create working directory and download samples:

```bash
mkdir -p ~/soc-labs/week7
cd ~/soc-labs/week7
```

**Option 1: Use provided sample**
```bash
cp /path/to/soc-training-program/Lab-Resources/Sample-Data/firewall.log .
```

**Option 2: Generate sample log**

Create `firewall.log` with sample data:
```bash
cat > firewall.log << 'EOF'
Jan 15 08:15:23 fw01 filterlog: block,in,tcp,203.0.113.50,192.0.2.10,54321,22,S
Jan 15 08:15:24 fw01 filterlog: block,in,tcp,203.0.113.50,192.0.2.10,54322,23,S
Jan 15 08:15:25 fw01 filterlog: block,in,tcp,203.0.113.50,192.0.2.10,54323,21,S
Jan 15 08:15:26 fw01 filterlog: block,in,tcp,203.0.113.50,192.0.2.10,54324,25,S
Jan 15 08:15:27 fw01 filterlog: block,in,tcp,203.0.113.50,192.0.2.10,54325,80,S
# ... (add more entries)
EOF
```

---

## Part 2: Command-Line Log Analysis (60 minutes)

### Exercise 1: Basic Log Inspection

**View the log file:**
```bash
cat firewall.log | head -20
```

**Count total log entries:**
```bash
wc -l firewall.log
```

**View log structure:**
```bash
head -1 firewall.log
```

### Exercise 2: Identify Blocked Connections

**Question:** How many connections were blocked?

**Command:**
```bash
grep -c "block\|deny\|drop" firewall.log
```

**Explanation:**
- `grep -c` counts matching lines
- `block\|deny\|drop` matches any of these actions

**View blocked connections:**
```bash
grep "block\|deny" firewall.log | head -20
```

### Exercise 3: Extract Source IP Addresses

**Question:** What are the unique source IPs attempting connections?

**For pfSense logs:**
```bash
grep "block" firewall.log | awk -F',' '{print $5}' | sort -u
```

**Count occurrences per IP:**
```bash
grep "block" firewall.log | awk -F',' '{print $5}' | sort | uniq -c | sort -rn
```

**Expected output:**
```
    523 203.0.113.50
    145 198.51.100.25
     89 192.0.2.100
```

**Top 10 source IPs:**
```bash
grep "block" firewall.log | awk -F',' '{print $5}' | sort | uniq -c | sort -rn | head -10
```

### Exercise 4: Identify Port Scanning Activity

**Question:** What ports were targeted?

**Extract destination ports:**
```bash
grep "block" firewall.log | awk -F',' '{print $7}' | sort -u
```

**Count attempts per port:**
```bash
grep "block" firewall.log | awk -F',' '{print $7}' | sort | uniq -c | sort -rn
```

**Expected output:**
```
    234 22    # SSH
    189 3389  # RDP
    156 445   # SMB
    123 80    # HTTP
     98 23    # Telnet
```

**Identify sequential port scanning:**
```bash
grep "203.0.113.50" firewall.log | awk -F',' '{print $7}' | head -20
```

If you see sequential ports (21, 22, 23, 24, 25...), it's likely a port scan.

### Exercise 5: Analyze Time Patterns

**Question:** When did the scanning activity occur?

**Extract timestamps:**
```bash
grep "203.0.113.50" firewall.log | awk '{print $1, $2, $3}' | head -20
```

**Group by hour:**
```bash
grep "block" firewall.log | awk '{print $3}' | cut -d: -f1 | sort | uniq -c
```

**Expected output:**
```
     45 08
    234 09
    456 10
    123 11
```

**Find time range of attack:**
```bash
echo "First attempt:"
grep "203.0.113.50" firewall.log | head -1 | awk '{print $1, $2, $3}'

echo "Last attempt:"
grep "203.0.113.50" firewall.log | tail -1 | awk '{print $1, $2, $3}'
```

### Exercise 6: Detect Brute-Force Attempts

**Question:** Are there brute-force attempts on specific services?

**SSH brute-force detection (port 22):**
```bash
grep "block" firewall.log | awk -F',' '$7 == 22 {print $5}' | sort | uniq -c | sort -rn
```

**IPs with >100 SSH attempts:**
```bash
grep "block" firewall.log | awk -F',' '$7 == 22 {print $5}' | sort | uniq -c | sort -rn | awk '$1 > 100'
```

**RDP brute-force detection (port 3389):**
```bash
grep "block" firewall.log | awk -F',' '$7 == 3389 {print $5}' | sort | uniq -c | sort -rn
```

### Exercise 7: Identify Successful Connections

**Question:** Were any connections from suspicious IPs allowed?

**Find allowed connections from attacker IP:**
```bash
grep "203.0.113.50" firewall.log | grep -v "block\|deny"
```

**If any are found, this indicates:**
- Potential compromise
- Misconfigured firewall rules
- Need for immediate investigation

**Extract allowed connections:**
```bash
grep "allow\|accept\|pass" firewall.log | grep "203.0.113.50"
```

---

## Part 3: Advanced Analysis Techniques (60 minutes)

### Exercise 8: Correlate with Threat Intelligence

**Check IP reputation using command-line tools:**

**Using curl with AbuseIPDB:**
```bash
# Get your API key from https://www.abuseipdb.com/
API_KEY="your_api_key_here"
IP="203.0.113.50"

curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=$IP" \
  -H "Key: $API_KEY" \
  -H "Accept: application/json"
```

**Using whois:**
```bash
whois 203.0.113.50
```

**Look for:**
- Country of origin
- ISP/Organization
- Abuse contact email

**Create a script for bulk IP checking:**

```bash
cat > check_ips.sh << 'EOF'
#!/bin/bash
# Extract unique IPs and check reputation

echo "Extracting suspicious IPs..."
grep "block" firewall.log | awk -F',' '{print $5}' | sort | uniq -c | sort -rn | head -10 > suspicious_ips.txt

echo "Checking IP reputation..."
while read count ip; do
    echo "=== $ip ($count attempts) ==="
    whois $ip | grep -i "country\|org"
    echo ""
done < suspicious_ips.txt
EOF

chmod +x check_ips.sh
./check_ips.sh
```

### Exercise 9: Identify Attack Patterns

**Detect horizontal scanning (one IP, many targets):**
```bash
grep "203.0.113.50" firewall.log | awk -F',' '{print $6}' | sort -u | wc -l
```

If the count is high (>10 unique destination IPs), it's horizontal scanning.

**Detect vertical scanning (one IP, one target, many ports):**
```bash
grep "203.0.113.50" firewall.log | grep "192.0.2.10" | awk -F',' '{print $7}' | sort -u | wc -l
```

If the count is high (>20 unique ports), it's vertical scanning.

**Identify distributed attacks (many IPs, one target):**
```bash
grep "192.0.2.10" firewall.log | awk -F',' '{print $5}' | sort -u | wc -l
```

### Exercise 10: Geo-Location Analysis

**Create a script to identify countries:**

```bash
cat > geolocate.sh << 'EOF'
#!/bin/bash
# Geolocate top attacking IPs

echo "IP Address,Country,Attempts" > geolocation.csv

grep "block" firewall.log | awk -F',' '{print $5}' | sort | uniq -c | sort -rn | head -20 | while read count ip; do
    country=$(whois $ip | grep -i "^country:" | head -1 | awk '{print $2}')
    echo "$ip,$country,$count" >> geolocation.csv
done

echo "Results saved to geolocation.csv"
cat geolocation.csv
EOF

chmod +x geolocate.sh
./geolocate.sh
```

### Exercise 11: Protocol Analysis

**Analyze protocols used:**
```bash
grep "block" firewall.log | awk -F',' '{print $4}' | sort | uniq -c | sort -rn
```

**Expected output:**
```
   1234 tcp
    456 udp
     23 icmp
```

**Identify unusual protocols:**
- GRE (protocol 47) - VPN tunneling
- ESP (protocol 50) - IPsec
- IGMP (protocol 2) - Multicast

---

## Part 4: Splunk Analysis (Optional, 45 minutes)

### Exercise 12: Import Logs into Splunk

If you have Splunk from Week 2 lab:

1. **Copy log file to Splunk server:**
   ```bash
   scp firewall.log socadmin@192.168.56.10:/tmp/
   ```

2. **In Splunk Web Interface:**
   - Go to **Settings → Add Data**
   - Select **Upload**
   - Choose `firewall.log`
   - Set **Source Type:** `syslog` or create custom
   - Click **Submit**

### Exercise 13: Splunk Queries for Firewall Analysis

**Basic search:**
```spl
source="firewall.log"
```

**Count blocked connections:**
```spl
source="firewall.log" (block OR deny)
| stats count
```

**Top source IPs:**
```spl
source="firewall.log" (block OR deny)
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+),(?<dst_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort -count
| head 10
```

**Port scan detection:**
```spl
source="firewall.log" (block OR deny)
| rex field=_raw "(?<src_ip>\d+\.\d+\.\d+\.\d+),(?<dst_ip>\d+\.\d+\.\d+\.\d+),\d+,(?<dst_port>\d+)"
| stats dc(dst_port) as unique_ports by src_ip
| where unique_ports > 20
| sort -unique_ports
```

**Timeline visualization:**
```spl
source="firewall.log" (block OR deny)
| timechart count by action
```

---

## Part 5: Creating Firewall Rules (30 minutes)

### Exercise 14: Recommend Blocking Rules

Based on your analysis, create firewall rules to block malicious IPs.

**pfSense/OPNsense:**
```
# Block malicious IP
block in quick on em0 from 203.0.113.50 to any
block in quick on em0 from 198.51.100.25 to any
```

**Cisco ASA:**
```
access-list outside_in deny ip host 203.0.113.50 any
access-list outside_in deny ip host 198.51.100.25 any
```

**iptables (Linux):**
```bash
iptables -A INPUT -s 203.0.113.50 -j DROP
iptables -A INPUT -s 198.51.100.25 -j DROP
```

**Fortinet FortiGate:**
```
config firewall address
    edit "Malicious_IP_1"
        set subnet 203.0.113.50 255.255.255.255
    next
end

config firewall policy
    edit 1
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "Malicious_IP_1"
        set dstaddr "all"
        set action deny
    next
end
```

### Exercise 15: Rate Limiting Rules

Implement rate limiting to prevent brute-force attacks:

**iptables (SSH brute-force protection):**
```bash
# Allow max 3 SSH connections per minute per IP
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
```

**pfSense:**
- Go to **Firewall → Rules**
- Edit SSH rule
- **Advanced Options → Max states per host:** 3
- **Max new connections per second:** 3

---

## Part 6: Creating Your Analysis Report (30 minutes)

### Exercise 16: Generate Comprehensive Report

Create `Firewall-Log-Analysis-Report.md`:

```markdown
# Firewall Log Analysis Report

**Analyst:** [Your Name]  
**Date:** [Analysis Date]  
**Log File:** firewall.log  
**Analysis Period:** [Date Range]  
**Total Log Entries:** [Number]

---

## Executive Summary

[2-3 sentence summary of findings]

**Key Findings:**
- [Number] blocked connection attempts detected
- [Number] unique source IPs identified
- Primary attack type: [Port Scanning / Brute Force / DDoS]
- Recommended actions: [Block X IPs, implement rate limiting]

---

## 1. Attack Overview

### Timeline
- **First Attack:** Jan 15, 2024 08:15:23
- **Last Attack:** Jan 15, 2024 18:45:12
- **Duration:** 10 hours 30 minutes
- **Total Attempts:** 5,234

### Attack Type
[Port Scanning / Brute Force / Distributed Attack]

---

## 2. Source Analysis

### Top 10 Attacking IPs

| IP Address | Attempts | Country | ISP | Reputation |
|------------|----------|---------|-----|------------|
| 203.0.113.50 | 2,345 | CN | ChinaNet | Malicious |
| 198.51.100.25 | 1,234 | RU | Unknown | Suspicious |
| ... | ... | ... | ... | ... |

**Command Used:**
```bash
grep "block" firewall.log | awk -F',' '{print $5}' | sort | uniq -c | sort -rn | head -10
```

---

## 3. Target Analysis

### Targeted Ports

| Port | Service | Attempts | Risk Level |
|------|---------|----------|------------|
| 22 | SSH | 1,234 | High |
| 3389 | RDP | 987 | High |
| 445 | SMB | 654 | Critical |
| 80 | HTTP | 543 | Medium |

**Command Used:**
```bash
grep "block" firewall.log | awk -F',' '{print $7}' | sort | uniq -c | sort -rn
```

### Targeted Systems

| IP Address | System | Attempts |
|------------|--------|----------|
| 192.0.2.10 | Web Server | 3,456 |
| 192.0.2.11 | Mail Server | 1,234 |

---

## 4. Attack Pattern Analysis

### Scanning Behavior
- **Type:** Vertical port scanning
- **Ports Scanned:** 1-65535 (sequential)
- **Scan Speed:** ~100 ports/second
- **Tool Suspected:** Nmap, Masscan

### Brute-Force Attempts
- **SSH (Port 22):** 1,234 attempts from 203.0.113.50
- **RDP (Port 3389):** 987 attempts from 198.51.100.25
- **Pattern:** Dictionary attack, common usernames

---

## 5. Threat Intelligence Correlation

### IP Reputation Check

**203.0.113.50:**
- **AbuseIPDB Score:** 100% (Malicious)
- **Reports:** 523 abuse reports
- **Categories:** Port Scan, Brute Force, SSH Attack
- **Last Reported:** 2 days ago

**198.51.100.25:**
- **AbuseIPDB Score:** 85% (Suspicious)
- **Reports:** 234 abuse reports
- **Categories:** RDP Brute Force

---

## 6. Successful Connections

### Allowed Traffic from Suspicious IPs
[None detected / List any found]

**Command Used:**
```bash
grep "203.0.113.50" firewall.log | grep -v "block"
```

---

## 7. Recommendations

### Immediate Actions (Priority 1)
1. **Block malicious IPs:**
   ```
   203.0.113.50
   198.51.100.25
   192.0.2.100
   ```

2. **Implement rate limiting on:**
   - SSH (Port 22): Max 3 attempts/minute
   - RDP (Port 3389): Max 5 attempts/minute

3. **Review and harden:**
   - SSH configuration (disable root login, key-based auth)
   - RDP configuration (NLA, account lockout)

### Short-term Improvements (Priority 2)
1. **Deploy fail2ban** for automated IP blocking
2. **Implement geo-blocking** for countries with no business need
3. **Enable two-factor authentication** for all remote access
4. **Deploy IDS/IPS** (Suricata, Snort) for deeper inspection

### Long-term Enhancements (Priority 3)
1. **Implement Zero Trust architecture**
2. **Deploy VPN** for all remote access
3. **Segment network** to limit lateral movement
4. **Enhance monitoring** with SIEM correlation

---

## 8. Proposed Firewall Rules

### Block Malicious IPs
```bash
# iptables
iptables -A INPUT -s 203.0.113.50 -j DROP
iptables -A INPUT -s 198.51.100.25 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Rate Limiting
```bash
# SSH brute-force protection
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
```

---

## 9. Appendix

### Commands Used
```bash
# Total blocked connections
grep -c "block" firewall.log

# Top source IPs
grep "block" firewall.log | awk -F',' '{print $5}' | sort | uniq -c | sort -rn | head -10

# Targeted ports
grep "block" firewall.log | awk -F',' '{print $7}' | sort | uniq -c | sort -rn

# Time range
grep "203.0.113.50" firewall.log | head -1 | awk '{print $1, $2, $3}'
grep "203.0.113.50" firewall.log | tail -1 | awk '{print $1, $2, $3}'
```

### Tools Used
- grep, awk, sed, sort, uniq
- whois
- AbuseIPDB API
- Splunk (optional)

---

**Analysis Completed:** [Date/Time]  
**Report Version:** 1.0  
**Next Review:** [Date]
```

---

## Deliverables

Submit the following:

1. **Firewall-Log-Analysis-Report.md** - Your comprehensive analysis report
2. **Scripts/** - Directory containing:
   - `check_ips.sh` - IP reputation checking script
   - `geolocate.sh` - Geolocation script
   - Any other analysis scripts created
3. **Data/** - Directory containing:
   - `suspicious_ips.txt` - List of malicious IPs
   - `geolocation.csv` - Geolocation data
   - `blocked_ports.txt` - List of targeted ports
4. **Rules/** - Directory containing:
   - Proposed firewall rules for your environment
   - Rate limiting configurations

---

## Evaluation Criteria

- **Analysis Depth:** Thorough investigation of logs
- **Command Proficiency:** Effective use of CLI tools
- **Threat Intelligence:** Correlation with external sources
- **Pattern Recognition:** Identification of attack patterns
- **Recommendations:** Actionable security improvements
- **Documentation:** Professional, complete report

---

## Additional Challenges (Optional)

1. **Automate the analysis** with a comprehensive bash script
2. **Create visualizations** using gnuplot or Python
3. **Implement fail2ban** and test with simulated attacks
4. **Integrate with SIEM** for real-time alerting
5. **Create custom Splunk dashboard** for firewall monitoring

---

## Additional Resources

- [pfSense Documentation](https://docs.netgate.com/pfsense/en/latest/)
- [Cisco ASA Logging](https://www.cisco.com/c/en/us/td/docs/security/asa/syslog/b_syslog.html)
- [iptables Tutorial](https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [SANS Firewall Checklist](https://www.sans.org/security-resources/policies/general/pdf/firewall-checklist)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Intermediate
