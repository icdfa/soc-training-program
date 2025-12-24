# Week 9 Lab: Introduction to Splunk

## Learning Outcomes

By the end of this lab, you will be able to:

- Install and configure a standalone Splunk Enterprise instance
- Understand Splunk architecture and data pipeline
- Onboard data from Windows and Linux systems using Universal Forwarders
- Master SPL (Search Processing Language) fundamentals
- Create searches, filters, and basic visualizations
- Identify security events and investigate incidents using Splunk
- Configure indexes, sourcetypes, and data inputs
- Create dashboards and reports for SOC operations

## Objective

Deploy Splunk Enterprise as a Security Information and Event Management (SIEM) platform, onboard multiple data sources, and master SPL queries for security monitoring and incident investigation.

## Scenario

You are a SOC Analyst at CyberSecure Inc., and management has approved the deployment of Splunk Enterprise as the organization's primary SIEM platform. Your responsibilities include:
1. Deploying Splunk Enterprise in the lab environment
2. Onboarding logs from Windows and Linux systems
3. Creating searches to detect security events
4. Building dashboards for the SOC team
5. Demonstrating Splunk's capabilities for incident investigation

## Prerequisites

- Ubuntu Server VM (from Week 2 lab) or dedicated SIEM VM
- Windows VM (for log collection)
- Linux VM (for log collection)
- Minimum system requirements:
  - **CPU:** 4 cores
  - **RAM:** 8GB (12GB recommended)
  - **Storage:** 100GB free space
- Basic understanding of log formats and security events

## Lab Duration

Approximately 5-6 hours

---

## Part 1: Understanding Splunk (30 minutes)

### Step 1: What is Splunk?

**Splunk** is a powerful platform for searching, monitoring, and analyzing machine-generated data through a web-style interface.

**Key Capabilities:**
- **Data Collection:** Ingest data from any source
- **Indexing:** Store and index data for fast retrieval
- **Search:** Query data using SPL (Search Processing Language)
- **Visualization:** Create dashboards, charts, and reports
- **Alerting:** Real-time alerts on specific conditions
- **Correlation:** Correlate events across multiple sources

**Splunk Architecture:**

```
┌─────────────────────────────────────────────────────────┐
│                    Splunk Architecture                   │
│                                                          │
│  ┌──────────────┐         ┌──────────────┐             │
│  │   Forwarder  │────────▶│   Indexer    │             │
│  │  (Windows)   │         │              │             │
│  └──────────────┘         │  - Parsing   │             │
│                           │  - Indexing  │             │
│  ┌──────────────┐         │  - Storage   │             │
│  │   Forwarder  │────────▶│              │             │
│  │   (Linux)    │         └──────┬───────┘             │
│  └──────────────┘                │                     │
│                                   │                     │
│  ┌──────────────┐                │                     │
│  │   Forwarder  │────────────────┘                     │
│  │  (Firewall)  │                                      │
│  └──────────────┘         ┌──────────────┐             │
│                           │ Search Head  │             │
│                           │              │             │
│                           │  - Web UI    │             │
│                           │  - Searches  │             │
│                           │  - Dashboards│             │
│                           └──────────────┘             │
└─────────────────────────────────────────────────────────┘
```

**Splunk Editions:**
- **Splunk Free:** 500MB/day limit, no alerting, no authentication
- **Splunk Enterprise Trial:** 60-day full-featured trial
- **Splunk Enterprise:** Full commercial version
- **Splunk Cloud:** SaaS offering

**For this lab:** We'll use **Splunk Enterprise Trial** (60 days, fully featured)

### Step 2: Splunk Data Pipeline

Understanding how data flows through Splunk:

1. **Input:** Data enters Splunk (forwarders, files, APIs)
2. **Parsing:** Data is broken into events
3. **Indexing:** Events are stored in indexes
4. **Searching:** Users query indexed data
5. **Visualization:** Results displayed in dashboards/reports

---

## Part 2: Installing Splunk Enterprise (60 minutes)

### Step 3: Download Splunk

1. **Go to:** https://www.splunk.com/
2. **Click:** Free Splunk → Free Trial
3. **Create account** (required for download)
4. **Select:** Splunk Enterprise (Linux .deb or .tgz)
5. **Download:** `splunk-9.x.x-linux-2.6-amd64.deb`

**Or use wget (requires authentication):**
```bash
# After logging in, get download link from website
wget -O splunk-9.1.2-linux-amd64.deb "https://download.splunk.com/..."
```

### Step 4: Install Splunk on Ubuntu

**Transfer installer to VM:**
```bash
scp splunk-9.1.2-linux-amd64.deb socadmin@192.168.56.10:/tmp/
```

**SSH to Splunk server:**
```bash
ssh socadmin@192.168.56.10
```

**Install Splunk:**
```bash
cd /tmp
sudo dpkg -i splunk-9.1.2-linux-amd64.deb
```

**Splunk installs to:** `/opt/splunk/`

**Start Splunk for first time:**
```bash
cd /opt/splunk/bin
sudo ./splunk start --accept-license
```

**Create admin credentials:**
```
Administrator Username: admin
Password: [Choose strong password, min 8 characters]
```

**Splunk will start and display:**
```
Splunk> All batbelt. Yay!

Splunk has started successfully!
Web interface: http://your-server-ip:8000
```

**Enable Splunk to start on boot:**
```bash
sudo /opt/splunk/bin/splunk enable boot-start
```

### Step 5: Access Splunk Web Interface

1. **Open browser** on your host machine
2. **Navigate to:** `http://192.168.56.10:8000`
3. **Login:**
   - Username: `admin`
   - Password: [your password]

**Welcome Screen:**
- Take the tour (optional)
- Click **Start Searching**

### Step 6: Initial Configuration

**Configure receiving port for forwarders:**

1. **Settings → Forwarding and receiving**
2. **Configure receiving**
3. **New Receiving Port**
4. **Port:** `9997`
5. **Save**

**Verify:**
```bash
sudo /opt/splunk/bin/splunk list inputstatus
```

---

## Part 3: Installing Universal Forwarders (45 minutes)

### Step 7: Install Forwarder on Windows

**Download Windows Universal Forwarder:**
- https://www.splunk.com/en_us/download/universal-forwarder.html
- Select: Windows 64-bit
- Download: `splunkforwarder-9.1.2-x64-release.msi`

**Install on Windows VM:**
1. **Run installer**
2. **Accept license**
3. **Username:** `admin`
4. **Password:** [same as Splunk server]
5. **Deployment Server:** [Leave blank]
6. **Receiving Indexer:**
   - Host: `192.168.56.10`
   - Port: `9997`
7. **Install**

**Verify installation:**
```powershell
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk.exe status
```

### Step 8: Configure Windows Event Log Collection

**Edit inputs.conf:**
```powershell
cd "C:\Program Files\SplunkUniversalForwarder\etc\system\local"
notepad inputs.conf
```

**Add:**
```ini
[WinEventLog://Security]
disabled = 0
index = windows_security

[WinEventLog://System]
disabled = 0
index = windows_system

[WinEventLog://Application]
disabled = 0
index = windows_application

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows_sysmon
renderXml = true
```

**Restart forwarder:**
```powershell
cd "C:\Program Files\SplunkUniversalForwarder\bin"
.\splunk.exe restart
```

### Step 9: Install Forwarder on Linux

**Download Linux Universal Forwarder:**
```bash
wget -O splunkforwarder-9.1.2-linux-amd64.deb https://download.splunk.com/products/universalforwarder/releases/9.1.2/linux/splunkforwarder-9.1.2-b1a7a4176146-linux-2.6-amd64.deb
```

**Install:**
```bash
sudo dpkg -i splunkforwarder-9.1.2-linux-amd64.deb
```

**Start and configure:**
```bash
cd /opt/splunkforwarder/bin
sudo ./splunk start --accept-license
# Create admin credentials
sudo ./splunk add forward-server 192.168.56.10:9997
sudo ./splunk enable boot-start
```

**Configure Linux log collection:**
```bash
sudo ./splunk add monitor /var/log/syslog -index linux_logs
sudo ./splunk add monitor /var/log/auth.log -index linux_security
sudo ./splunk add monitor /var/log/apache2/access.log -index web_logs
sudo ./splunk restart
```

### Step 10: Create Indexes on Splunk Server

**In Splunk Web:**
1. **Settings → Indexes**
2. **New Index**
3. **Create indexes:**
   - `windows_security`
   - `windows_system`
   - `windows_application`
   - `windows_sysmon`
   - `linux_logs`
   - `linux_security`
   - `web_logs`

**For each index:**
- Max Size: 500MB (for lab)
- Click **Save**

### Step 11: Verify Data Ingestion

**Search for Windows events:**
```spl
index=windows_security
```

**Search for Linux events:**
```spl
index=linux_logs
```

**If no results:**
- Wait 1-2 minutes for data to index
- Check forwarder status
- Verify network connectivity
- Check Splunk receiving port

---

## Part 4: SPL Fundamentals (90 minutes)

### Exercise 1: Basic Search Syntax

**SPL (Search Processing Language)** is Splunk's query language.

**Basic search structure:**
```spl
index=<index_name> <search_terms> | <commands>
```

**Search all Windows Security events:**
```spl
index=windows_security
```

**Search with time range:**
```spl
index=windows_security earliest=-1h
```

**Time modifiers:**
- `earliest=-15m` (last 15 minutes)
- `earliest=-1h` (last hour)
- `earliest=-24h` (last 24 hours)
- `earliest=-7d` (last 7 days)

### Exercise 2: Filtering and Field Extraction

**Search for specific Event ID:**
```spl
index=windows_security EventCode=4625
```

**Event ID 4625** = Failed login attempt

**Search with multiple conditions:**
```spl
index=windows_security EventCode=4625 Account_Name!=*$
```

**Operators:**
- `=` equals
- `!=` not equals
- `AND` logical AND
- `OR` logical OR
- `NOT` logical NOT
- `*` wildcard

**Search for failed logins from specific user:**
```spl
index=windows_security EventCode=4625 Account_Name="administrator"
```

### Exercise 3: Using the `stats` Command

**Count failed login attempts:**
```spl
index=windows_security EventCode=4625
| stats count
```

**Count by user:**
```spl
index=windows_security EventCode=4625
| stats count by Account_Name
| sort -count
```

**Count by source IP:**
```spl
index=windows_security EventCode=4625
| stats count by Source_Network_Address
| where count > 10
| sort -count
```

### Exercise 4: Creating Tables

**Create table of failed logins:**
```spl
index=windows_security EventCode=4625
| table _time, Account_Name, Source_Network_Address, Workstation_Name
| sort -_time
```

**Rename fields:**
```spl
index=windows_security EventCode=4625
| table _time, Account_Name, Source_Network_Address
| rename Account_Name as "Username", Source_Network_Address as "Source IP"
```

### Exercise 5: Linux Log Analysis

**Search SSH logins:**
```spl
index=linux_security "sshd" "Accepted"
```

**Search failed SSH attempts:**
```spl
index=linux_security "sshd" "Failed password"
```

**Extract source IPs from SSH failures:**
```spl
index=linux_security "sshd" "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort -count
```

**Search sudo commands:**
```spl
index=linux_security "sudo" "COMMAND"
| rex field=_raw "USER=(?<user>\w+).*COMMAND=(?<command>.*)"
| table _time, user, command
```

### Exercise 6: Time-based Analysis

**Timechart of failed logins:**
```spl
index=windows_security EventCode=4625
| timechart count
```

**Timechart by user:**
```spl
index=windows_security EventCode=4625
| timechart count by Account_Name
```

**Timechart with span:**
```spl
index=windows_security EventCode=4625
| timechart span=1h count
```

---

## Part 5: Security Use Cases (60 minutes)

### Exercise 7: Detect Brute Force Attacks

**Windows RDP brute force:**
```spl
index=windows_security EventCode=4625 Logon_Type=10
| stats count by Source_Network_Address, Account_Name
| where count > 5
| sort -count
```

**SSH brute force:**
```spl
index=linux_security "sshd" "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| where count > 10
| sort -count
```

### Exercise 8: Detect Successful Logins After Failures

**Identify compromised accounts:**
```spl
index=windows_security (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as failures, count(eval(EventCode=4624)) as successes by Account_Name
| where failures > 5 AND successes > 0
| sort -failures
```

### Exercise 9: Detect New User Creation

**Windows user creation (Event ID 4720):**
```spl
index=windows_security EventCode=4720
| table _time, Account_Name, Creator_Subject_Account_Name
| rename Account_Name as "New User", Creator_Subject_Account_Name as "Created By"
```

### Exercise 10: Detect Privilege Escalation

**Detect admin group additions (Event ID 4728):**
```spl
index=windows_security EventCode=4728
| table _time, Group_Name, Member_Name, Subject_Account_Name
| rename Subject_Account_Name as "Added By"
```

### Exercise 11: Web Server Analysis

**Top requested URLs:**
```spl
index=web_logs
| rex field=_raw "\"(?<method>\w+) (?<uri>[^\s]+)"
| stats count by uri
| sort -count
| head 20
```

**Detect web attacks (SQL injection attempts):**
```spl
index=web_logs ("union" OR "select" OR "drop" OR "insert" OR "'" OR "--")
| rex field=_raw "\"(?<method>\w+) (?<uri>[^\s]+)"
| table _time, clientip, method, uri
```

**Detect directory traversal:**
```spl
index=web_logs ("../" OR "..\\" OR "%2e%2e")
| table _time, clientip, uri, status
```

---

## Part 6: Dashboards and Reports (45 minutes)

### Exercise 12: Create Security Dashboard

**Create new dashboard:**
1. **Dashboards → Create New Dashboard**
2. **Title:** "SOC Security Dashboard"
3. **Permissions:** Shared in App
4. **Create Dashboard**

**Add panels:**

**Panel 1: Failed Login Attempts (Last 24h)**
```spl
index=windows_security EventCode=4625 earliest=-24h
| stats count
```
- Visualization: Single Value
- Title: "Failed Login Attempts (24h)"

**Panel 2: Top Failed Login Users**
```spl
index=windows_security EventCode=4625 earliest=-24h
| stats count by Account_Name
| sort -count
| head 10
```
- Visualization: Bar Chart
- Title: "Top 10 Failed Login Users"

**Panel 3: Failed Logins Over Time**
```spl
index=windows_security EventCode=4625 earliest=-24h
| timechart span=1h count
```
- Visualization: Line Chart
- Title: "Failed Logins Timeline"

**Panel 4: SSH Failed Attempts by IP**
```spl
index=linux_security "sshd" "Failed password" earliest=-24h
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort -count
| head 10
```
- Visualization: Pie Chart
- Title: "SSH Brute Force Sources"

### Exercise 13: Create Scheduled Report

**Create report for daily security summary:**

1. **Search & Reporting**
2. **Run search:**
```spl
index=windows_security EventCode=4625 earliest=-24h
| stats count by Account_Name, Source_Network_Address
| sort -count
```
3. **Save As → Report**
4. **Title:** "Daily Failed Login Report"
5. **Schedule:** Daily at 8:00 AM
6. **Email results** (optional)

---

## Deliverables

Submit the following:

1. **Splunk-Lab-Report.md** - Comprehensive lab report
2. **Screenshots/** - Directory containing:
   - Splunk installation completion
   - Web interface dashboard
   - Data ingestion verification
   - SPL search results for all exercises
   - Security dashboard
   - Failed login analysis
   - Brute force detection
3. **SPL-Queries.txt** - All SPL queries used
4. **Dashboard-Export.xml** - Exported dashboard (Settings → Export)

## Report Template

```markdown
# Splunk Introduction Lab Report

**Analyst:** [Your Name]  
**Date:** [Date]  
**Splunk Version:** 9.1.2

---

## 1. Installation

### Splunk Server
- **OS:** Ubuntu 22.04
- **IP Address:** 192.168.56.10
- **Installation Path:** /opt/splunk
- **Web Interface:** http://192.168.56.10:8000

**Screenshot:**
![Splunk Installation](screenshots/splunk-install.png)

---

## 2. Data Onboarding

### Forwarders Configured
- [x] Windows VM (192.168.56.20)
- [x] Linux VM (192.168.56.30)

### Indexes Created
- windows_security
- windows_system
- linux_logs
- linux_security
- web_logs

**Screenshot:**
![Data Ingestion](screenshots/data-ingestion.png)

---

## 3. SPL Queries and Results

### Exercise 1: Failed Login Attempts
**Query:**
```spl
index=windows_security EventCode=4625
| stats count
```

**Result:** 234 failed login attempts

**Screenshot:**
![Failed Logins](screenshots/failed-logins.png)

### Exercise 2: Brute Force Detection
**Query:**
```spl
index=windows_security EventCode=4625
| stats count by Source_Network_Address
| where count > 10
```

**Result:** Detected 3 IPs with >10 failed attempts

---

## 4. Security Findings

### Brute Force Attempts Detected
- **Source IP:** 203.0.113.50
- **Attempts:** 145
- **Target Account:** administrator
- **Recommendation:** Block IP, enforce account lockout policy

---

## 5. Dashboard Created

**Dashboard:** SOC Security Dashboard
- 4 panels created
- Real-time monitoring enabled
- Scheduled refresh: Every 5 minutes

**Screenshot:**
![Dashboard](screenshots/dashboard.png)
```

---

## Evaluation Criteria

- **Installation:** Successfully deployed Splunk Enterprise
- **Data Onboarding:** Configured forwarders and indexes
- **SPL Proficiency:** Executed all search exercises correctly
- **Security Analysis:** Identified security events accurately
- **Dashboard Creation:** Built functional SOC dashboard
- **Documentation:** Professional, complete report

---

## Additional Resources

- [Splunk Documentation](https://docs.splunk.com/)
- [SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)
- [Splunk Boss of the SOC](https://www.splunk.com/en_us/blog/conf-splunklive/boss-of-the-soc-scoring-server-questions-and-answers-and-dataset-open-sourced-and-ready-for-download.html)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Intermediate
