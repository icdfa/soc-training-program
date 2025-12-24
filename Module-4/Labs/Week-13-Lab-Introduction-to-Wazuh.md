# Week 13 Lab: Introduction to Wazuh

## Learning Outcomes

By the end of this lab, you will be able to:

- Install and configure a Wazuh server (manager) with Elasticsearch and Kibana
- Deploy and manage Wazuh agents on Windows and Linux endpoints
- Navigate the Wazuh web interface and analyze security events
- Configure File Integrity Monitoring (FIM) and rootcheck
- Detect security threats using Wazuh rules and decoders
- Investigate security incidents using Wazuh dashboards
- Understand Wazuh's capabilities for Host-based Intrusion Detection (HIDS) and EDR
- Create custom rules for specific security use cases
- Integrate Wazuh with threat intelligence feeds

## Objective

Deploy Wazuh as a comprehensive Host-based Intrusion Detection System (HIDS) and Endpoint Detection and Response (EDR) solution, configure agents for endpoint monitoring, and master threat detection and incident investigation using Wazuh's capabilities.

## Scenario

You are a Senior SOC Analyst at SecureEnterprise Corp. Management has approved the deployment of Wazuh as the organization's primary endpoint security monitoring solution to replace the aging HIDS system. Your responsibilities include:
1. Deploying the Wazuh infrastructure (manager, Elasticsearch, Kibana)
2. Onboarding Windows and Linux endpoints
3. Configuring security monitoring policies
4. Demonstrating threat detection capabilities
5. Training the SOC team on Wazuh operations

## Prerequisites

- Ubuntu Server 22.04 VM (minimum 4GB RAM, 50GB storage)
- Windows 10/11 VM for agent deployment
- Linux VM (Ubuntu/CentOS) for agent deployment
- Root/Administrator access to all systems
- Basic understanding of Linux system administration
- Familiarity with security concepts (file integrity, rootkits, vulnerabilities)

## Lab Duration

Approximately 5-6 hours

---

## Part 1: Understanding Wazuh (30 minutes)

### Step 1: What is Wazuh?

**Wazuh** is an open-source security platform that provides:
- **HIDS (Host-based Intrusion Detection System)**
- **EDR (Endpoint Detection and Response)**
- **Log Data Analysis**
- **File Integrity Monitoring (FIM)**
- **Vulnerability Detection**
- **Configuration Assessment**
- **Incident Response**
- **Regulatory Compliance** (PCI DSS, GDPR, HIPAA)

**Wazuh Architecture:**

```
┌──────────────────────────────────────────────────────────┐
│                    Wazuh Architecture                     │
│                                                           │
│  ┌─────────────┐      ┌─────────────┐                   │
│  │   Agent     │─────▶│             │                   │
│  │  (Windows)  │      │             │                   │
│  └─────────────┘      │   Wazuh     │                   │
│                       │   Manager   │                   │
│  ┌─────────────┐      │             │                   │
│  │   Agent     │─────▶│  - Rules    │                   │
│  │   (Linux)   │      │  - Decoders │                   │
│  └─────────────┘      │  - Analysis │                   │
│                       └──────┬──────┘                   │
│  ┌─────────────┐             │                          │
│  │   Agent     │─────────────┘                          │
│  │  (Server)   │                                        │
│  └─────────────┘             │                          │
│                              ▼                          │
│                       ┌──────────────┐                  │
│                       │Elasticsearch │                  │
│                       │   (Indexer)  │                  │
│                       └──────┬───────┘                  │
│                              │                          │
│                              ▼                          │
│                       ┌──────────────┐                  │
│                       │    Kibana    │                  │
│                       │  (Dashboard) │                  │
│                       └──────────────┘                  │
└──────────────────────────────────────────────────────────┘
```

**Key Components:**

| Component | Purpose | Port |
|-----------|---------|------|
| **Wazuh Manager** | Central server, rule processing, agent management | 1514, 1515, 55000 |
| **Wazuh Agent** | Installed on endpoints, collects logs/events | - |
| **Elasticsearch** | Data storage and indexing | 9200 |
| **Kibana** | Web interface for visualization | 443 |
| **Filebeat** | Log shipper to Elasticsearch | - |

### Step 2: Wazuh Capabilities

**1. File Integrity Monitoring (FIM)**
- Monitors file changes, additions, deletions
- Detects unauthorized modifications
- Tracks registry changes (Windows)

**2. Rootcheck**
- Detects rootkits
- Identifies hidden processes
- Checks system anomalies

**3. Vulnerability Detection**
- Scans for known vulnerabilities
- CVE correlation
- Patch management insights

**4. Configuration Assessment**
- CIS benchmark compliance
- Security configuration checks
- Policy enforcement

**5. Active Response**
- Automated threat mitigation
- Firewall rule updates
- Account lockouts

**6. Log Analysis**
- Centralized log collection
- Pattern matching
- Correlation rules

---

## Part 2: Installing Wazuh Server (90 minutes)

### Step 3: Prepare Ubuntu Server

**System Requirements:**
- **OS:** Ubuntu 22.04 LTS
- **CPU:** 4 cores
- **RAM:** 8GB minimum (16GB recommended)
- **Storage:** 50GB minimum (100GB+ for production)
- **Network:** Static IP address

**Update system:**
```bash
sudo apt update && sudo apt upgrade -y
sudo reboot
```

**Set static IP (if needed):**
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Add:
```yaml
network:
  version: 2
  ethernets:
    ens33:
      addresses: [192.168.56.15/24]
      gateway4: 192.168.56.1
      nameservers:
        addresses: [8.8.8.8, 8.8.4.4]
```

Apply:
```bash
sudo netplan apply
```

### Step 4: Install Wazuh (All-in-One Deployment)

**Download Wazuh installation assistant:**
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
```

**Run installation:**
```bash
sudo bash wazuh-install.sh -a
```

**This installs:**
- Wazuh manager
- Wazuh indexer (Elasticsearch)
- Wazuh dashboard (Kibana)
- Filebeat

**Installation takes 10-15 minutes.**

**Save the admin credentials displayed at the end:**
```
User: admin
Password: [random-password]
```

**IMPORTANT:** Save these credentials securely!

### Step 5: Access Wazuh Dashboard

**Get the dashboard URL:**
```bash
echo "https://$(hostname -I | awk '{print $1}')"
```

**Access from your browser:**
```
https://192.168.56.15
```

**Accept self-signed certificate warning**

**Login:**
- Username: `admin`
- Password: [from installation]

**Welcome to Wazuh Dashboard!**

### Step 6: Verify Installation

**Check Wazuh manager status:**
```bash
sudo systemctl status wazuh-manager
```

**Check indexer status:**
```bash
sudo systemctl status wazuh-indexer
```

**Check dashboard status:**
```bash
sudo systemctl status wazuh-dashboard
```

**All should show "active (running)"**

**Check Wazuh version:**
```bash
/var/ossec/bin/wazuh-control info
```

---

## Part 3: Deploying Wazuh Agents (60 minutes)

### Step 7: Deploy Agent on Windows

**In Wazuh Dashboard:**
1. **Click** "Add agent" (top-right or welcome screen)
2. **Select OS:** Windows
3. **Server address:** 192.168.56.15
4. **Agent name:** WIN-WORKSTATION-01 (or leave default)
5. **Copy the PowerShell command**

**Example command:**
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.0-1.msi -OutFile ${env:tmp}\wazuh-agent.msi; msiexec.exe /i ${env:tmp}\wazuh-agent.msi /q WAZUH_MANAGER='192.168.56.15' WAZUH_AGENT_NAME='WIN-WORKSTATION-01'
```

**On Windows VM (as Administrator):**
1. **Open PowerShell as Administrator**
2. **Paste and run the command**
3. **Wait for installation to complete**

**Start the agent:**
```powershell
NET START WazuhSvc
```

**Verify agent status:**
```powershell
"C:\Program Files (x86)\ossec-agent\wazuh-agent.exe" -h
```

### Step 8: Deploy Agent on Linux

**In Wazuh Dashboard:**
1. **Click** "Add agent"
2. **Select OS:** DEB amd64 (for Ubuntu/Debian)
3. **Server address:** 192.168.56.15
4. **Agent name:** LINUX-SERVER-01
5. **Copy the command**

**Example command:**
```bash
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.0-1_amd64.deb && sudo WAZUH_MANAGER='192.168.56.15' WAZUH_AGENT_NAME='LINUX-SERVER-01' dpkg -i ./wazuh-agent_4.7.0-1_amd64.deb
```

**On Linux VM:**
1. **Run the command**
2. **Wait for installation**

**Start the agent:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

**Verify agent status:**
```bash
sudo systemctl status wazuh-agent
```

### Step 9: Verify Agent Connection

**In Wazuh Dashboard:**
1. **Go to:** Server management → Endpoints Summary
2. **You should see your agents listed**
3. **Status should be:** "Active"

**From command line (on Wazuh server):**
```bash
sudo /var/ossec/bin/agent_control -l
```

**Expected output:**
```
Wazuh agent_control. List of available agents:
   ID: 001, Name: WIN-WORKSTATION-01, IP: 192.168.56.20, Active
   ID: 002, Name: LINUX-SERVER-01, IP: 192.168.56.30, Active
```

---

## Part 4: Configuring File Integrity Monitoring (45 minutes)

### Step 10: Configure FIM on Windows

**On Wazuh server, edit agent configuration:**
```bash
sudo nano /var/ossec/etc/shared/default/agent.conf
```

**Add FIM configuration:**
```xml
<agent_config>
  <!-- File Integrity Monitoring -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    
    <!-- Windows directories -->
    <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
    <directories check_all="yes" realtime="yes">C:\Program Files</directories>
    <directories check_all="yes">C:\Users</directories>
    
    <!-- Windows Registry -->
    <windows_registry>HKEY_LOCAL_MACHINE\Software</windows_registry>
    <windows_registry>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services</windows_registry>
  </syscheck>
</agent_config>
```

**Save and restart manager:**
```bash
sudo systemctl restart wazuh-manager
```

**Agents will automatically receive the new configuration.**

### Step 11: Configure FIM on Linux

**Add Linux directories to agent.conf:**
```xml
<agent_config os="Linux">
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    
    <!-- Linux directories -->
    <directories check_all="yes" realtime="yes">/etc</directories>
    <directories check_all="yes" realtime="yes">/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin</directories>
    <directories check_all="yes">/var/www</directories>
  </syscheck>
</agent_config>
```

**Restart manager:**
```bash
sudo systemctl restart wazuh-manager
```

### Step 12: Test File Integrity Monitoring

**On Windows:**
```powershell
# Create a test file in monitored directory
echo "Test file" > C:\Windows\System32\test_fim.txt
```

**On Linux:**
```bash
# Create a test file
sudo touch /etc/test_fim.txt
sudo echo "Test content" > /etc/test_fim.txt
```

**In Wazuh Dashboard:**
1. **Go to:** Security events
2. **Filter:** `rule.groups:syscheck`
3. **You should see FIM alerts**

---

## Part 5: Generating and Analyzing Security Events (60 minutes)

### Exercise 1: Detect Failed Login Attempts

**On Windows:**
```powershell
# Generate failed RDP login attempts
# Try logging in with wrong password multiple times
```

**On Linux:**
```bash
# Generate failed SSH attempts
ssh wronguser@localhost
# Enter wrong password 5 times
```

**In Wazuh Dashboard:**
1. **Security events**
2. **Filter:** `rule.id:5710` (Windows) or `rule.id:5551` (Linux)
3. **Analyze the alerts**

### Exercise 2: Detect New User Creation

**On Windows (as Administrator):**
```powershell
net user testuser P@ssw0rd123 /add
```

**On Linux:**
```bash
sudo useradd -m testuser
sudo passwd testuser
```

**In Wazuh Dashboard:**
1. **Filter:** `rule.groups:account_changed`
2. **Look for user creation events**
3. **Rule ID 5902** (Windows) or **Rule ID 5901** (Linux)

### Exercise 3: Detect Service Manipulation

**On Windows:**
```powershell
# Stop Windows Defender
Stop-Service WinDefend
```

**On Linux:**
```bash
# Stop SSH service
sudo systemctl stop ssh
```

**In Wazuh Dashboard:**
1. **Filter:** `rule.groups:service_control`
2. **Analyze service stop events**

### Exercise 4: Detect Malware Simulation

**Download EICAR test file (harmless malware test):**

**On Windows:**
```powershell
Invoke-WebRequest -Uri "https://secure.eicar.org/eicar.com" -OutFile "C:\Users\Public\eicar.com"
```

**On Linux:**
```bash
wget https://secure.eicar.org/eicar.com -O /tmp/eicar.com
```

**Wazuh should detect this as potential malware.**

### Exercise 5: Rootcheck Scan

**Force rootcheck scan on agent:**

**On Wazuh server:**
```bash
# Trigger rootcheck on agent 001 (Windows)
sudo /var/ossec/bin/agent_control -r -u 001

# Trigger rootcheck on agent 002 (Linux)
sudo /var/ossec/bin/agent_control -r -u 002
```

**In Wazuh Dashboard:**
1. **Go to:** Modules → Security Configuration Assessment
2. **Select agent**
3. **Review rootcheck results**

---

## Part 6: Vulnerability Detection (30 minutes)

### Step 13: Enable Vulnerability Detection

**Edit ossec.conf on Wazuh manager:**
```bash
sudo nano /var/ossec/etc/ossec.conf
```

**Ensure vulnerability detection is enabled:**
```xml
<vulnerability-detector>
  <enabled>yes</enabled>
  <interval>5m</interval>
  <run_on_start>yes</run_on_start>
  
  <!-- Ubuntu/Debian -->
  <provider name="canonical">
    <enabled>yes</enabled>
    <os>jammy</os>
    <update_interval>1h</update_interval>
  </provider>
  
  <!-- Windows -->
  <provider name="msu">
    <enabled>yes</enabled>
    <update_interval>1h</update_interval>
  </provider>
</vulnerability-detector>
```

**Restart manager:**
```bash
sudo systemctl restart wazuh-manager
```

### Step 14: View Vulnerability Scan Results

**In Wazuh Dashboard:**
1. **Go to:** Modules → Vulnerabilities
2. **Select an agent**
3. **Review detected vulnerabilities:**
   - CVE IDs
   - Severity levels
   - Affected packages
   - Remediation recommendations

---

## Part 7: Custom Rules and Active Response (45 minutes)

### Step 15: Create Custom Rule

**Scenario:** Detect when someone accesses a sensitive file.

**Create custom rule:**
```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

**Add:**
```xml
<group name="local,syscheck,">
  <rule id="100001" level="12">
    <if_sid>550</if_sid>
    <field name="file">/etc/shadow</field>
    <description>Sensitive file /etc/shadow was accessed</description>
    <group>pci_dss_11.5,gdpr_II_5.1.f,</group>
  </rule>
</group>
```

**Restart manager:**
```bash
sudo systemctl restart wazuh-manager
```

**Test:**
```bash
# On Linux agent
sudo cat /etc/shadow
```

### Step 16: Configure Active Response

**Active response automatically reacts to threats.**

**Example: Block IP after 5 failed SSH attempts**

**Edit ossec.conf:**
```bash
sudo nano /var/ossec/etc/ossec.conf
```

**Add:**
```xml
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5710,5551</rules_id>
  <timeout>300</timeout>
</active-response>
```

**This will:**
- Trigger on failed login attempts (rules 5710, 5551)
- Block the source IP for 300 seconds (5 minutes)

**Restart manager:**
```bash
sudo systemctl restart wazuh-manager
```

---

## Part 8: Dashboards and Reporting (30 minutes)

### Step 17: Explore Built-in Dashboards

**In Wazuh Dashboard, explore:**

1. **Security Events:** Real-time security alerts
2. **Integrity Monitoring:** File changes
3. **Vulnerabilities:** CVE detections
4. **Regulatory Compliance:** PCI DSS, GDPR, HIPAA
5. **MITRE ATT&CK:** Threat framework mapping
6. **Security Configuration Assessment:** CIS benchmarks

### Step 18: Create Custom Dashboard

1. **Dashboard → Create new dashboard**
2. **Add visualizations:**
   - Top security events
   - Failed login attempts by agent
   - File integrity changes timeline
   - Vulnerability severity distribution
3. **Save dashboard:** "SOC Security Overview"

---

## Deliverables

Submit the following:

1. **Wazuh-Lab-Report.md** - Comprehensive lab report
2. **Screenshots/** - Directory containing:
   - Wazuh installation completion
   - Dashboard with active agents
   - Security events for each exercise
   - FIM alerts
   - Vulnerability scan results
   - Custom rule triggering
   - Active response in action
3. **Configurations/** - Directory containing:
   - `agent.conf` (FIM configuration)
   - `local_rules.xml` (custom rules)
   - `ossec.conf` (active response config)

## Report Template

```markdown
# Wazuh HIDS/EDR Lab Report

**Analyst:** [Your Name]  
**Date:** [Date]  
**Wazuh Version:** 4.7.0

---

## 1. Installation

### Wazuh Server
- **OS:** Ubuntu 22.04
- **IP:** 192.168.56.15
- **Components:** Manager, Indexer, Dashboard

**Screenshot:**
![Wazuh Dashboard](screenshots/wazuh-dashboard.png)

---

## 2. Agents Deployed

| Agent ID | Name | OS | IP | Status |
|----------|------|----|----|--------|
| 001 | WIN-WORKSTATION-01 | Windows 10 | 192.168.56.20 | Active |
| 002 | LINUX-SERVER-01 | Ubuntu 22.04 | 192.168.56.30 | Active |

**Screenshot:**
![Agents](screenshots/agents.png)

---

## 3. Security Events Detected

### Failed Login Attempts
- **Agent:** WIN-WORKSTATION-01
- **Rule ID:** 5710
- **Count:** 12 attempts
- **Source:** 192.168.56.50

**Screenshot:**
![Failed Logins](screenshots/failed-logins.png)

### User Creation
- **Agent:** LINUX-SERVER-01
- **Rule ID:** 5901
- **User Created:** testuser
- **Created By:** root

---

## 4. File Integrity Monitoring

### Changes Detected
- **File:** /etc/passwd
- **Change Type:** Modified
- **Agent:** LINUX-SERVER-01
- **Timestamp:** [Time]

**Screenshot:**
![FIM Alert](screenshots/fim-alert.png)

---

## 5. Vulnerability Assessment

### Critical Vulnerabilities
- **CVE-2023-XXXX:** OpenSSL vulnerability
- **Severity:** High
- **Affected Package:** openssl-1.1.1
- **Recommendation:** Update to version 1.1.1w

---

## 6. Custom Rules

### Rule Created
- **Rule ID:** 100001
- **Purpose:** Detect /etc/shadow access
- **Severity:** Level 12 (High)
- **Status:** Tested and working

---

## 7. Recommendations

1. Deploy agents to all endpoints
2. Configure FIM for critical directories
3. Enable vulnerability scanning
4. Implement active response for brute force
5. Integrate with SIEM for correlation
```

---

## Evaluation Criteria

- **Installation:** Successfully deployed Wazuh infrastructure
- **Agent Deployment:** Configured agents on multiple platforms
- **Configuration:** Properly configured FIM and monitoring
- **Event Analysis:** Identified and analyzed security events
- **Custom Rules:** Created and tested custom detection rules
- **Documentation:** Professional, comprehensive report

---

## Additional Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh Rules](https://documentation.wazuh.com/current/user-manual/ruleset/index.html)
- [MITRE ATT&CK Integration](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html)
- [Wazuh GitHub](https://github.com/wazuh/wazuh)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Advanced
