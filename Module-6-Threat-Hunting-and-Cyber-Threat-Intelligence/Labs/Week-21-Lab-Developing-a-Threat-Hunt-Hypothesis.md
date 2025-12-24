# Week 21 Lab: Developing a Threat Hunt Hypothesis

## Learning Outcomes

By the end of this lab, you will be able to:

- Understand the fundamentals of proactive threat hunting
- Develop structured threat hunting hypotheses using multiple frameworks
- Identify and prioritize data sources for threat hunting
- Create effective search queries across multiple platforms (Splunk, ELK, Kusto)
- Apply the MITRE ATT&CK framework to threat hunting
- Conduct hypothesis-driven threat hunts
- Document and communicate hunting findings
- Measure the effectiveness of threat hunting operations
- Develop playbooks for repeatable threat hunts

## Objective

Master the art and science of proactive threat hunting by developing structured hypotheses, leveraging threat intelligence, applying the MITRE ATT&CK framework, and conducting data-driven investigations to uncover hidden threats in enterprise environments.

## Scenario

You are a Threat Hunter at GlobalCorp, a multinational financial services company. The Threat Intelligence team has issued an alert about a new ransomware variant called **"LockData"** that is actively targeting financial institutions. Intelligence reports indicate:

**LockData Ransomware Profile:**
- **Initial Access:** Spear-phishing with malicious Office documents
- **Execution:** PowerShell-based payload
- **Persistence:** Scheduled tasks and registry modifications
- **Lateral Movement:** PsExec and WMI
- **Impact:** File encryption with .lockdata extension
- **Ransom Note:** README_DECRYPT.txt
- **C2 Communication:** HTTPS to compromised WordPress sites
- **Typical Dwell Time:** 3-7 days before encryption

Your CISO has tasked you with conducting a proactive threat hunt to determine if LockData (or similar ransomware) has gained a foothold in the organization's network. You must develop comprehensive hunting hypotheses, identify data sources, create detection queries, and execute the hunt.

## Prerequisites

- Access to SIEM (Splunk, ELK, or similar)
- Windows Event Logs from endpoints
- EDR/HIDS data (Wazuh, Sysmon, etc.)
- Network traffic logs (firewall, proxy)
- Understanding of MITRE ATT&CK framework
- Familiarity with Windows internals
- Basic knowledge of ransomware TTPs

## Lab Duration

Approximately 5-6 hours

---

## Part 1: Understanding Threat Hunting (30 minutes)

### Step 1: What is Threat Hunting?

**Threat Hunting** is the proactive and iterative process of searching through networks and datasets to detect and isolate advanced threats that evade existing security solutions.

**Key Characteristics:**

| Aspect | Description |
|--------|-------------|
| **Proactive** | Don't wait for alerts; actively search |
| **Hypothesis-Driven** | Based on threat intelligence and TTPs |
| **Iterative** | Continuous process, not one-time |
| **Human-Led** | Requires analyst expertise and intuition |
| **Data-Driven** | Leverages logs, telemetry, and analytics |

**Threat Hunting vs. Incident Response:**

| Threat Hunting | Incident Response |
|----------------|-------------------|
| Proactive | Reactive |
| Hypothesis-driven | Alert-driven |
| Assumes compromise | Responds to confirmed incidents |
| Finds unknown threats | Handles known incidents |

### Step 2: The Threat Hunting Loop

```
┌─────────────────────────────────────────────────────┐
│           The Threat Hunting Cycle                  │
│                                                     │
│  1. Hypothesis Development                          │
│     ↓                                               │
│  2. Data Collection & Preparation                   │
│     ↓                                               │
│  3. Investigation & Analysis                        │
│     ↓                                               │
│  4. Pattern & Anomaly Detection                     │
│     ↓                                               │
│  5. Response & Mitigation                           │
│     ↓                                               │
│  6. Documentation & Lessons Learned                 │
│     ↓                                               │
│  7. Detection Engineering (Create Rules)            │
│     ↓                                               │
│  [Loop back to step 1]                              │
└─────────────────────────────────────────────────────┘
```

### Step 3: Types of Threat Hunting

**1. Intelligence-Driven Hunting**
- Based on threat intelligence (IOCs, TTPs)
- Example: Hunt for specific malware family

**2. Hypothesis-Driven Hunting**
- Based on assumptions about attacker behavior
- Example: "Attackers are using living-off-the-land binaries"

**3. Situational Awareness Hunting**
- Based on environmental changes
- Example: New software deployment, network changes

**4. Baseline Hunting**
- Based on deviations from normal behavior
- Example: Unusual process execution patterns

---

## Part 2: Developing Threat Hunting Hypotheses (60 minutes)

### Step 4: Hypothesis Development Framework

**A good hypothesis is:**
- **Specific:** Clearly defined threat/technique
- **Measurable:** Can be tested with data
- **Actionable:** Can lead to detection/response
- **Relevant:** Applicable to your environment
- **Time-bound:** Scoped to specific timeframe

**Hypothesis Template:**
```
IF [threat actor/malware] is present in our environment,
THEN we should observe [specific behavior/artifact]
IN [data source]
USING [detection method/query]
```

### Step 5: LockData Ransomware Hypothesis Development

**Hypothesis 1: Initial Access via Phishing**

```
IF LockData ransomware entered our environment via spear-phishing,
THEN we should observe suspicious Office document executions followed by PowerShell
IN Windows Event Logs (Event ID 4688) and Sysmon logs
USING queries for winword.exe/excel.exe spawning powershell.exe
```

**Hypothesis 2: Lateral Movement via PsExec**

```
IF LockData is performing lateral movement,
THEN we should observe PsExec execution and related network connections
IN Windows Event Logs, Sysmon, and network logs
USING queries for psexesvc.exe, named pipes, and SMB connections
```

**Hypothesis 3: Persistence via Scheduled Tasks**

```
IF LockData has established persistence,
THEN we should observe suspicious scheduled task creation
IN Windows Event Logs (Event ID 4698) and Sysmon
USING queries for task creation with unusual paths or commands
```

**Hypothesis 4: Data Staging Before Encryption**

```
IF LockData is preparing for encryption,
THEN we should observe large file operations and data staging
IN file system logs and EDR telemetry
USING queries for mass file access and compression activities
```

**Hypothesis 5: Ransomware Execution**

```
IF LockData ransomware has executed,
THEN we should observe mass file modifications and ransom note creation
IN file integrity monitoring and EDR logs
USING queries for .lockdata extensions and README_DECRYPT.txt
```

### Step 6: MITRE ATT&CK Mapping

Map LockData TTPs to MITRE ATT&CK:

| Tactic | Technique | ID | Hunt Focus |
|--------|-----------|----|-----------| 
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | Office docs with macros |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell execution |
| Persistence | Scheduled Task/Job | T1053.005 | Task creation |
| Privilege Escalation | Exploitation for Privilege Escalation | T1068 | Exploit usage |
| Defense Evasion | Obfuscated Files or Information | T1027 | Encoded PowerShell |
| Credential Access | OS Credential Dumping | T1003 | LSASS access |
| Discovery | System Information Discovery | T1082 | Recon commands |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | PsExec, WMI |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | HTTPS C2 |
| Impact | Data Encrypted for Impact | T1486 | File encryption |

---

## Part 3: Identifying Data Sources (45 minutes)

### Step 7: Data Source Mapping

**For LockData hunt, we need:**

| Data Source | Purpose | Key Events |
|-------------|---------|------------|
| **Windows Event Logs** | Process execution, logons, task creation | 4688, 4624, 4698 |
| **Sysmon** | Detailed process, network, file activity | 1, 3, 11, 13 |
| **EDR/HIDS** | Endpoint behavior, file changes | Process trees, FIM |
| **Firewall Logs** | Network connections, blocked traffic | Allow/deny rules |
| **Proxy Logs** | Web traffic, C2 communication | HTTP/HTTPS requests |
| **DNS Logs** | Domain resolutions, tunneling | DNS queries |
| **Email Logs** | Phishing emails, attachments | Email metadata |
| **File System Logs** | File operations, modifications | Create/modify/delete |

### Step 8: Data Availability Assessment

**Check what data you have:**

**In Splunk:**
```spl
| metadata type=sourcetypes | table sourcetype
```

**Check Windows Event Logs:**
```spl
index=windows sourcetype=WinEventLog:*
| stats count by sourcetype
```

**Check Sysmon availability:**
```spl
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| stats count by EventCode
```

**Identify gaps:**
- Missing Sysmon? Install it!
- No PowerShell logging? Enable it!
- Limited network visibility? Add network sensors!

---

## Part 4: Creating Detection Queries (90 minutes)

### Exercise 1: Hunt for Phishing Initial Access

**Hypothesis:** Office documents spawning PowerShell

**Splunk Query:**
```spl
index=windows EventCode=4688
(ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe")
NewProcessName="*\\powershell.exe"
| table _time, ComputerName, ParentImage, NewProcessName, CommandLine, SubjectUserName
| sort -_time
```

**Sysmon Query (Event ID 1 - Process Creation):**
```spl
index=windows EventCode=1 sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"
(ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE")
Image="*\\powershell.exe"
| table _time, Computer, ParentImage, Image, CommandLine, User
```

**Look for:**
- Encoded PowerShell commands (`-enc`, `-e`)
- Download cradles (`IEX`, `Invoke-WebRequest`, `DownloadString`)
- Obfuscation (random variable names, base64)

### Exercise 2: Hunt for PsExec Lateral Movement

**Hypothesis:** PsExec usage for lateral movement

**Splunk Query - PsExec Service:**
```spl
index=windows EventCode=4688 NewProcessName="*\\psexesvc.exe"
| table _time, ComputerName, SubjectUserName, NewProcessName, ParentProcessName
| sort -_time
```

**Sysmon Query - Named Pipe (Event ID 17/18):**
```spl
index=windows (EventCode=17 OR EventCode=18) PipeName="\\psexesvc"
| table _time, Computer, PipeName, Image, User
```

**Network Connection Query (Sysmon Event ID 3):**
```spl
index=windows EventCode=3 DestinationPort=445
Image="*\\psexec.exe"
| table _time, Computer, Image, SourceIp, DestinationIp, DestinationPort
| stats count by SourceIp, DestinationIp
```

**Windows Event Log - Service Installation (Event ID 7045):**
```spl
index=windows EventCode=7045 ServiceName="PSEXESVC"
| table _time, ComputerName, ServiceName, ServiceFileName, AccountName
```

### Exercise 3: Hunt for Suspicious Scheduled Tasks

**Hypothesis:** Scheduled tasks for persistence

**Splunk Query - Task Creation (Event ID 4698):**
```spl
index=windows EventCode=4698
| rex field=TaskContent "<Command>(?<Command>[^<]+)</Command>"
| rex field=TaskContent "<Arguments>(?<Arguments>[^<]+)</Arguments>"
| table _time, ComputerName, TaskName, Command, Arguments, SubjectUserName
| search Command="*\\powershell.exe" OR Command="*\\cmd.exe" OR Command="*\\wscript.exe"
```

**Sysmon Query - Task Scheduler (Event ID 1):**
```spl
index=windows EventCode=1 ParentImage="*\\schtasks.exe"
| table _time, Computer, CommandLine, User
```

**Look for:**
- Tasks running from unusual paths (Temp, AppData)
- Tasks with obfuscated commands
- Tasks running as SYSTEM

### Exercise 4: Hunt for Data Staging

**Hypothesis:** Attackers staging data before exfiltration

**Splunk Query - Large Archive Creation:**
```spl
index=windows EventCode=1
(Image="*\\7z.exe" OR Image="*\\winrar.exe" OR Image="*\\zip.exe")
CommandLine="*C:\\Users\\*" OR CommandLine="*C:\\Temp\\*"
| table _time, Computer, Image, CommandLine, User
```

**File Creation in Staging Directories:**
```spl
index=windows EventCode=11 TargetFilename="C:\\Users\\Public\\*"
| stats count by Computer, TargetFilename
| where count > 100
```

### Exercise 5: Hunt for Ransomware Execution

**Hypothesis:** Mass file encryption activity

**Splunk Query - Mass File Modifications:**
```spl
index=windows EventCode=11
| rex field=TargetFilename "\.(?<extension>\w+)$"
| stats count by Computer, extension, User
| where count > 100
| sort -count
```

**Ransom Note Creation:**
```spl
index=windows EventCode=11 TargetFilename="*README_DECRYPT.txt"
| table _time, Computer, TargetFilename, User, Image
```

**Suspicious Process with High File Activity:**
```spl
index=windows EventCode=11
| stats count by Computer, Image
| where count > 500
| sort -count
```

### Exercise 6: Hunt for C2 Communication

**Hypothesis:** HTTPS C2 to compromised WordPress sites

**Proxy Log Query:**
```spl
index=proxy
| rex field=url "(?<domain>[^/]+)"
| search url="*/wp-content/*" OR url="*/wp-includes/*"
| stats count by src_ip, domain
| where count > 50
```

**DNS Query for Suspicious Domains:**
```spl
index=dns
| rare limit=20 query
| search query!="*.microsoft.com" query!="*.google.com"
```

---

## Part 5: Executing the Threat Hunt (60 minutes)

### Step 9: Hunt Execution Plan

**Create a structured hunt plan:**

```markdown
# LockData Ransomware Threat Hunt Plan

## Hunt Metadata
- **Hunt ID:** TH-2024-001
- **Hunter:** [Your Name]
- **Date:** 2024-01-15
- **Duration:** 4 hours
- **Priority:** High

## Scope
- **Timeframe:** Last 30 days
- **Systems:** All Windows endpoints (2,500 hosts)
- **Data Sources:** Windows Event Logs, Sysmon, EDR, Network logs

## Hypotheses
1. Initial access via phishing
2. Lateral movement via PsExec
3. Persistence via scheduled tasks
4. Data staging before encryption
5. Ransomware execution

## Execution Order
1. Start with highest-fidelity hypothesis (PsExec)
2. Work backwards to initial access
3. Work forwards to impact
4. Correlate findings across hypotheses
```

### Step 10: Execute Queries and Analyze Results

**Step-by-step execution:**

**1. Run PsExec query:**
```spl
index=windows EventCode=4688 NewProcessName="*\\psexesvc.exe" earliest=-30d
| stats count by ComputerName, SubjectUserName
```

**Result:** 3 hosts with PsExec activity

**2. Investigate suspicious hosts:**
```spl
index=windows ComputerName="FINANCE-WS05" earliest=-30d
| stats count by EventCode, NewProcessName
| sort -count
```

**3. Build timeline for suspicious host:**
```spl
index=windows ComputerName="FINANCE-WS05" earliest=-30d
| table _time, EventCode, NewProcessName, CommandLine, SubjectUserName
| sort _time
```

**4. Pivot to parent process:**
```spl
index=windows ComputerName="FINANCE-WS05" EventCode=1 earliest=-30d
| table _time, ParentImage, Image, CommandLine
| sort _time
```

**5. Check for ransomware indicators:**
```spl
index=windows ComputerName="FINANCE-WS05" EventCode=11 earliest=-30d
| rex field=TargetFilename "\.(?<extension>\w+)$"
| stats count by extension
| sort -count
```

### Step 11: Document Findings

**For each finding, document:**
- **What:** What did you find?
- **Where:** Which system(s)?
- **When:** Timestamp of activity
- **Who:** User/process involved
- **How:** Technique used
- **Why:** Malicious or benign?

---

## Part 6: Response and Detection Engineering (45 minutes)

### Step 12: Triage Findings

**Classification:**

| Finding | Severity | Confidence | Action |
|---------|----------|------------|--------|
| PsExec on FINANCE-WS05 | High | High | Escalate to IR |
| Scheduled task on HR-WS12 | Medium | Medium | Investigate further |
| PowerShell from Word | High | High | Escalate to IR |
| Mass file changes | Critical | High | Immediate isolation |

### Step 13: Create Detection Rules

**Convert hunt queries to automated detections:**

**Splunk Alert - PsExec Detection:**
```spl
index=windows EventCode=4688 NewProcessName="*\\psexesvc.exe"
| stats count by ComputerName, SubjectUserName
| where count > 0
```

**Schedule:** Every 5 minutes
**Action:** Create notable event, send email

**Suricata Rule - PsExec Network Traffic:**
```
alert tcp any any -> any 445 (msg:"Possible PsExec Activity"; content:"|ff|SMB"; offset:4; depth:5; content:"psexesvc"; nocase; sid:1000001; rev:1;)
```

### Step 14: Improve Detection Coverage

**Recommendations:**
1. **Enable PowerShell logging** (Event ID 4104)
2. **Deploy Sysmon** with comprehensive config
3. **Implement EDR** on all endpoints
4. **Enhance network monitoring** (Zeek, Suricata)
5. **Create detection rules** from hunt findings

---

## Deliverables

Submit the following:

1. **Threat-Hunt-Report.md** - Comprehensive hunt report
2. **Hypotheses/** - Directory containing:
   - `hypothesis-1-initial-access.md`
   - `hypothesis-2-lateral-movement.md`
   - `hypothesis-3-persistence.md`
   - `hypothesis-4-data-staging.md`
   - `hypothesis-5-ransomware-execution.md`
3. **Queries/** - Directory containing:
   - `splunk-queries.txt`
   - `sysmon-queries.txt`
   - `network-queries.txt`
4. **Findings/** - Directory containing:
   - `suspicious-hosts.csv`
   - `iocs-extracted.txt`
   - `timeline-of-events.md`
5. **Detection-Rules/** - Directory containing:
   - `splunk-alerts.txt`
   - `suricata-rules.txt`
   - `yara-rules.yar`

## Report Template

```markdown
# Threat Hunt Report: LockData Ransomware

**Hunt ID:** TH-2024-001  
**Hunter:** [Your Name]  
**Date:** 2024-01-15  
**Duration:** 4 hours  
**Status:** Completed

---

## Executive Summary

[2-3 sentence summary of hunt and findings]

**Key Findings:**
- [Number] suspicious hosts identified
- [Number] confirmed malicious activities
- [Number] false positives
- Ransomware detected: [Yes/No]

---

## 1. Hunt Scope

### Timeframe
- **Start:** 2023-12-15 00:00:00
- **End:** 2024-01-15 23:59:59
- **Duration:** 30 days

### Systems Covered
- **Total Hosts:** 2,500
- **Windows Endpoints:** 2,200
- **Servers:** 300

### Data Sources
- Windows Event Logs (Security, System, Application)
- Sysmon logs
- EDR telemetry (Wazuh)
- Network logs (Firewall, Proxy)
- DNS logs

---

## 2. Hypotheses Tested

### Hypothesis 1: Initial Access via Phishing
**Status:** ✅ Confirmed  
**Findings:** 3 instances of Office documents spawning PowerShell

**Evidence:**
```
Host: FINANCE-WS05
Time: 2024-01-10 14:23:45
Process: WINWORD.EXE → powershell.exe -enc [base64]
User: jdoe
```

### Hypothesis 2: Lateral Movement via PsExec
**Status:** ✅ Confirmed  
**Findings:** PsExec activity detected on 3 hosts

**Evidence:**
```
Source: FINANCE-WS05
Targets: FINANCE-WS06, FINANCE-WS07
Time: 2024-01-10 15:30:00 - 16:45:00
User: jdoe
```

### Hypothesis 3: Persistence via Scheduled Tasks
**Status:** ✅ Confirmed  
**Findings:** Suspicious scheduled task created

**Evidence:**
```
Host: FINANCE-WS05
Task Name: WindowsUpdate
Command: C:\Users\jdoe\AppData\Local\Temp\update.exe
Created: 2024-01-10 14:30:00
```

### Hypothesis 4: Data Staging
**Status:** ⚠️ Inconclusive  
**Findings:** No clear evidence of data staging

### Hypothesis 5: Ransomware Execution
**Status:** ❌ Not Detected  
**Findings:** No mass file encryption detected

---

## 3. Detailed Findings

### Finding 1: Malicious PowerShell Execution
- **Host:** FINANCE-WS05
- **Severity:** Critical
- **Confidence:** High
- **MITRE ATT&CK:** T1059.001 (PowerShell)

**Description:**
Encoded PowerShell command executed from Word document.

**IOCs:**
- File: malicious_invoice.docm
- Hash: abc123def456...
- C2: hxxps://compromised-site[.]com/wp-content/update.php

**Recommendation:**
Isolate FINANCE-WS05, conduct full forensic analysis.

---

## 4. IOCs Extracted

### File Hashes
```
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Network IOCs
```
203.0.113.50 (C2 Server)
compromised-site.com
malicious-domain.tk
```

### Registry IOCs
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
```

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|---------| 
| Initial Access | Phishing: Spearphishing Attachment | T1566.001 | malicious_invoice.docm |
| Execution | PowerShell | T1059.001 | Encoded PowerShell |
| Persistence | Scheduled Task | T1053.005 | WindowsUpdate task |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 | PsExec activity |

---

## 6. Detection Rules Created

### Splunk Alert: PsExec Detection
```spl
index=windows EventCode=4688 NewProcessName="*\\psexesvc.exe"
| stats count by ComputerName, SubjectUserName
```

### Suricata Rule: PsExec Network Traffic
```
alert tcp any any -> any 445 (msg:"PsExec Activity"; content:"psexesvc"; sid:1000001;)
```

---

## 7. Recommendations

### Immediate Actions
1. **Isolate affected hosts:** FINANCE-WS05, FINANCE-WS06, FINANCE-WS07
2. **Block IOCs** at firewall/proxy
3. **Reset credentials** for user jdoe
4. **Conduct forensic analysis** on isolated hosts
5. **Scan all endpoints** for malicious_invoice.docm

### Short-term Improvements
1. Deploy Sysmon on all endpoints
2. Enable PowerShell logging (Event ID 4104)
3. Implement application whitelisting
4. Enhance email security (sandbox attachments)
5. Deploy EDR solution

### Long-term Strategy
1. Establish regular threat hunting program
2. Develop threat hunting playbooks
3. Integrate threat intelligence feeds
4. Implement SOAR for automated response
5. Conduct purple team exercises

---

## 8. Lessons Learned

### What Worked Well
- Hypothesis-driven approach was effective
- MITRE ATT&CK mapping helped focus hunt
- Sysmon provided critical visibility

### Challenges
- Limited historical data (only 30 days)
- Some endpoints missing Sysmon
- High volume of false positives in initial queries

### Improvements for Next Hunt
- Extend data retention to 90 days
- Deploy Sysmon universally
- Refine queries to reduce false positives
- Automate more of the hunt process

---

## Appendix

### Queries Used
[Include all Splunk/ELK queries]

### Timeline of Attack
[Detailed timeline from initial access to lateral movement]

### References
- MITRE ATT&CK: https://attack.mitre.org/
- LockData Ransomware Report: [Link]
- Internal Threat Intelligence Report: TI-2024-001

---

**Hunt Completed:** 2024-01-15 18:00:00  
**Report Version:** 1.0  
**Next Hunt Scheduled:** 2024-02-15
```

---

## Evaluation Criteria

- **Hypothesis Quality:** Well-structured, testable hypotheses
- **Query Effectiveness:** Accurate, efficient detection queries
- **Analysis Depth:** Thorough investigation of findings
- **MITRE ATT&CK Mapping:** Correct technique identification
- **Detection Engineering:** Effective automated detection rules
- **Documentation:** Professional, comprehensive report
- **Actionable Recommendations:** Practical improvements

---

## Additional Resources

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Threat Hunting Project](https://www.threathunting.net/)
- [SANS Threat Hunting](https://www.sans.org/cyber-security-courses/advanced-threat-hunting-incident-response-threat-intelligence/)
- [Sqrrl Threat Hunting Reference](https://www.threathunting.net/sqrrl-archive)
- [Cyber Threat Hunting Book](https://www.amazon.com/Practical-Threat-Intelligence-Threat-Hunting-ebook/dp/B07L3JBHZD)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Expert
