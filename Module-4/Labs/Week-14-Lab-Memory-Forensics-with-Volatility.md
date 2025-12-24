# Week 14 Lab: Memory Forensics with Volatility

## Learning Outcomes

By the end of this lab, you will be able to:

- Understand the fundamentals of memory forensics and its importance in incident response
- Install and configure Volatility 3 for memory analysis
- Identify operating system information and system details from memory dumps
- Analyze running processes, DLLs, and handles in memory
- Detect malware, rootkits, and code injection in memory
- Investigate network connections and registry artifacts
- Extract files, passwords, and encryption keys from memory
- Correlate memory artifacts with MITRE ATT&CK techniques
- Create comprehensive memory forensics reports

## Objective

Master advanced memory forensics techniques using Volatility to investigate compromised systems, detect sophisticated malware, identify attacker TTPs, and extract critical evidence from RAM dumps for incident response and threat hunting.

## Scenario

You are a Senior Incident Response Analyst at CyberDefense Corp. The Security Operations Center has escalated a critical incident involving a suspected APT (Advanced Persistent Threat) compromise of a Windows workstation in the finance department. The system exhibited suspicious behavior including:
- Unusual outbound network connections
- Unknown processes running
- Potential data exfiltration
- Anti-forensics techniques detected

The system has been isolated and a memory dump was captured before shutdown. Your task is to perform a comprehensive memory forensics investigation to:
1. Identify the malware and its capabilities
2. Determine the scope of compromise
3. Extract IOCs for threat hunting
4. Understand the attacker's techniques
5. Provide actionable recommendations

## Prerequisites

- Linux system (Ubuntu 22.04 recommended) or Windows with Python
- Python 3.8+ installed
- 8GB+ RAM (16GB recommended)
- 20GB+ free disk space
- Basic understanding of Windows internals
- Familiarity with malware behavior

## Lab Duration

Approximately 5-6 hours

---

## Part 1: Understanding Memory Forensics (30 minutes)

### Step 1: What is Memory Forensics?

**Memory Forensics** is the analysis of volatile memory (RAM) to:
- Detect malware and rootkits
- Identify running processes and services
- Extract encryption keys and passwords
- Analyze network connections
- Recover deleted/hidden data
- Investigate fileless malware
- Understand attacker TTPs

**Why Memory Forensics?**

| Advantage | Description |
|-----------|-------------|
| **Volatile Data** | Captures running state, not just disk artifacts |
| **Malware Detection** | Finds in-memory-only malware (fileless) |
| **Decrypted Data** | Access to decrypted data in RAM |
| **Active Connections** | See live network connections |
| **Bypasses Anti-Forensics** | Harder for attackers to hide in memory |
| **Timeline Reconstruction** | Understand sequence of events |

### Step 2: Memory Acquisition Methods

**Live Acquisition (system running):**
- FTK Imager
- DumpIt
- WinPmem
- LiME (Linux)

**Virtual Machine:**
- VMware: .vmem files
- VirtualBox: Save state
- Hyper-V: .bin files

**Crash Dumps:**
- Windows: memory.dmp
- Linux: /proc/kcore

### Step 3: Volatility Overview

**Volatility** is the leading open-source memory forensics framework.

**Volatility 3 Features:**
- Cross-platform (Windows, Linux, Mac)
- Plugin architecture
- Symbol support
- Timeline analysis
- Malware detection

**Key Concepts:**

| Term | Definition |
|------|------------|
| **Profile** | OS version and architecture (Vol2 only) |
| **Symbol Table** | Kernel data structures |
| **Plugin** | Analysis module (pslist, netscan, etc.) |
| **Address Space** | Memory layout |

---

## Part 2: Installing Volatility 3 (30 minutes)

### Step 4: Install Prerequisites

**On Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-dev git
```

**Install required Python packages:**
```bash
pip3 install pycryptodome yara-python capstone
```

### Step 5: Install Volatility 3

**Clone from GitHub:**
```bash
cd ~
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
```

**Install:**
```bash
pip3 install -r requirements.txt
python3 setup.py install
```

**Or install via pip:**
```bash
pip3 install volatility3
```

**Verify installation:**
```bash
vol3 -h
```

**Or if installed from source:**
```bash
python3 vol.py -h
```

**Expected output:**
```
Volatility 3 Framework 2.5.0
usage: volatility [-h] [-c CONFIG] [--parallelism [{off,processes,threads}]]
...
```

### Step 6: Download Symbol Tables

**Volatility 3 uses symbol tables for analysis.**

**Download Windows symbols:**
```bash
cd ~/volatility3
mkdir -p symbols
cd symbols

# Download from Volatility's symbol server
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
unzip windows.zip
```

**Or let Volatility download automatically (slower).**

### Step 7: Download Sample Memory Dumps

**Option 1: Use provided sample**
```bash
mkdir -p ~/memory-forensics
cd ~/memory-forensics
# Copy from course repository
cp /path/to/soc-training-program/Lab-Resources/Sample-Data/memdump.vmem .
```

**Option 2: Download public samples**
```bash
# MemLabs challenges (excellent for practice)
wget https://github.com/stuxnet999/MemLabs/releases/download/v1.0/MemLabs.zip
unzip MemLabs.zip

# Or use:
# - https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
# - https://www.malware-traffic-analysis.net/
```

**For this lab, we'll use:** `infected-system.vmem` (Windows 10 x64)

---

## Part 3: Basic Memory Analysis (60 minutes)

### Exercise 1: Identify the Operating System

**Volatility 3 auto-detects the OS, but let's verify:**

```bash
vol3 -f infected-system.vmem windows.info
```

**Expected output:**
```
Variable        Value
Kernel Base     0xf8000XXXXXXX
DTB             0x1aa000
Symbols         file:///path/to/symbols/ntkrnlmp.pdb/...
Is64Bit         True
IsPAE           False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdVersionBlock  0xf80002c4f3a0
Major/Minor     15.19041
MachineType     34404
KeNumberProcessors      4
SystemTime      2024-01-15 14:23:45
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Thu Jan  1 00:00:00 1970
```

**Key Information:**
- **OS:** Windows 10 (Build 19041)
- **Architecture:** 64-bit
- **Capture Time:** 2024-01-15 14:23:45 UTC
- **Processors:** 4

### Exercise 2: List Running Processes

**Get process list:**
```bash
vol3 -f infected-system.vmem windows.pslist
```

**Output:**
```
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime
4       0       System          0xXXXXXXXXXXXX  123     -       N/A     False   2024-01-15 08:00:00     N/A
...
1234    5678    explorer.exe    0xXXXXXXXXXXXX  45      1234    1       False   2024-01-15 08:05:23     N/A
5432    1234    malware.exe     0xXXXXXXXXXXXX  8       156     1       False   2024-01-15 14:15:00     N/A
...
```

**Key Fields:**
- **PID:** Process ID
- **PPID:** Parent Process ID
- **ImageFileName:** Process name
- **Threads/Handles:** Resource usage
- **CreateTime:** When process started

**Suspicious indicators:**
- Unusual process names
- Misspelled system processes
- Processes with no parent (PPID=0, except System)
- Processes running from unusual locations

**Export to file for analysis:**
```bash
vol3 -f infected-system.vmem windows.pslist > pslist.txt
```

### Exercise 3: Process Tree Analysis

**View process hierarchy:**
```bash
vol3 -f infected-system.vmem windows.pstree
```

**Output:**
```
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime
4       0       System          0xXXXXXXXXXXXX  123     -       N/A     False   2024-01-15 08:00:00
* 456   4       smss.exe        0xXXXXXXXXXXXX  2       -       N/A     False   2024-01-15 08:00:01
** 678  456     csrss.exe       0xXXXXXXXXXXXX  12      -       0       False   2024-01-15 08:00:02
** 789  456     wininit.exe     0xXXXXXXXXXXXX  1       -       0       False   2024-01-15 08:00:02
*** 890 789     services.exe    0xXXXXXXXXXXXX  8       -       0       False   2024-01-15 08:00:03
**** 1234 890   svchost.exe     0xXXXXXXXXXXXX  15      -       0       False   2024-01-15 08:00:05
**** 5432 890   malware.exe     0xXXXXXXXXXXXX  8       156     0       False   2024-01-15 14:15:00
```

**Analyze:**
- Is the parent-child relationship logical?
- Are there unexpected children of system processes?
- Example: `cmd.exe` spawned by `winlogon.exe` is suspicious

### Exercise 4: Detect Hidden Processes

**Compare pslist with psscan:**

**pslist** walks the active process list (can be manipulated by rootkits)
**psscan** scans memory for process structures (finds hidden processes)

```bash
vol3 -f infected-system.vmem windows.psscan > psscan.txt
```

**Compare:**
```bash
diff pslist.txt psscan.txt
```

**If psscan finds processes not in pslist:**
- Likely rootkit hiding processes
- Investigate those processes

---

## Part 4: Malware Detection (60 minutes)

### Exercise 5: Identify Suspicious Processes

**Indicators of malicious processes:**

1. **Unusual names:**
```bash
grep -i "svchost\|explorer\|chrome" pslist.txt
```
Look for misspellings: `svch0st.exe`, `explor3r.exe`

2. **Unusual paths:**
```bash
vol3 -f infected-system.vmem windows.cmdline | grep -v "C:\\Windows"
```

Legitimate processes run from:
- `C:\Windows\System32\`
- `C:\Windows\SysWOW64\`
- `C:\Program Files\`

Suspicious paths:
- `C:\Users\<user>\AppData\Local\Temp\`
- `C:\ProgramData\`
- `C:\Users\Public\`

3. **No company information:**
```bash
vol3 -f infected-system.vmem windows.verinfo --pid 5432
```

Legitimate processes have version info, company name, etc.

### Exercise 6: Analyze Process Memory

**Dump process memory:**
```bash
vol3 -f infected-system.vmem windows.memmap --pid 5432 --dump
```

**Scan for strings:**
```bash
strings pid.5432.dmp | grep -i "http\|password\|key"
```

**Look for:**
- URLs (C2 servers)
- IP addresses
- Passwords
- Encryption keys
- Commands

### Exercise 7: Detect Code Injection

**Check for DLL injection:**
```bash
vol3 -f infected-system.vmem windows.dlllist --pid 5432
```

**Suspicious indicators:**
- DLLs loaded from unusual paths
- DLLs with no path (in-memory injection)
- Unexpected DLLs in system processes

**Detect process hollowing:**
```bash
vol3 -f infected-system.vmem windows.malfind
```

**Malfind detects:**
- Injected code
- Executable memory regions
- Hidden DLLs
- Shellcode

**Output:**
```
Process: malware.exe Pid: 5432 Address: 0x400000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 1, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x400000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x400010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
...

Disassembly:
0x400000:       push    ebp
0x400001:       mov     ebp, esp
0x400003:       sub     esp, 0x40
...
```

### Exercise 8: Network Connections

**Identify active network connections:**
```bash
vol3 -f infected-system.vmem windows.netscan
```

**Output:**
```
Offset          Proto   LocalAddr       LocalPort       ForeignAddr     ForeignPort     State           PID     Owner           Created
0xXXXXXXXXXXXX  TCPv4   192.168.1.100   49234           203.0.113.50    443             ESTABLISHED     5432    malware.exe     2024-01-15 14:16:00
0xXXXXXXXXXXXX  TCPv4   192.168.1.100   49235           198.51.100.25   8080            ESTABLISHED     5432    malware.exe     2024-01-15 14:17:00
```

**Suspicious indicators:**
- Connections to unusual ports (not 80, 443)
- Connections to foreign IPs
- Multiple connections from single process
- Connections from system processes

**Check IP reputation:**
```bash
whois 203.0.113.50
# Or use VirusTotal, AbuseIPDB
```

---

## Part 5: Advanced Analysis (60 minutes)

### Exercise 9: Registry Analysis

**Dump registry hives:**
```bash
vol3 -f infected-system.vmem windows.registry.hivelist
```

**Check autorun locations:**
```bash
vol3 -f infected-system.vmem windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

**Malware persistence locations:**
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\System\CurrentControlSet\Services`

### Exercise 10: Extract Files from Memory

**List files:**
```bash
vol3 -f infected-system.vmem windows.filescan | grep -i "malware\|suspicious"
```

**Dump specific file:**
```bash
vol3 -f infected-system.vmem windows.dumpfiles --virtaddr 0xXXXXXXXXXXXX
```

**Analyze extracted file:**
```bash
file file.0xXXXXXXXXXXXX.dat
sha256sum file.0xXXXXXXXXXXXX.dat
# Upload to VirusTotal
```

### Exercise 11: Password and Credential Extraction

**Extract cached credentials:**
```bash
vol3 -f infected-system.vmem windows.hashdump
```

**Output:**
```
User            rid     lmhash          nthash
Administrator   500     aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
Guest           501     aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
user1           1001    aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c
```

**Extract LSA secrets:**
```bash
vol3 -f infected-system.vmem windows.lsadump
```

**Note:** Use responsibly and only in authorized investigations!

### Exercise 12: Timeline Analysis

**Create timeline of events:**
```bash
vol3 -f infected-system.vmem windows.timeliner > timeline.txt
```

**Analyze timeline:**
```bash
grep "2024-01-15 14:" timeline.txt | sort
```

**Look for:**
- When malware was executed
- File modifications
- Registry changes
- Network connections

---

## Part 6: MITRE ATT&CK Mapping (30 minutes)

### Exercise 13: Map Findings to ATT&CK

Based on analysis, map to MITRE ATT&CK:

| Technique | ID | Evidence |
|-----------|----|---------| 
| **Initial Access** | T1566 | Phishing email attachment |
| **Execution** | T1204 | User executed malware.exe |
| **Persistence** | T1547.001 | Registry Run key added |
| **Defense Evasion** | T1055 | Process injection detected |
| **Credential Access** | T1003 | LSASS memory dumped |
| **Discovery** | T1057 | Process enumeration |
| **Command and Control** | T1071 | HTTP C2 to 203.0.113.50 |
| **Exfiltration** | T1041 | Data sent over C2 channel |

---

## Deliverables

Submit the following:

1. **Memory-Forensics-Report.md** - Comprehensive analysis report
2. **Evidence/** - Directory containing:
   - `pslist.txt` - Process list
   - `psscan.txt` - Process scan
   - `netscan.txt` - Network connections
   - `malfind.txt` - Code injection evidence
   - `timeline.txt` - Event timeline
3. **Extracted-Files/** - Dumped suspicious files
4. **IOCs.txt** - All indicators of compromise
5. **MITRE-ATT&CK-Mapping.md** - Technique mapping

## Report Template

```markdown
# Memory Forensics Investigation Report

**Analyst:** [Your Name]  
**Date:** [Date]  
**Case ID:** INC-2024-001  
**Memory Dump:** infected-system.vmem

---

## Executive Summary

[2-3 sentence summary of incident]

**Key Findings:**
- Malware Identified: [Name/Family]
- C2 Server: 203.0.113.50
- Data Exfiltrated: [Amount/Type]
- Persistence: Registry Run key
- Credentials Compromised: [Yes/No]

---

## 1. System Information

- **OS:** Windows 10 Build 19041 (64-bit)
- **Capture Time:** 2024-01-15 14:23:45 UTC
- **Hostname:** FINANCE-WS01
- **User:** jdoe

---

## 2. Malicious Process Identified

### Process Details
- **PID:** 5432
- **Name:** malware.exe
- **Path:** C:\Users\jdoe\AppData\Local\Temp\malware.exe
- **Parent:** explorer.exe (PID: 1234)
- **Started:** 2024-01-15 14:15:00 UTC

**Volatility Command:**
```bash
vol3 -f infected-system.vmem windows.pslist | grep 5432
```

---

## 3. Code Injection Detected

**Technique:** Process Hollowing
**Target Process:** svchost.exe (PID: 2345)
**Injected Code:** 0x400000 - 0x450000

**Evidence:**
```
vol3 -f infected-system.vmem windows.malfind --pid 2345
```

---

## 4. Network Activity

### C2 Communication
- **C2 Server:** 203.0.113.50:443
- **Protocol:** HTTPS
- **Beaconing Interval:** 60 seconds
- **Data Exfiltrated:** ~2.5 MB

**Volatility Command:**
```bash
vol3 -f infected-system.vmem windows.netscan | grep 5432
```

---

## 5. Persistence Mechanism

**Registry Run Key:**
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Name: "WindowsUpdate"
Value: "C:\Users\jdoe\AppData\Local\Temp\malware.exe"
```

---

## 6. IOCs Extracted

### File Hashes
```
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Network IOCs
```
203.0.113.50 (C2 Server)
malicious-domain.com
```

### Registry IOCs
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
```

---

## 7. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|--------|-----------|----|---------| 
| Initial Access | Phishing | T1566 | Email attachment |
| Execution | User Execution | T1204 | malware.exe executed |
| Persistence | Registry Run Keys | T1547.001 | Run key added |
| Defense Evasion | Process Injection | T1055 | Code injected into svchost.exe |
| Command and Control | Application Layer Protocol | T1071 | HTTPS C2 |
| Exfiltration | Exfiltration Over C2 Channel | T1041 | Data sent to C2 |

---

## 8. Recommendations

### Immediate Actions
1. **Isolate affected system** (already done)
2. **Block C2 infrastructure:**
   - IP: 203.0.113.50
   - Domain: malicious-domain.com
3. **Scan all systems** for malware.exe hash
4. **Reset credentials** for affected user
5. **Review email logs** for phishing campaign

### Long-term Improvements
1. Deploy EDR on all endpoints
2. Implement application whitelisting
3. Enhance email security (sandboxing)
4. Conduct security awareness training
5. Implement network segmentation

---

## Appendix

### Volatility Commands Used
```bash
vol3 -f infected-system.vmem windows.info
vol3 -f infected-system.vmem windows.pslist
vol3 -f infected-system.vmem windows.pstree
vol3 -f infected-system.vmem windows.psscan
vol3 -f infected-system.vmem windows.malfind
vol3 -f infected-system.vmem windows.netscan
vol3 -f infected-system.vmem windows.registry.printkey
vol3 -f infected-system.vmem windows.hashdump
```

---

**Investigation Completed:** [Date/Time]  
**Report Version:** 1.0
```

---

## Evaluation Criteria

- **Technical Proficiency:** Correct use of Volatility plugins
- **Analysis Depth:** Thorough investigation of memory artifacts
- **Malware Detection:** Successfully identified malicious processes
- **IOC Extraction:** Comprehensive list of indicators
- **ATT&CK Mapping:** Accurate technique identification
- **Documentation:** Professional, detailed report

---

## Additional Resources

- [Volatility Documentation](https://volatility3.readthedocs.io/)
- [Volatility Cheat Sheet](https://downloads.volatilityfoundation.org/releases/2.4/CheatSheet_v2.4.pdf)
- [MemLabs Challenges](https://github.com/stuxnet999/MemLabs)
- [SANS Memory Forensics](https://www.sans.org/blog/memory-forensics-cheat-sheet/)
- [MITRE ATT&CK](https://attack.mitre.org/)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Advanced
