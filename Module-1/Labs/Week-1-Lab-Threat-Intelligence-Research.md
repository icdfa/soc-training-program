# Week 1 Lab: Threat Intelligence Research

## Learning Outcomes

By the end of this lab, you will be able to:

- Gather threat intelligence from open-source intelligence (OSINT) sources
- Analyze threat actor profiles and TTPs (Tactics, Techniques, and Procedures)
- Map attack techniques to the MITRE ATT&CK framework
- Create a threat intelligence summary report

## Objective

To research a recent, well-known cyber attack and document the attacker's tactics, techniques, and procedures (TTPs) using the MITRE ATT&CK framework.

## Scenario

You are a Junior SOC Analyst at SecureCorp, and your manager has asked you to create a threat intelligence report on the SolarWinds Orion supply chain attack. This report will be used to improve the SOC's detection capabilities and inform the organization's security posture.

## Prerequisites

- A web browser with internet access
- A text editor or Markdown editor (VS Code, Typora, or similar)
- Access to the MITRE ATT&CK Navigator

## Lab Duration

Approximately 2-3 hours

---

## Part 1: Understanding the SolarWinds Attack (30 minutes)

### Step 1: Research the Attack Timeline

The SolarWinds supply chain attack, also known as SUNBURST or Solarigate, was one of the most sophisticated cyberattacks in history. Begin your research by understanding the timeline of events.

**Recommended Sources:**

1. **FireEye Blog:** [Highly Evasive Attacker Leverages SolarWinds Supply Chain](https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html)
2. **Microsoft Security Blog:** [Deep dive into the Solorigate second-stage activation](https://www.microsoft.com/security/blog/2020/12/18/analyzing-solorigate-the-compromised-dll-file-that-started-a-sophisticated-cyberattack-and-how-microsoft-defender-helps-protect/)
3. **CISA Alert:** [Advanced Persistent Threat Compromise of Government Agencies](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)

**Key Questions to Answer:**

- When was the attack first discovered?
- When did the compromise actually occur?
- How long did the attackers have access to victim networks?
- Who was the suspected threat actor behind the attack?
- What was the primary objective of the attack?

**Document Your Findings:**

Create a new file named `SolarWinds-Threat-Report.md` and add a section titled "Attack Timeline" with your findings.

```markdown
# SolarWinds Orion Supply Chain Attack - Threat Intelligence Report

## Executive Summary

[Brief 2-3 sentence overview of the attack]

## Attack Timeline

- **March 2020:** Initial compromise of SolarWinds build environment
- **May 2020:** Trojanized updates begin distribution to customers
- **December 2020:** Attack discovered by FireEye
- **[Add more timeline events]**
```

### Step 2: Identify the Threat Actor

Research the threat actor behind the SolarWinds attack. The attack has been attributed to APT29 (also known as Cozy Bear, The Dukes, or NOBELIUM).

**Research Questions:**

- What is APT29's history and origin?
- What are their typical targets?
- What are their known capabilities?
- What other notable attacks have they conducted?

**Add to Your Report:**

```markdown
## Threat Actor Profile

**Name:** APT29 (Cozy Bear, The Dukes, NOBELIUM)

**Origin:** [Your findings]

**Typical Targets:** [Your findings]

**Known Capabilities:** [Your findings]

**Previous Notable Attacks:** [Your findings]
```

---

## Part 2: Technical Analysis of the Attack (45 minutes)

### Step 3: Analyze the SUNBURST Backdoor

The SUNBURST backdoor was the primary malware used in the SolarWinds attack. Research the technical details of this malware.

**Key Technical Details to Document:**

1. **File Information:**
   - Filename: SolarWinds.Orion.Core.BusinessLayer.dll
   - File type: .NET DLL
   - How it was distributed: Trojanized software update

2. **Malware Capabilities:**
   - Command and control (C2) communication
   - File operations (read, write, delete)
   - Process execution
   - Registry manipulation
   - Network reconnaissance
   - Data exfiltration

3. **Evasion Techniques:**
   - Dormancy period (12-14 days after installation)
   - Domain generation algorithm (DGA) for C2
   - Checks for security tools and sandboxes
   - Legitimate-looking domain names
   - Use of legitimate cloud services (AWS, Azure, GCP)

**Add to Your Report:**

```markdown
## Technical Analysis

### SUNBURST Backdoor

**File Details:**
- **Filename:** SolarWinds.Orion.Core.BusinessLayer.dll
- **File Type:** .NET DLL
- **Distribution Method:** Trojanized software update
- **File Hash (SHA256):** [Research and add]

**Capabilities:**
- [List each capability with brief description]

**Evasion Techniques:**
- [List each evasion technique]

**Command and Control (C2):**
- **C2 Domain:** avsvmcloud[.]com (and others)
- **C2 Protocol:** HTTPS
- **C2 Characteristics:** [Your findings]
```

### Step 4: Understand the Attack Chain

Document the complete attack chain from initial compromise to data exfiltration.

**Attack Phases:**

1. **Initial Access:** Supply chain compromise of SolarWinds build system
2. **Execution:** Trojanized DLL executed as part of legitimate SolarWinds Orion software
3. **Persistence:** Backdoor runs as part of legitimate SolarWinds service
4. **Defense Evasion:** Multiple techniques to avoid detection
5. **Discovery:** Network and system reconnaissance
6. **Lateral Movement:** Movement to high-value targets within victim networks
7. **Collection:** Gathering of sensitive data
8. **Exfiltration:** Data stolen via C2 channels

**Add to Your Report:**

```markdown
## Attack Chain

### Phase 1: Initial Access
[Detailed description]

### Phase 2: Execution
[Detailed description]

### Phase 3: Persistence
[Detailed description]

[Continue for all phases]
```

---

## Part 3: MITRE ATT&CK Mapping (45 minutes)

### Step 5: Access the MITRE ATT&CK Navigator

1. Navigate to the MITRE ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
2. Click on "Create New Layer" and select "Enterprise ATT&CK v14"
3. Name your layer "SolarWinds SUNBURST Attack"

### Step 6: Map TTPs to MITRE ATT&CK

Based on your research, identify and map the techniques used in the SolarWinds attack. Here are the key techniques to include:

**Initial Access:**
- T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain

**Execution:**
- T1059.001 - Command and Scripting Interpreter: PowerShell
- T1059.003 - Command and Scripting Interpreter: Windows Command Shell

**Persistence:**
- T1543.003 - Create or Modify System Process: Windows Service
- T1574.002 - Hijack Execution Flow: DLL Side-Loading

**Defense Evasion:**
- T1027 - Obfuscated Files or Information
- T1036.005 - Masquerading: Match Legitimate Name or Location
- T1070.004 - Indicator Removal on Host: File Deletion
- T1497 - Virtualization/Sandbox Evasion
- T1562.001 - Impair Defenses: Disable or Modify Tools

**Discovery:**
- T1007 - System Service Discovery
- T1016 - System Network Configuration Discovery
- T1033 - System Owner/User Discovery
- T1057 - Process Discovery
- T1082 - System Information Discovery

**Lateral Movement:**
- T1021.001 - Remote Services: Remote Desktop Protocol
- T1021.002 - Remote Services: SMB/Windows Admin Shares

**Collection:**
- T1005 - Data from Local System
- T1039 - Data from Network Shared Drive
- T1074.001 - Data Staged: Local Data Staging

**Command and Control:**
- T1071.001 - Application Layer Protocol: Web Protocols
- T1573.002 - Encrypted Channel: Asymmetric Cryptography
- T1568.002 - Dynamic Resolution: Domain Generation Algorithms

**Exfiltration:**
- T1041 - Exfiltration Over C2 Channel
- T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage

### Step 7: Configure the ATT&CK Navigator Layer

For each technique you identified:

1. Click on the technique in the ATT&CK Navigator
2. Set the score to 1 (to highlight it)
3. Add a comment explaining how it was used in the SolarWinds attack
4. Choose a color (e.g., red for high severity)

**Example Comment for T1195.002:**

```
The attackers compromised the SolarWinds Orion build environment and inserted the SUNBURST backdoor into the SolarWinds.Orion.Core.BusinessLayer.dll file. This trojanized DLL was then digitally signed and distributed to approximately 18,000 customers via legitimate software updates.
```

### Step 8: Export Your ATT&CK Layer

1. Click on the layer name at the top of the navigator
2. Select "Download Layer" → "layer_file (JSON)"
3. Save the file as `SolarWinds-Attack.json`

**Add to Your Report:**

```markdown
## MITRE ATT&CK Techniques

### Initial Access

**T1195.002 - Supply Chain Compromise: Compromise Software Supply Chain**
- The attackers compromised the SolarWinds Orion build environment and inserted the SUNBURST backdoor into the SolarWinds.Orion.Core.BusinessLayer.dll file.

### Execution

**T1059.001 - Command and Scripting Interpreter: PowerShell**
- [Your description]

**T1059.003 - Command and Scripting Interpreter: Windows Command Shell**
- [Your description]

[Continue for all techniques]

## ATT&CK Navigator Layer

The complete ATT&CK Navigator layer for this attack is available in the file `SolarWinds-Attack.json`.
```

---

## Part 4: Indicators of Compromise (30 minutes)

### Step 9: Compile IOCs

Research and document all known Indicators of Compromise (IOCs) for the SolarWinds attack.

**IOC Categories:**

1. **File Hashes:**
   - SUNBURST DLL hashes
   - TEARDROP malware hashes
   - Other related malware hashes

2. **Network IOCs:**
   - C2 domains (e.g., avsvmcloud[.]com)
   - IP addresses
   - URLs

3. **Registry Keys:**
   - Any registry modifications made by SUNBURST

4. **File Paths:**
   - Locations where malicious files were dropped

**Add to Your Report:**

```markdown
## Indicators of Compromise (IOCs)

### File Hashes (SHA256)

```
32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77
ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6
[Add more hashes]
```

### Network IOCs

**C2 Domains:**
```
avsvmcloud[.]com
digitalcollege[.]org
freescanonline[.]com
[Add more domains]
```

**IP Addresses:**
```
13.59.205.66
54.193.127.66
[Add more IPs]
```

### Registry Keys

```
HKEY_LOCAL_MACHINE\SOFTWARE\SolarWinds\Orion\ReportWatcher
[Add more registry keys]
```

### File Paths

```
C:\Program Files (x86)\SolarWinds\Orion\SolarWinds.Orion.Core.BusinessLayer.dll
[Add more file paths]
```
```

---

## Part 5: Detection and Mitigation (30 minutes)

### Step 10: Develop Detection Strategies

Based on your understanding of the attack, propose detection strategies that could identify similar attacks.

**Add to Your Report:**

```markdown
## Detection Strategies

### Network-Based Detection

1. **Monitor for suspicious C2 domains:**
   - Look for connections to domains using DGA patterns
   - Monitor for connections to cloud services from unexpected processes

2. **Analyze DNS queries:**
   - Look for CNAME records pointing to avsvmcloud[.]com or similar domains
   - Monitor for unusual DNS query patterns

3. **Inspect HTTPS traffic:**
   - Look for HTTPS connections from unexpected processes
   - Monitor for data exfiltration patterns

### Host-Based Detection

1. **Monitor SolarWinds processes:**
   - Look for unusual child processes spawned by SolarWinds services
   - Monitor for unexpected network connections from SolarWinds processes

2. **File integrity monitoring:**
   - Monitor SolarWinds DLL files for unauthorized modifications
   - Verify digital signatures of all SolarWinds files

3. **Registry monitoring:**
   - Monitor for modifications to SolarWinds registry keys
   - Look for new persistence mechanisms

### Log Analysis

1. **Windows Event Logs:**
   - Event ID 7045: New service installation
   - Event ID 4688: Process creation events
   - Event ID 4624/4625: Logon events

2. **Firewall Logs:**
   - Monitor for connections to known C2 infrastructure
   - Look for unusual outbound connections

## Mitigation and Remediation

### Immediate Actions

1. **Isolate affected systems:**
   - Disconnect systems running vulnerable SolarWinds versions from the network

2. **Reset credentials:**
   - Reset all credentials that may have been compromised
   - Implement multi-factor authentication (MFA)

3. **Apply patches:**
   - Update SolarWinds Orion to the latest patched version
   - Apply all relevant security updates

### Long-Term Recommendations

1. **Implement supply chain security:**
   - Verify integrity of all software updates
   - Implement software composition analysis (SCA)

2. **Enhance monitoring:**
   - Deploy EDR solutions on all endpoints
   - Implement network traffic analysis (NTA)

3. **Conduct threat hunting:**
   - Proactively search for signs of compromise
   - Use the IOCs and TTPs documented in this report
```

---

## Deliverables

Submit the following files:

1. **SolarWinds-Threat-Report.md** - Your complete threat intelligence report
2. **SolarWinds-Attack.json** - Your MITRE ATT&CK Navigator layer

## Evaluation Criteria

Your lab will be evaluated based on:

- **Completeness:** Did you document all key aspects of the attack?
- **Accuracy:** Are your findings accurate and well-researched?
- **Technical Depth:** Did you provide sufficient technical detail?
- **ATT&CK Mapping:** Did you correctly map TTPs to the MITRE ATT&CK framework?
- **Practical Value:** Are your detection and mitigation recommendations actionable?

## Additional Resources

- [MITRE ATT&CK: SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024/)
- [NSA/CISA Joint Advisory on SolarWinds](https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF)
- [Volexity: Dark Halo Leverages SolarWinds Compromise](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/)

## Next Steps

After completing this lab, you will have a solid understanding of how to conduct threat intelligence research and document your findings. In the next lab, you will build your own SOC home lab environment to practice detecting and responding to attacks like SolarWinds.
