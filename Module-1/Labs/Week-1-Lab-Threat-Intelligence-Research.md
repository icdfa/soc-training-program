# Week 1 Lab: Threat Intelligence Research

## Learning Outcomes

By the end of this lab, you will be able to:

- Gather threat intelligence from open-source intelligence (OSINT) sources
- Install and configure OpenCTI (Open Cyber Threat Intelligence) platform
- Integrate AlienVault OTX (Open Threat Exchange) as a threat intelligence feed
- Analyze threat actor profiles and TTPs (Tactics, Techniques, and Procedures)
- Map attack techniques to the MITRE ATT&CK framework
- Use a threat intelligence platform to enrich IOCs
- Create a threat intelligence summary report

## Objective

To research a recent, well-known cyber attack and document the attacker's tactics, techniques, and procedures (TTPs) using the MITRE ATT&CK framework.

## Scenario

You are a Junior SOC Analyst at SecureCorp, and your manager has asked you to create a threat intelligence report on the SolarWinds Orion supply chain attack. This report will be used to improve the SOC's detection capabilities and inform the organization's security posture.

## Prerequisites

- A web browser with internet access
- A text editor or Markdown editor (VS Code, Typora, or similar)
- Access to the MITRE ATT&CK Navigator
- Ubuntu VM from Week 2 lab (or any Linux system with Docker)
- At least 8GB RAM and 20GB free disk space for OpenCTI
- AlienVault OTX account (free registration)

## Lab Duration

Approximately 4-5 hours (including OpenCTI setup)

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

## Part 6: OpenCTI Installation and Configuration (90 minutes)

### Step 11: Install Docker and Docker Compose

OpenCTI runs as a set of Docker containers, making deployment straightforward.

1. **Update your system:**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Docker:**
   ```bash
   # Install prerequisites
   sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
   
   # Add Docker's official GPG key
   curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
   
   # Add Docker repository
   echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
   
   # Install Docker
   sudo apt update
   sudo apt install -y docker-ce docker-ce-cli containerd.io
   ```

3. **Install Docker Compose:**
   ```bash
   sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   sudo chmod +x /usr/local/bin/docker-compose
   ```

4. **Add your user to docker group:**
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

5. **Verify installation:**
   ```bash
   docker --version
   docker-compose --version
   ```

### Step 12: Deploy OpenCTI

1. **Create OpenCTI directory:**
   ```bash
   mkdir -p ~/opencti
   cd ~/opencti
   ```

2. **Download OpenCTI docker-compose file:**
   ```bash
   wget https://raw.githubusercontent.com/OpenCTI-Platform/docker/master/docker-compose.yml
   ```

3. **Generate UUIDs for configuration:**
   ```bash
   # Install uuidgen if not available
   sudo apt install -y uuid-runtime
   
   # Generate UUIDs
   echo "OPENCTI_ADMIN_TOKEN=$(uuidgen)" > .env
   echo "MINIO_ROOT_USER=$(uuidgen)" >> .env
   echo "MINIO_ROOT_PASSWORD=$(uuidgen)" >> .env
   echo "RABBITMQ_DEFAULT_USER=guest" >> .env
   echo "RABBITMQ_DEFAULT_PASS=$(uuidgen)" >> .env
   echo "CONNECTOR_EXPORT_FILE_STIX_ID=$(uuidgen)" >> .env
   echo "CONNECTOR_IMPORT_FILE_STIX_ID=$(uuidgen)" >> .env
   ```

4. **View your admin token (save this!):**
   ```bash
   cat .env | grep OPENCTI_ADMIN_TOKEN
   ```

5. **Start OpenCTI:**
   ```bash
   docker-compose up -d
   ```

6. **Monitor the startup (this takes 5-10 minutes):**
   ```bash
   docker-compose logs -f opencti
   ```

   **Wait for:** "OpenCTI platform is ready and available"

7. **Verify all containers are running:**
   ```bash
   docker-compose ps
   ```

   You should see:
   - opencti
   - redis
   - elasticsearch
   - minio
   - rabbitmq
   - worker (multiple instances)
   - connector-export-file-stix
   - connector-import-file-stix

### Step 13: Access OpenCTI Web Interface

1. **Open your browser and navigate to:**
   ```
   http://localhost:8080
   ```

   Or if accessing from host machine:
   ```
   http://[VM-IP]:8080
   ```

2. **Login:**
   - Email: `admin@opencti.io`
   - Password: `admin`

3. **Change the default password:**
   - Click on your profile (top right)
   - Go to **Profile → Password**
   - Set a strong password

4. **Explore the interface:**
   - **Dashboard:** Overview of threat intelligence
   - **Analysis:** Threat actors, campaigns, incidents
   - **Observations:** Indicators, observables
   - **Data:** Import/export data
   - **Settings:** Configuration and connectors

---

## Part 7: AlienVault OTX Integration (45 minutes)

### Step 14: Create AlienVault OTX Account

1. **Go to AlienVault OTX:**
   - Navigate to: https://otx.alienvault.com/

2. **Sign up for a free account:**
   - Click **Sign Up**
   - Fill in your details
   - Verify your email

3. **Get your API Key:**
   - Log in to OTX
   - Click on your username (top right)
   - Go to **Settings**
   - Copy your **OTX Key** (save this securely!)

### Step 15: Install AlienVault OTX Connector in OpenCTI

1. **Create connector directory:**
   ```bash
   cd ~/opencti
   mkdir -p connectors
   cd connectors
   ```

2. **Download AlienVault OTX connector docker-compose:**
   ```bash
   wget https://raw.githubusercontent.com/OpenCTI-Platform/connectors/master/external-import/alienvault/docker-compose.yml -O docker-compose-otx.yml
   ```

3. **Create connector configuration:**
   ```bash
   nano .env-otx
   ```

4. **Add the following configuration:**
   ```bash
   OPENCTI_URL=http://opencti:8080
   OPENCTI_TOKEN=[Your OPENCTI_ADMIN_TOKEN from Step 12]
   CONNECTOR_ID=$(uuidgen)
   CONNECTOR_NAME=AlienVault
   CONNECTOR_SCOPE=alienvault
   CONNECTOR_CONFIDENCE_LEVEL=50
   CONNECTOR_UPDATE_EXISTING_DATA=false
   CONNECTOR_LOG_LEVEL=info
   ALIENVAULT_BASE_URL=https://otx.alienvault.com
   ALIENVAULT_API_KEY=[Your OTX API Key]
   ALIENVAULT_TLP=White
   ALIENVAULT_CREATE_OBSERVABLES=true
   ALIENVAULT_CREATE_INDICATORS=true
   ALIENVAULT_PULSE_START_TIMESTAMP=2024-01-01
   ALIENVAULT_REPORT_TYPE=threat-report
   ALIENVAULT_GUESS_MALWARE=false
   ALIENVAULT_GUESS_CVE=false
   ALIENVAULT_EXCLUDED_PULSE_INDICATOR_TYPES=FileHash-MD5,FileHash-SHA1
   ALIENVAULT_ENABLE_RELATIONSHIPS=true
   ALIENVAULT_ENABLE_ATTACK_PATTERNS_INDICATES=true
   ALIENVAULT_INTERVAL_SEC=1800
   ```

5. **Start the connector:**
   ```bash
   docker-compose -f docker-compose-otx.yml --env-file .env-otx up -d
   ```

6. **Verify connector is running:**
   ```bash
   docker-compose -f docker-compose-otx.yml ps
   docker-compose -f docker-compose-otx.yml logs -f
   ```

### Step 16: Verify AlienVault OTX Integration

1. **In OpenCTI web interface:**
   - Go to **Data → Connectors**
   - You should see **AlienVault** connector
   - Status should be **Running**
   - Check the last sync time

2. **View imported threat intelligence:**
   - Go to **Observations → Indicators**
   - You should see indicators imported from AlienVault OTX
   - Filter by source: AlienVault

3. **Explore threat actors:**
   - Go to **Threats → Threat Actors**
   - Browse threat actors from AlienVault OTX

4. **Search for specific threats:**
   - Use the search bar to look for "APT29" or "SolarWinds"
   - Explore the relationships and indicators

---

## Part 8: Enriching SolarWinds IOCs with OpenCTI (30 minutes)

### Step 17: Import SolarWinds IOCs into OpenCTI

1. **Create a STIX bundle with SolarWinds IOCs:**
   
   Create a file named `solarwinds-iocs.json`:
   ```json
   {
     "type": "bundle",
     "id": "bundle--solarwinds-2024",
     "objects": [
       {
         "type": "indicator",
         "spec_version": "2.1",
         "id": "indicator--solarwinds-domain-1",
         "created": "2024-01-01T00:00:00.000Z",
         "modified": "2024-01-01T00:00:00.000Z",
         "name": "SolarWinds C2 Domain",
         "description": "Command and Control domain used in SolarWinds attack",
         "pattern": "[domain-name:value = 'avsvmcloud.com']",
         "pattern_type": "stix",
         "valid_from": "2024-01-01T00:00:00.000Z",
         "labels": ["malicious-activity"]
       },
       {
         "type": "indicator",
         "spec_version": "2.1",
         "id": "indicator--solarwinds-hash-1",
         "created": "2024-01-01T00:00:00.000Z",
         "modified": "2024-01-01T00:00:00.000Z",
         "name": "SUNBURST DLL Hash",
         "description": "SHA256 hash of malicious SolarWinds DLL",
         "pattern": "[file:hashes.'SHA-256' = '32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77']",
         "pattern_type": "stix",
         "valid_from": "2024-01-01T00:00:00.000Z",
         "labels": ["malicious-activity"]
       }
     ]
   }
   ```

2. **Import into OpenCTI:**
   - In OpenCTI, go to **Data → Import**
   - Click **Upload a file**
   - Select your `solarwinds-iocs.json` file
   - Wait for import to complete

3. **Verify import:**
   - Go to **Observations → Indicators**
   - Search for "SolarWinds" or "SUNBURST"
   - Click on an indicator to view details

### Step 18: Analyze IOC Enrichment

1. **Check for related intelligence:**
   - Click on a SolarWinds indicator
   - View the **Knowledge** tab
   - Look for:
     - Related threat actors (APT29)
     - Related campaigns
     - Related malware
     - Other indicators

2. **Explore relationships:**
   - Click on **Graph view**
   - Visualize connections between:
     - Indicators
     - Threat actors
     - Attack patterns
     - Malware

3. **Export enriched intelligence:**
   - Select indicators
   - Click **Export**
   - Choose format (STIX, CSV, PDF)
   - Download for your report

---

## Part 9: Creating Threat Intelligence Report with OpenCTI Data (30 minutes)

### Step 19: Generate Report in OpenCTI

1. **Create a new report:**
   - Go to **Analysis → Reports**
   - Click **+ Create**
   - Fill in:
     - **Name:** SolarWinds SUNBURST Attack Analysis
     - **Description:** Comprehensive analysis of the SolarWinds supply chain attack
     - **Report types:** Threat Report
     - **Confidence level:** High
     - **Published:** [Today's date]

2. **Add entities to the report:**
   - In the report, click **+ Add entities**
   - Search and add:
     - Threat Actor: APT29
     - Malware: SUNBURST
     - All SolarWinds indicators
     - Related attack patterns

3. **Write the report content:**
   - Use the **Content** tab
   - Add your analysis from earlier parts
   - Include:
     - Executive summary
     - Technical analysis
     - IOCs
     - Recommendations

4. **Generate visualizations:**
   - Use the **Graph** view to create relationship diagrams
   - Take screenshots for your report

### Step 20: Export and Finalize Report

1. **Export from OpenCTI:**
   - Click **Export**
   - Choose **PDF** or **STIX**
   - Download the file

2. **Enhance with your research:**
   - Combine OpenCTI data with your manual research
   - Add MITRE ATT&CK mappings
   - Include detection rules
   - Add remediation steps

---

## Deliverables

Submit the following files:

1. **SolarWinds-Threat-Report.md** - Your complete threat intelligence report (enhanced with OpenCTI data)
2. **SolarWinds-Attack.json** - Your MITRE ATT&CK Navigator layer
3. **OpenCTI-Screenshots/** - Directory containing:
   - OpenCTI dashboard screenshot
   - AlienVault OTX connector status
   - SolarWinds indicators in OpenCTI
   - Threat actor graph visualization
4. **solarwinds-iocs.json** - STIX bundle with SolarWinds IOCs
5. **OpenCTI-Report-Export.pdf** - Report generated from OpenCTI

## Evaluation Criteria

Your lab will be evaluated based on:

- **Completeness:** Did you document all key aspects of the attack?
- **Accuracy:** Are your findings accurate and well-researched?
- **Technical Depth:** Did you provide sufficient technical detail?
- **ATT&CK Mapping:** Did you correctly map TTPs to the MITRE ATT&CK framework?
- **OpenCTI Setup:** Did you successfully install and configure OpenCTI?
- **Threat Intelligence Integration:** Did you integrate AlienVault OTX successfully?
- **IOC Enrichment:** Did you enrich IOCs using OpenCTI?
- **Practical Value:** Are your detection and mitigation recommendations actionable?

## Additional Resources

**SolarWinds Attack:**
- [MITRE ATT&CK: SolarWinds Compromise](https://attack.mitre.org/campaigns/C0024/)
- [NSA/CISA Joint Advisory on SolarWinds](https://media.defense.gov/2021/Apr/15/2002621240/-1/-1/0/CSA_SVR_TARGETS_US_ALLIES_UOO13234021.PDF)
- [Volexity: Dark Halo Leverages SolarWinds Compromise](https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/)

**Threat Intelligence Platforms:**
- [OpenCTI Documentation](https://docs.opencti.io/)
- [OpenCTI Connectors](https://github.com/OpenCTI-Platform/connectors)
- [AlienVault OTX](https://otx.alienvault.com/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- [TAXII 2.1 Specification](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)

## Next Steps

After completing this lab, you will have a solid understanding of how to conduct threat intelligence research and document your findings. In the next lab, you will build your own SOC home lab environment to practice detecting and responding to attacks like SolarWinds.
