# Certified SOC Analyst (CSA) Program

## A Highly Practical, Hands-On Security Operations Center Training Course

**Developed by:** Aminu Idris, AMCPN | International Cybersecurity and Digital Forensics Academy (ICDFA)

**GitHub:** [https://github.com/icdfa/soc-training-program](https://github.com/icdfa/soc-training-program)

---

## Course Overview

Welcome to the Certified SOC Analyst (CSA) Program! This comprehensive, 6-month self-paced course is designed to equip you with the practical skills, knowledge, and hands-on experience required to excel as a Tier 1/Tier 2 SOC Analyst in a modern Security Operations Center.

This program is built on a foundation of real-world scenarios, practical labs, and industry-standard tools. You will not only learn the theory but also apply it in a simulated SOC environment that you will build from scratch.

### Key Features

- **100% Hands-On:** Every module includes practical labs and exercises with real datasets.
- **Build Your Own SOC Lab:** Create a complete virtual lab with a SIEM, EDR, and network monitoring tools.
- **Industry-Standard Tools:** Gain experience with Splunk, Wireshark, Security Onion, Volatility, FlareVM, and more.
- **Real-World Scenarios:** Analyze real malware samples from PMAT labs, investigate phishing emails, and respond to simulated incidents.
- **5 Major Datasets:** Work with CIC-IDS2017, CSE-CIC-IDS2018, CIC-DDoS2019, CTU-13, and UNSW-NB15 datasets.
- **20 Malware Samples:** Hands-on malware analysis with real samples including WannaCry, RATs, droppers, and maldocs.
- **Career-Focused:** The program culminates in a capstone project and career preparation module to help you land your dream job.

## Course Structure

The course is divided into seven modules:

| Module | Title                                         | Duration | Key Topics                                                                 |
| :----: | :-------------------------------------------- | :------: | :------------------------------------------------------------------------- |
|   1    | SOC Fundamentals & Home Lab Setup             | 4 Weeks  | SOC operations, threat landscape, home lab setup, Linux/Windows fundamentals |
|   2    | Network Security & Traffic Analysis           | 4 Weeks  | Networking protocols, NSM tools, packet analysis, firewall/IDS/IPS logs, CIC-IDS2017 |
|   3    | SIEM & Log Management                         | 4 Weeks  | SIEM architecture, log analysis, alert triage, rule creation, threat intel   |
|   4    | Endpoint Security & Malware Analysis          | 4 Weeks  | EDR, endpoint forensics, FlareVM, static/dynamic malware analysis, phishing analysis  |
|   5    | Cloud SOC Monitoring                          | 4 Weeks  | Cloud security, AWS/Azure/GCP security services, CSE-CIC-IDS2018            |
|   6    | Threat Hunting & Cyber Threat Intelligence    | 2 Weeks  | Threat hunting methodologies, MITRE ATT&CK, CTI integration                 |
|   7    | AI/ML in SOC & Capstone Project               | 2 Weeks  | AI-powered threat detection, capstone project, career preparation           |

## Study Plans

Choose the study plan that best fits your schedule:

| Track         | Duration | Weekly Commitment | Description                                                                 |
| :------------ | :------- | :---------------- | :-------------------------------------------------------------------------- |
| **Fast Track**    | 4 Months | 20-25 hours       | Intensive program for dedicated learners                                    |
| **Standard Track**| 6 Months | 13-15 hours       | Balanced approach for working professionals                                 |
| **Part-Time Track**| 8 Months | 5-8 hours         | Flexible schedule for busy professionals                                    |

**Study Plan Documents:**
- [Fast Track Study Plan (4 Months)](./Documentation/Fast-Track-Study-Plan.md)
- [Standard Track Study Plan (6 Months)](./Documentation/Standard-Track-Study-Plan.md)
- [Part-Time Track Study Plan (8 Months)](./Documentation/Part-Time-Track-Study-Plan.md)
- [Detailed Program Schedule](./Documentation/SOC-Program-Schedule.md)
- [Official Syllabus](./Documentation/Syllabus.md)

## Lab Status

### Fully Expanded Labs (400-900 lines each)

The following 15 labs have been comprehensively expanded with detailed, step-by-step instructions:

**Module 1: SOC Fundamentals**
- ✅ [Week 1: Threat Intelligence Research](./Module-1/Labs/Week-1-Lab-Threat-Intelligence-Research.md) (853 lines) - OpenCTI + AlienVault OTX
- ✅ [Week 2: Home Lab Setup](./Module-1/Labs/Week-2-Lab-Home-Lab-Setup.md) (600+ lines)
- ✅ [Week 3: CLI Log Analysis](./Module-1/Labs/Week-3-Lab-Log-Analysis-with-CLI-Tools.md) (550+ lines)
- ✅ [Week 4: PowerShell Log Analysis](./Module-1/Labs/Week-4-Lab-Windows-Log-Analysis-with-PowerShell.md) (700+ lines)

**Module 2: Network Traffic Analysis**
- ✅ [Week 5: Wireshark Packet Analysis](./Module-2/Labs/Week-5-Lab-Packet-Analysis-with-Wireshark.md) (740 lines)
- ✅ [Week 6: Security Onion](./Module-2/Labs/Week-6-Lab-Introduction-to-Security-Onion.md) (727 lines)
- ✅ [Week 7: Firewall Log Analysis](./Module-2/Labs/Week-7-Lab-Firewall-Log-Analysis.md) (786 lines)
- ✅ [Week 8-B: CIC-IDS2017 Dataset Analysis](./Module-2/Labs/Week-8-Lab-B-CIC-IDS2017-Dataset-Analysis.md) (607 lines)
- ✅ [Week 8-C2: C2 Traffic Detection](./Module-2/Labs/Week-8-Lab-Detecting-C2-Traffic.md) (900+ lines)

**Module 3: SIEM and Log Management**
- ✅ [Week 9: Splunk Introduction](./Module-3/Labs/Week-9-Lab-Introduction-to-Splunk.md) (738 lines)

**Module 4: Incident Response and Forensics**
- ✅ [Week 13: Wazuh HIDS/EDR](./Module-4/Labs/Week-13-Lab-Introduction-to-Wazuh.md) (786 lines) ⭐
- ✅ [Week 14: Volatility Memory Forensics](./Module-4/Labs/Week-14-Lab-Memory-Forensics-with-Volatility.md) (752 lines) ⭐
- ✅ [Week 15-C: Static Malware Analysis](./Module-4/Labs/Week-15-Lab-C-Static-Malware-Analysis.md) (596 lines)

**Module 5: Cloud SOC Monitoring**
- ✅ [Week 18: CSE-CIC-IDS2018 Dataset Analysis](./Module-5/Labs/Week-18-Lab-CSE-CIC-IDS2018-Dataset-Analysis.md) (607 lines)

**Module 6: Threat Hunting**
- ✅ [Week 21: Threat Hunting Hypothesis Development](./Module-6-Threat-Hunting-and-Cyber-Threat-Intelligence/Labs/Week-21-Lab-Developing-a-Threat-Hunt-Hypothesis.md) (811 lines) ⭐

⭐ = Priority/Advanced Labs

### Labs with Templates Available

The remaining 13 labs have basic structure and can be expanded using the [Lab Expansion Template](./Documentation/Lab-Expansion-Template.md):

**Module 3:** Week 10, 11, 12  
**Module 4:** Week 15, 15-B, 15-D, 16  
**Module 5:** Week 17, Week 12 (Cloud)  
**Module 6:** Week 13 (Advanced Hunting)  
**Module 7:** Week 14 (AI/ML)

---

## Navigation

### Modules

- [Module 1: SOC Fundamentals & Home Lab Setup](./Module-1)
  - [Study Materials](./Module-1/Study-Materials)
  - [Labs](./Module-1/Labs)
  - [Assignments](./Module-1/Assignments)
  - [Learning Outcomes](./Module-1/Learning-Outcomes.md)
  
- [Module 2: Network Security & Traffic Analysis](./Module-2)
  - [Study Materials](./Module-2/Study-Materials)
  - [Labs](./Module-2/Labs)
  - [Assignments](./Module-2/Assignments)
  
- [Module 3: SIEM & Log Management](./Module-3)
  - [Study Materials](./Module-3/Study-Materials)
  - [Labs](./Module-3/Labs)
  - [Assignments](./Module-3/Assignments)
  
- [Module 4: Endpoint Security & Malware Analysis](./Module-4)
  - [Study Materials](./Module-4/Study-Materials)
  - [Labs](./Module-4/Labs)
  - [Assignments](./Module-4/Assignments)
  
- [Module 5: Cloud SOC Monitoring](./Module-5-Cloud-SOC-Monitoring)
  - [Study Materials](./Module-5-Cloud-SOC-Monitoring/Study-Materials)
  - [Labs](./Module-5-Cloud-SOC-Monitoring/Labs)
  
- [Module 6: Threat Hunting & Cyber Threat Intelligence](./Module-6-Threat-Hunting-and-Cyber-Threat-Intelligence)
  - [Study Materials](./Module-6-Threat-Hunting-and-Cyber-Threat-Intelligence/Study-Materials)
  - [Labs](./Module-6-Threat-Hunting-and-Cyber-Threat-Intelligence/Labs)
  
- [Module 7: AI/ML in SOC & Capstone](./Module-7-AI-and-Machine-Learning-in-SOC)
  - [Study Materials](./Module-7-AI-and-Machine-Learning-in-SOC/Study-Materials)

### Datasets

- [CIC-IDS2017](./Datasets/CIC-IDS2017) - Comprehensive intrusion detection dataset with benign and attack traffic
- [CSE-CIC-IDS2018](./Datasets/CSE-CIC-IDS2018) - Large-scale cloud-based dataset with 10 days of network activity
- [CIC-DDoS2019](./Datasets/CIC-DDoS2019) - DDoS attack dataset with various attack vectors
- [CTU-13](./Datasets/CTU-13) - Botnet traffic dataset from CTU University
- [UNSW-NB15](./Datasets/UNSW-NB15) - Modern network intrusion dataset

### Malware Samples

The program includes **20+ real malware samples** from the PMAT-labs repository for hands-on malware analysis. All samples are password-protected (password: `infected`) and should only be analyzed in an isolated virtual environment.

**Location:** `Module-4/Labs/resources/malware_samples/`

**⚠️ CRITICAL SAFETY WARNING:**
- **NEVER** execute malware on your host machine
- **ALWAYS** use an isolated virtual machine (FlareVM recommended)
- **DISCONNECT** the VM from the network during analysis
- **TAKE SNAPSHOTS** before analyzing malware
- **REVERT** to clean snapshots after analysis
- All samples are password-protected with password: `infected`

#### Malware Sample Categories

##### 1. Basic Samples (Learning Tools)
**Purpose:** Learn malware analysis tools and techniques with simple, safe samples

| Sample | Location | Lab | Description |
|--------|----------|-----|-------------|
| `helloWorld.exe` | [2-1.AdvancedStaticAnalysis/helloWorld-c/](./Module-4/Labs/resources/malware_samples/2-1.AdvancedStaticAnalysis/helloWorld-c/) | Week 15 Lab C | Simple C program for learning static analysis tools (PEStudio, IDA, Ghidra) |
| `helloWorld-stripped.exe` | [2-1.AdvancedStaticAnalysis/helloWorld-c/](./Module-4/Labs/resources/malware_samples/2-1.AdvancedStaticAnalysis/helloWorld-c/) | Week 15 Lab C | Stripped version for advanced reverse engineering practice |

##### 2. Dropper Malware
**Purpose:** Understand multi-stage malware delivery mechanisms

| Sample | Location | Lab | Techniques | MITRE ATT&CK |
|--------|----------|-----|------------|---------------|
| `Dropper.DownloadFromURL.exe` | [2-1.AdvancedStaticAnalysis/Dropper.DownloadFromURL.exe.malz/](./Module-4/Labs/resources/malware_samples/2-1.AdvancedStaticAnalysis/Dropper.DownloadFromURL.exe.malz/) | Week 15 Lab C & D | URL download, process creation, persistence | T1105 (Ingress Tool Transfer), T1543 (Create or Modify System Process) |

##### 3. Multi-Stage Malware
**Purpose:** Analyze complex, staged malware execution chains

| Sample | Location | Lab | Techniques | MITRE ATT&CK |
|--------|----------|-----|------------|---------------|
| `Malware.stage0.exe` | [2-1.AdvancedStaticAnalysis/Malware.stage0.exe.malz/](./Module-4/Labs/resources/malware_samples/2-1.AdvancedStaticAnalysis/Malware.stage0.exe.malz/) | Week 15 Lab C & D | Staged execution, obfuscation, anti-analysis | T1027 (Obfuscated Files), T1497 (Virtualization/Sandbox Evasion) |

##### 4. Maldocs (Malicious Documents)
**Purpose:** Analyze document-based malware delivery (most common phishing vector)

| Sample | Type | Location | Lab | Techniques | MITRE ATT&CK |
|--------|------|----------|-----|------------|---------------|
| `sheetsForFinancial.xlsx` | Excel | [3-1.GonePhishing-MaldocAnalysis/Excel/](./Module-4/Labs/resources/malware_samples/3-1.GonePhishing-MaldocAnalysis/Excel/) | Week 16 | Macro-based malware, social engineering | T1566.001 (Phishing: Spearphishing Attachment), T1204.002 (User Execution: Malicious File) |
| `bookReport.docm` | Word (Macro) | [3-1.GonePhishing-MaldocAnalysis/Word/docm/](./Module-4/Labs/resources/malware_samples/3-1.GonePhishing-MaldocAnalysis/Word/docm/) | Week 16 | VBA macros, document exploitation | T1566.001, T1059.005 (Visual Basic) |
| `incrediblyPolishedResume.docx` | Word | [3-1.GonePhishing-MaldocAnalysis/Word/docx/](./Module-4/Labs/resources/malware_samples/3-1.GonePhishing-MaldocAnalysis/Word/docx/) | Week 16 | Document-based attacks, phishing | T1566.001, T1204.002 |

##### 5. Ransomware (Advanced)
**Purpose:** Analyze real-world ransomware (WannaCry) - most dangerous sample in the collection

| Sample | Location | Lab | Techniques | MITRE ATT&CK |
|--------|----------|-----|------------|---------------|
| `Ransomware.wannacry.exe` | [4-1.Bossfight-wannacry.exe/](./Module-4/Labs/resources/malware_samples/4-1.Bossfight-wannacry.exe/) | Week 15 Lab C & D | File encryption, network propagation, kill switch, SMB exploitation (EternalBlue) | T1486 (Data Encrypted for Impact), T1021 (Remote Services), T1210 (Exploitation of Remote Services) |

**WannaCry Analysis Resources:**
- Password file: `password.txt` (contains: `infected`)
- Answer key: `answers/` directory
- **Extreme caution required** - This is real, destructive ransomware

#### Sample Organization

```
Module-4/Labs/resources/malware_samples/
├── 2-1.AdvancedStaticAnalysis/          # Static analysis samples
│   ├── Dropper.DownloadFromURL.exe.malz/
│   ├── Malware.stage0.exe.malz/
│   └── helloWorld-c/
├── 2-2.AdvancedDynamicAnalysis/         # Dynamic analysis samples
│   ├── Dropper.DownloadFromURL.exe/
│   └── helloWorld-c/
├── 3-1.GonePhishing-MaldocAnalysis/     # Malicious documents
│   ├── Excel/
│   └── Word/
│       ├── docm/
│       └── docx/
└── 4-1.Bossfight-wannacry.exe/          # WannaCry ransomware
    ├── Ransomware.wannacry.exe.malz.7z
    ├── password.txt
    └── answers/
```

**Safety Guidelines:**
- **NEVER** execute malware on your host machine
- **ALWAYS** use an isolated virtual machine (FlareVM recommended)
- **DISCONNECT** the VM from the network during analysis
- **TAKE SNAPSHOTS** before analyzing malware
- **REVERT** to clean snapshots after analysis
- All samples are password-protected with password: `infected`

### Assessments

- [Pre-Assessment](./Assessments/Pre-Assessment.md)
- [Module 1 Quiz](./Module-1/Assessments/Module-1-Quiz.md)
- [Final Exam](./Assessments/Final-Exam.md)

### Documentation

- [FAQ](./Documentation/FAQ.md)
- [Glossary](./Documentation/Glossary.md)
- [Career Pathways](./Documentation/Career-Pathways.md)
- [Tools Guide](./Documentation/Tools-Guide.md)
- [Comprehensive Lab Guide](./Documentation/Comprehensive-Lab-Guide.md) - **NEW!** Complete guide to all labs
- [Lab Expansion Template](./Documentation/Lab-Expansion-Template.md) - **NEW!** Template for expanding remaining labs

### Templates

- [Incident Response Report Template](./Templates/Incident-Response-Report-Template.md)

### Capstone Project

- [Capstone Project Instructions](./Capstone-Project/Capstone-Project.md)

## Getting Started

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/icdfa/soc-training-program.git
   ```
2. **Take the Pre-Assessment:** Complete the [Pre-Assessment](./Assessments/Pre-Assessment.md) to gauge your current knowledge.
3. **Choose Your Study Plan:** Select the [study plan](./Documentation) that best fits your schedule.
4. **Review the Syllabus:** Read the [Official Syllabus](./Documentation/Syllabus.md) to understand the program structure.
5. **Set Up Your Lab:** Follow the instructions in [Module 1](./Module-1) to build your virtual SOC home lab.
6. **Begin Your Journey:** Follow the weekly study plans and complete the labs and assignments for each module.

## About the Author

This program was developed by **Aminu Idris, AMCPN**, a seasoned cybersecurity professional and educator with extensive experience in building and managing Security Operations Centers. As the Founder and Commandant of the International Cybersecurity and Digital Forensics Academy (ICDFA), he is dedicated to providing practical, hands-on training to the next generation of cybersecurity defenders.

**Certifications:** CCNA, CompTIA Security+, CEH, OSCP, CISSP | MPCSEAN

## Contributing

We welcome contributions to the SOC Training Program! Please read our [Contributing Guidelines](./CONTRIBUTING.md) and [Code of Conduct](./CODE_OF_CONDUCT.md) before submitting a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE.md](./LICENSE.md) file for details.

## Contact

For questions or support, please open an issue on our [GitHub repository](https://github.com/icdfa/soc-training-program).
