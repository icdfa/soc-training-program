# Comprehensive Lab Guide - SOC Training Program

## Overview

This guide provides detailed information about all 28 hands-on labs in the Certified SOC Analyst (CSA) Program. Each lab is designed to provide practical, real-world experience with security tools, datasets, and malware samples.

---

## Lab Structure

Each lab includes:

- **Learning Outcomes:** Clear objectives for what you will learn
- **Prerequisites:** Required knowledge and tools
- **Lab Duration:** Estimated time to complete
- **Step-by-Step Instructions:** Detailed guidance through each exercise
- **Deliverables:** What you need to submit
- **Evaluation Criteria:** How your work will be assessed
- **Additional Resources:** Links to documentation and references

---

## Module 1: SOC Fundamentals & Home Lab Setup (4 Labs)

### Week 1 Lab: Threat Intelligence Research
- **Duration:** 2-3 hours
- **Tools:** Web browser, MITRE ATT&CK Navigator
- **Dataset:** N/A (OSINT research)
- **Key Skills:** Threat intelligence gathering, MITRE ATT&CK mapping, IOC extraction
- **Deliverables:** Threat intelligence report, ATT&CK Navigator layer (JSON)
- **File:** [Week-1-Lab-Threat-Intelligence-Research.md](../Module-1/Labs/Week-1-Lab-Threat-Intelligence-Research.md)

### Week 2 Lab: Home Lab Setup
- **Duration:** 3-4 hours
- **Tools:** VirtualBox/VMware, pfSense, Splunk
- **Dataset:** N/A (infrastructure setup)
- **Key Skills:** Virtualization, network configuration, SIEM deployment
- **Deliverables:** Screenshots of lab environment, network diagram
- **File:** [Week-2-Lab-Home-Lab-Setup.md](../Module-1/Labs/Week-2-Lab-Home-Lab-Setup.md)

### Week 3 Lab: Log Analysis with CLI Tools
- **Duration:** 2 hours
- **Tools:** grep, awk, sed, bash
- **Dataset:** Sample Apache access logs (provided in lab)
- **Key Skills:** Command-line log analysis, pattern matching, data extraction
- **Deliverables:** Log analysis report with commands and findings
- **File:** [Week-3-Lab-Log-Analysis-with-CLI-Tools.md](../Module-1/Labs/Week-3-Lab-Log-Analysis-with-CLI-Tools.md)

### Week 4 Lab: Windows Log Analysis with PowerShell
- **Duration:** 2 hours
- **Tools:** PowerShell, Windows Event Viewer
- **Dataset:** Windows Security Event Logs (self-generated)
- **Key Skills:** PowerShell scripting, Windows event log analysis, brute force detection
- **Deliverables:** Windows log analysis report with PowerShell commands
- **File:** [Week-4-Lab-Windows-Log-Analysis-with-PowerShell.md](../Module-1/Labs/Week-4-Lab-Windows-Log-Analysis-with-PowerShell.md)

---

## Module 2: Network Security & Traffic Analysis (5 Labs)

### Week 5 Lab: Packet Analysis with Wireshark
- **Duration:** 2-3 hours
- **Tools:** Wireshark
- **Dataset:** Sample PCAP file (provided in lab)
- **Key Skills:** Packet capture analysis, protocol identification, file extraction
- **Deliverables:** Packet analysis report with screenshots
- **File:** [Week-5-Lab-Packet-Analysis-with-Wireshark.md](../Module-2/Labs/Week-5-Lab-Packet-Analysis-with-Wireshark.md)

### Week 6 Lab: Introduction to Security Onion
- **Duration:** 3-4 hours
- **Tools:** Security Onion, Metasploitable, Kali Linux
- **Dataset:** Self-generated attack traffic
- **Key Skills:** NSM platform deployment, alert analysis, PCAP investigation
- **Deliverables:** Security Onion screenshots, alert analysis report
- **File:** [Week-6-Lab-Introduction-to-Security-Onion.md](../Module-2/Labs/Week-6-Lab-Introduction-to-Security-Onion.md)

### Week 7 Lab: Firewall Log Analysis
- **Duration:** 2 hours
- **Tools:** grep, awk, Splunk
- **Dataset:** Sample firewall logs (provided in lab)
- **Key Skills:** Firewall log parsing, port scan detection, threat investigation
- **Deliverables:** Firewall log analysis report
- **File:** [Week-7-Lab-Firewall-Log-Analysis.md](../Module-2/Labs/Week-7-Lab-Firewall-Log-Analysis.md)

### Week 8 Lab: Detecting C2 Traffic
- **Duration:** 2 hours
- **Tools:** Wireshark, NetworkMiner
- **Dataset:** Sample C2 PCAP (provided in lab)
- **Key Skills:** C2 detection, beaconing analysis, DNS tunneling identification
- **Deliverables:** C2 detection report with IOCs
- **File:** [Week-8-Lab-Detecting-C2-Traffic.md](../Module-2/Labs/Week-8-Lab-Detecting-C2-Traffic.md)

### Week 8 Lab B: CIC-IDS2017 Dataset Analysis
- **Duration:** 4-5 hours
- **Tools:** Wireshark, Splunk
- **Dataset:** CIC-IDS2017 (8GB, 5 days of traffic)
  - Location: `/Datasets/CIC-IDS2017/`
  - Download: https://www.unb.ca/cic/datasets/ids-2017.html
- **Attack Types:** Brute Force (FTP/SSH), DoS (GoldenEye, Hulk, Slowloris), Web Attacks, Infiltration, Botnet
- **Key Skills:** Large-scale dataset analysis, attack classification, SIEM correlation
- **Deliverables:** Comprehensive analysis report, Splunk dashboard, detection rules
- **File:** [Week-8-Lab-B-CIC-IDS2017-Dataset-Analysis.md](../Module-2/Labs/Week-8-Lab-B-CIC-IDS2017-Dataset-Analysis.md)

---

## Module 3: SIEM & Log Management (4 Labs)

### Week 9 Lab: Introduction to Splunk
- **Duration:** 2-3 hours
- **Tools:** Splunk, Universal Forwarder
- **Dataset:** Logs from your home lab
- **Key Skills:** Splunk installation, data onboarding, SPL queries
- **Deliverables:** Splunk screenshots, basic search results
- **File:** [Week-9-Lab-Introduction-to-Splunk.md](../Module-3/Labs/Week-9-Lab-Introduction-to-Splunk.md)

### Week 10 Lab: Creating Correlation Searches in Splunk
- **Duration:** 2 hours
- **Tools:** Splunk
- **Dataset:** Home lab logs
- **Key Skills:** Correlation rule creation, alert configuration, dashboard building
- **Deliverables:** Correlation searches, security dashboard
- **File:** [Week-10-Lab-Creating-Correlation-Searches-in-Splunk.md](../Module-3/Labs/Week-10-Lab-Creating-Correlation-Searches-in-Splunk.md)

### Week 11 Lab: Integrating Threat Intelligence in Splunk
- **Duration:** 1-2 hours
- **Tools:** Splunk, Abuse.ch feeds
- **Dataset:** Feodo Tracker C2 IP list
- **Key Skills:** Threat intel integration, lookup tables, IOC matching
- **Deliverables:** Threat intel correlation search, alert screenshots
- **File:** [Week-11-Lab-Integrating-Threat-Intelligence-in-Splunk.md](../Module-3/Labs/Week-11-Lab-Integrating-Threat-Intelligence-in-Splunk.md)

### Week 12 Lab: Advanced Splunk Searches
- **Duration:** 2 hours
- **Tools:** Splunk
- **Dataset:** Home lab logs
- **Key Skills:** Advanced SPL (eval, transaction, geostats), complex queries
- **Deliverables:** Advanced search results, analysis report
- **File:** [Week-12-Lab-Advanced-Splunk-Searches.md](../Module-3/Labs/Week-12-Lab-Advanced-Splunk-Searches.md)

---

## Module 4: Endpoint Security & Malware Analysis (7 Labs)

### Week 13 Lab: Introduction to Wazuh
- **Duration:** 2-3 hours
- **Tools:** Wazuh, Wazuh agents
- **Dataset:** Self-generated security events
- **Key Skills:** EDR deployment, agent management, alert analysis
- **Deliverables:** Wazuh dashboard screenshots, alert analysis
- **File:** [Week-13-Lab-Introduction-to-Wazuh.md](../Module-4/Labs/Week-13-Lab-Introduction-to-Wazuh.md)

### Week 14 Lab: Memory Forensics with Volatility
- **Duration:** 2-3 hours
- **Tools:** Volatility Framework
- **Dataset:** Sample memory dump (provided in lab)
- **Key Skills:** Memory analysis, process investigation, malware detection in memory
- **Deliverables:** Memory forensics report
- **File:** [Week-14-Lab-Memory-Forensics-with-Volatility.md](../Module-4/Labs/Week-14-Lab-Memory-Forensics-with-Volatility.md)

### Week 15 Lab: Static and Dynamic Malware Analysis
- **Duration:** 2 hours
- **Tools:** PEStudio, Strings, Cuckoo Sandbox
- **Dataset:** Sample malware from MalwareBazaar
- **Key Skills:** Basic malware analysis, IOC extraction
- **Deliverables:** Malware analysis report, IOC list
- **File:** [Week-15-Lab-Static-and-Dynamic-Malware-Analysis.md](../Module-4/Labs/Week-15-Lab-Static-and-Dynamic-Malware-Analysis.md)

### Week 15 Lab B: Setting Up FlareVM
- **Duration:** 2-3 hours (plus installation time)
- **Tools:** FlareVM, Windows 10 VM
- **Dataset:** N/A (environment setup)
- **Key Skills:** Malware analysis lab setup, tool familiarization
- **Deliverables:** FlareVM screenshots, tool list
- **File:** [Week-15-Lab-B-Setting-Up-Flare-VM.md](../Module-4/Labs/Week-15-Lab-B-Setting-Up-Flare-VM.md)

### Week 15 Lab C: Static Malware Analysis
- **Duration:** 3-4 hours
- **Tools:** PEStudio, FLOSS, IDA Free, Detect It Easy, Dependency Walker
- **Malware Samples:**
  - `Dropper.DownloadFromURL.exe` - Dropper malware
  - `Malware.stage0.exe` - Multi-stage malware
  - `Ransomware.wannacry.exe` - WannaCry ransomware
  - Location: `Module-4/Labs/resources/malware_samples/`
- **Key Skills:** PE analysis, string extraction, disassembly, YARA rule creation
- **Deliverables:** Static analysis report, IOC list, YARA rules
- **File:** [Week-15-Lab-C-Static-Malware-Analysis.md](../Module-4/Labs/Week-15-Lab-C-Static-Malware-Analysis.md)

### Week 15 Lab D: Dynamic Malware Analysis
- **Duration:** 3-4 hours
- **Tools:** Process Monitor, Process Explorer, Wireshark, Regshot
- **Malware Samples:** Same as Lab C
- **Key Skills:** Runtime behavior analysis, file/registry monitoring, network analysis
- **Deliverables:** Dynamic analysis report, behavior timeline
- **File:** [Week-15-Lab-D-Dynamic-Malware-Analysis.md](../Module-4/Labs/Week-15-Lab-D-Dynamic-Malware-Analysis.md)

### Week 16 Lab: Phishing Email Analysis
- **Duration:** 1-2 hours
- **Tools:** Email header analyzer, VirusTotal
- **Malware Samples:**
  - `sheetsForFinancial.xlsx` - Malicious Excel
  - `bookReport.docm` - Malicious Word (macro)
  - `incrediblyPolishedResume.docx` - Weaponized document
  - Location: `Module-4/Labs/resources/malware_samples/3-1.GonePhishing-MaldocAnalysis/`
- **Key Skills:** Email header analysis, phishing detection, maldoc analysis
- **Deliverables:** Phishing analysis report, IOC list
- **File:** [Week-16-Lab-Phishing-Email-Analysis.md](../Module-4/Labs/Week-16-Lab-Phishing-Email-Analysis.md)

---

## Module 5: Cloud SOC Monitoring (3 Labs)

### Week 17 Lab: Setting Up a Cloud Environment
- **Duration:** 1-2 hours
- **Tools:** AWS/Azure/GCP free tier
- **Dataset:** N/A (cloud infrastructure setup)
- **Key Skills:** Cloud account creation, VM deployment, security group configuration
- **Deliverables:** Cloud VM screenshots, public IP
- **File:** [Week-17-Lab-Setting-Up-a-Cloud-Environment.md](../Module-5-Cloud-SOC-Monitoring/Labs/Week-17-Lab-Setting-Up-a-Cloud-Environment.md)

### Week 12 Lab: Cloud Security Services
- **Duration:** 2-3 hours
- **Tools:** AWS CloudTrail/Azure Monitor/GCP Stackdriver
- **Dataset:** Cloud logs (self-generated)
- **Key Skills:** Cloud logging, IAM configuration, security monitoring
- **Deliverables:** Cloud security configuration screenshots
- **File:** [Week-12-Lab-Cloud-Security-Services.md](../Module-5-Cloud-SOC-Monitoring/Labs/Week-12-Lab-Cloud-Security-Services.md)

### Week 18 Lab: CSE-CIC-IDS2018 Dataset Analysis
- **Duration:** 5-6 hours
- **Tools:** Splunk, Wireshark, Python
- **Dataset:** CSE-CIC-IDS2018 (16GB, 10 days of cloud traffic)
  - Location: `/Datasets/CSE-CIC-IDS2018/`
  - Download: https://www.unb.ca/cic/datasets/ids-2018.html
- **Attack Types:** Brute Force, DoS/DDoS, Web Attacks, Infiltration, Botnet
- **Key Skills:** Cloud traffic analysis, infiltration detection, botnet C2 identification
- **Deliverables:** Comprehensive analysis report, detection dashboards, ML model (optional)
- **File:** [Week-18-Lab-CSE-CIC-IDS2018-Dataset-Analysis.md](../Module-5/Labs/Week-18-Lab-CSE-CIC-IDS2018-Dataset-Analysis.md)

---

## Module 6: Threat Hunting & Cyber Threat Intelligence (2 Labs)

### Week 21 Lab: Developing a Threat Hunt Hypothesis
- **Duration:** 1-2 hours
- **Tools:** Splunk, MITRE ATT&CK
- **Dataset:** Home lab logs or CIC datasets
- **Key Skills:** Hypothesis development, hunt planning, query creation
- **Deliverables:** Threat hunt hypothesis, search queries
- **File:** [Week-21-Lab-Developing-a-Threat-Hunt-Hypothesis.md](../Module-6-Threat-Hunting-and-Cyber-Threat-Intelligence/Labs/Week-21-Lab-Developing-a-Threat-Hunt-Hypothesis.md)

### Week 13 Lab: Advanced Threat Hunting
- **Duration:** 3-4 hours
- **Tools:** Splunk, MITRE ATT&CK Navigator
- **Dataset:** Large dataset with simulated APT activity
- **Key Skills:** Full threat hunt execution, IOC pivoting, attack timeline creation
- **Deliverables:** Threat hunt report, IOC list, attack timeline
- **File:** [Week-13-Lab-Advanced-Threat-Hunting.md](../Module-6-Threat-Hunting-and-Cyber-Threat-Intelligence/Labs/Week-13-Lab-Advanced-Threat-Hunting.md)

---

## Module 7: AI/ML in SOC & Capstone (1 Lab + Capstone)

### Week 14 Lab: AI and Machine Learning in the SOC
- **Duration:** 2-3 hours
- **Tools:** Python, scikit-learn, pandas
- **Dataset:** CIC-IDS2017 (preprocessed)
- **Key Skills:** ML model training, anomaly detection, model evaluation
- **Deliverables:** ML model, accuracy report, analysis
- **File:** [Week-14-Lab-AI-ML-in-SOC.md](../Module-7-AI-and-Machine-Learning-in-SOC/Labs/Week-14-Lab-AI-ML-in-SOC.md)

### Capstone Project
- **Duration:** 1-2 weeks
- **Tools:** All tools from the program
- **Dataset:** Comprehensive incident scenario (provided)
- **Key Skills:** Full incident investigation, reporting, presentation
- **Deliverables:** Incident response report, presentation
- **File:** [Capstone-Project.md](../Capstone-Project/Capstone-Project.md)

---

## Dataset Quick Reference

| Dataset | Size | Days | Attack Types | Used In |
|---------|------|------|--------------|---------|
| CIC-IDS2017 | 8GB | 5 | Brute Force, DoS, Web Attacks, Infiltration, Botnet | Week 8 Lab B |
| CSE-CIC-IDS2018 | 16GB | 10 | Brute Force, DoS/DDoS, Web Attacks, Infiltration, Botnet | Week 18 Lab |
| CIC-DDoS2019 | 4GB | 2 | DDoS (various vectors) | Optional exercises |
| CTU-13 | 2GB | 13 | Botnet traffic | Optional exercises |
| UNSW-NB15 | 3GB | 2 | Modern attacks | Optional exercises |

---

## Malware Sample Quick Reference

| Sample | Type | Used In | Techniques |
|--------|------|---------|------------|
| Dropper.DownloadFromURL.exe | Dropper | Week 15 Lab C & D | URL download, process creation |
| Malware.stage0.exe | Multi-stage | Week 15 Lab C & D | Staged execution, obfuscation |
| Ransomware.wannacry.exe | Ransomware | Week 15 Lab C & D | Encryption, propagation, kill switch |
| sheetsForFinancial.xlsx | Maldoc | Week 16 Lab | Excel macros |
| bookReport.docm | Maldoc | Week 16 Lab | Word macros |
| incrediblyPolishedResume.docx | Maldoc | Week 16 Lab | Document exploitation |

---

## Lab Completion Checklist

Use this checklist to track your progress:

**Module 1:**
- [ ] Week 1: Threat Intelligence Research
- [ ] Week 2: Home Lab Setup
- [ ] Week 3: Log Analysis with CLI Tools
- [ ] Week 4: Windows Log Analysis with PowerShell

**Module 2:**
- [ ] Week 5: Packet Analysis with Wireshark
- [ ] Week 6: Introduction to Security Onion
- [ ] Week 7: Firewall Log Analysis
- [ ] Week 8: Detecting C2 Traffic
- [ ] Week 8 Lab B: CIC-IDS2017 Dataset Analysis

**Module 3:**
- [ ] Week 9: Introduction to Splunk
- [ ] Week 10: Creating Correlation Searches
- [ ] Week 11: Integrating Threat Intelligence
- [ ] Week 12: Advanced Splunk Searches

**Module 4:**
- [ ] Week 13: Introduction to Wazuh
- [ ] Week 14: Memory Forensics with Volatility
- [ ] Week 15: Static and Dynamic Malware Analysis
- [ ] Week 15 Lab B: Setting Up FlareVM
- [ ] Week 15 Lab C: Static Malware Analysis
- [ ] Week 15 Lab D: Dynamic Malware Analysis
- [ ] Week 16: Phishing Email Analysis

**Module 5:**
- [ ] Week 17: Setting Up a Cloud Environment
- [ ] Week 12: Cloud Security Services
- [ ] Week 18: CSE-CIC-IDS2018 Dataset Analysis

**Module 6:**
- [ ] Week 21: Developing a Threat Hunt Hypothesis
- [ ] Week 13: Advanced Threat Hunting

**Module 7:**
- [ ] Week 14: AI and Machine Learning in SOC
- [ ] Capstone Project

---

## Tips for Success

1. **Follow the sequence:** Labs build on each other, so complete them in order
2. **Take notes:** Document your findings and commands for future reference
3. **Ask questions:** Use the GitHub discussions or issues for help
4. **Practice regularly:** Hands-on practice is key to mastering SOC skills
5. **Build your portfolio:** Save your lab reports and dashboards for job interviews
6. **Join the community:** Connect with other students in the program
7. **Stay safe:** Always use isolated VMs for malware analysis
8. **Back up your work:** Take snapshots of your VMs regularly

---

## Additional Resources

- [Tools Guide](./Tools-Guide.md) - Detailed information about all tools used
- [FAQ](./FAQ.md) - Frequently asked questions
- [Glossary](./Glossary.md) - Cybersecurity terms and definitions
- [Career Pathways](./Career-Pathways.md) - SOC career progression guide

---

## Support

If you encounter issues with any lab:

1. Check the lab's troubleshooting section
2. Review the FAQ document
3. Search GitHub issues for similar problems
4. Open a new issue with detailed information
5. Join the community discussions

---

**Last Updated:** January 2026

**Developed by:** Aminu Idris, AMCPN | International Cybersecurity and Digital Forensics Academy (ICDFA)
