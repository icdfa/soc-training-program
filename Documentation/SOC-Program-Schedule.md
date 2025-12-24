# Certified SOC Analyst (CSA) Program - 6-Month Schedule

## Overview

This document provides a detailed week-by-week schedule for the 6-month (24-week) self-paced SOC Training Program. Each week is designed for approximately 10-15 hours of study, including readings, labs, and assignments.

---

## Module 1: SOC Fundamentals & Home Lab Setup (Weeks 1-4)

### **Week 1: Introduction to SOC Operations**
*   **Topic:** Understanding the modern Security Operations Center, roles, responsibilities, and core processes.
*   **Learning Objectives:**
    *   Define the purpose and function of a SOC.
    *   Describe the roles of Tier 1, Tier 2, and Tier 3 analysts.
    *   Understand the importance of threat intelligence.
*   **Reading:** `Module-1/Study-Materials/Week-1-Introduction-to-SOC-Operations.md`
*   **Lab:** `Module-1/Labs/Week-1-Lab-Threat-Intelligence-Research.md`
*   **Assignment:** `Module-1/Assignments/Week-1-Assignment-Threat-Landscape-Report.md`

### **Week 2: Building Your SOC Home Lab**
*   **Topic:** Setting up a virtual lab environment for hands-on practice.
*   **Learning Objectives:**
    *   Install and configure VirtualBox.
    *   Set up Security Onion, FlareVM, and other necessary VMs.
    *   Understand virtual networking for a lab environment.
*   **Reading:** `Module-1/Study-Materials/Week-2-Building-Your-SOC-Home-Lab.md`
*   **Lab:** `Module-1/Labs/Week-2-Lab-Home-Lab-Setup.md`

### **Week 3: Essential Linux Command-Line Skills**
*   **Topic:** Mastering Linux command-line tools for log analysis and system administration.
*   **Learning Objectives:**
    *   Use `grep`, `awk`, `sed`, and other tools to parse logs.
    *   Navigate the Linux file system and manage processes.
*   **Reading:** `Module-1/Study-Materials/Week-3-Essential-Linux-Command-Line-Skills.md`
*   **Lab:** `Module-1/Labs/Week-3-Lab-Log-Analysis-with-CLI-Tools.md` (Dataset: `access.log`)

### **Week 4: Essential Windows PowerShell Skills**
*   **Topic:** Using PowerShell for Windows log analysis and incident response.
*   **Learning Objectives:**
    *   Analyze Windows Event Logs with PowerShell.
    *   Automate tasks for incident investigation.
*   **Reading:** `Module-1/Study-Materials/Week-4-Essential-Windows-PowerShell-Skills.md`
*   **Lab:** `Module-1/Labs/Week-4-Lab-Windows-Log-Analysis-with-PowerShell.md`

---

## Module 2: Network Security & Traffic Analysis (Weeks 5-8)

### **Week 5: Networking Fundamentals for SOC Analysts**
*   **Topic:** Deep dive into TCP/IP, network protocols, and traffic analysis.
*   **Learning Objectives:**
    *   Understand the OSI and TCP/IP models.
    *   Analyze packet headers and payloads.
*   **Reading:** `Module-2/Study-Materials/Week-5-Networking-Fundamentals-for-SOC-Analysts.md`
*   **Lab:** `Module-2/Labs/Week-5-Lab-Packet-Analysis-with-Wireshark.md` (Dataset: `suspicious-traffic.pcap`)

### **Week 6: Network Security Monitoring (NSM) Tools**
*   **Topic:** Introduction to Security Onion, Zeek, and Suricata.
*   **Learning Objectives:**
    *   Understand the components of Security Onion.
    *   Generate alerts with Suricata IDS.
*   **Reading:** `Module-2/Study-Materials/Week-6-Network-Security-Monitoring-Tools.md`
*   **Lab:** `Module-2/Labs/Week-6-Lab-Introduction-to-Security-Onion.md`

### **Week 7: Firewall and Proxy Log Analysis**
*   **Topic:** Analyzing logs from firewalls and web proxies to detect threats.
*   **Learning Objectives:**
    *   Identify malicious traffic patterns in firewall logs.
    *   Detect policy violations and web attacks from proxy logs.
*   **Reading:** `Module-2/Study-Materials/Week-7-Firewall-and-Proxy-Log-Analysis.md`
*   **Lab:** `Module-2/Labs/Week-7-Lab-Firewall-Log-Analysis.md` (Dataset: `firewall.log`)

### **Week 8: Advanced Traffic Analysis & CIC-IDS2017**
*   **Topic:** Detecting C2 traffic and analyzing a large-scale IDS dataset.
*   **Learning Objectives:**
    *   Identify command-and-control communication patterns.
    *   Analyze various attack types in the CIC-IDS2017 dataset.
*   **Reading:** `Module-2/Study-Materials/Week-8-Advanced-Traffic-Analysis.md`
*   **Labs:**
    *   `Module-2/Labs/Week-8-Lab-Detecting-C2-Traffic.md` (Dataset: `c2-traffic.pcap`)
    *   `Module-2/Labs/Week-8-Lab-B-CIC-IDS2017-Dataset-Analysis.md` (Dataset: CIC-IDS2017)
*   **Assignment:** `Module-2/Assignments/Module-2-Assignment-Network-Forensics-Challenge.md` (Dataset: `challenge.pcap`)

---

## Module 3: SIEM & Log Management (Weeks 9-12)

*   ... (Schedule continues for all 24 weeks, covering all modules and labs)

---

## Module 4: Endpoint Security & Malware Analysis (Weeks 13-16)

*   ... (Includes FlareVM and malware analysis labs)

---

## Module 5: Cloud SOC Monitoring (Weeks 17-20)

*   ... (Includes CSE-CIC-IDS2018 lab)

---

## Module 6: Threat Hunting & CTI (Weeks 21-22)

*   ...

---

## Module 7: AI/ML in SOC & Capstone (Weeks 23-24)

*   **Week 23:** AI and Machine Learning in SOC
*   **Week 24:** Capstone Project & Final Exam


---

## Module 3: SIEM & Log Management (Weeks 9-12)

### **Week 9: Introduction to SIEM**
*   **Topic:** Understanding SIEM concepts and architecture.
*   **Learning Objectives:**
    *   Define SIEM and its core capabilities.
    *   Understand the architecture of a SIEM solution.
*   **Reading:** `Module-3/Study-Materials/Week-9-Introduction-to-SIEM.md`
*   **Lab:** `Module-3/Labs/Week-9-Lab-Introduction-to-Splunk.md`

### **Week 10: Basic SIEM Alerting and Correlation**
*   **Topic:** Creating basic alerts and correlation rules in Splunk.
*   **Learning Objectives:**
    *   Write SPL queries to search and analyze data.
    *   Create correlation searches to detect threats.
*   **Reading:** `Module-3/Study-Materials/Week-10-Basic-SIEM-Alerting-and-Correlation.md`
*   **Lab:** `Module-3/Labs/Week-10-Lab-Creating-Correlation-Searches-in-Splunk.md`

### **Week 11: Threat Intelligence Integration**
*   **Topic:** Integrating threat intelligence feeds into Splunk.
*   **Learning Objectives:**
    *   Understand the value of threat intelligence in a SIEM.
    *   Integrate open-source threat intelligence feeds.
*   **Reading:** `Module-3/Study-Materials/Week-11-Threat-Intelligence-Integration.md`
*   **Lab:** `Module-3/Labs/Week-11-Lab-Integrating-Threat-Intelligence-in-Splunk.md`

### **Week 12: Advanced SIEM Usage**
*   **Topic:** Advanced Splunk searches, dashboards, and reporting.
*   **Learning Objectives:**
    *   Create advanced dashboards and visualizations.
    *   Automate reporting for compliance and security posture.
*   **Reading:** `Module-3/Study-Materials/Week-12-Advanced-SIEM-Usage.md`
*   **Lab:** `Module-3/Labs/Week-12-Lab-Advanced-Splunk-Searches.md`
*   **Assignment:** `Module-3/Assignments/Module-3-Assignment-SIEM-Challenge.md` (Dataset: `botsv1_data.zip`)

---

## Module 4: Endpoint Security & Malware Analysis (Weeks 13-16)

### **Week 13: Endpoint Security and EDR**
*   **Topic:** Introduction to Endpoint Detection and Response (EDR) with Wazuh.
*   **Learning Objectives:**
    *   Understand the capabilities of an EDR solution.
    *   Deploy and configure Wazuh agents.
*   **Reading:** `Module-4/Study-Materials/Week-13-Endpoint-Security-and-EDR.md`
*   **Lab:** `Module-4/Labs/Week-13-Lab-Introduction-to-Wazuh.md`

### **Week 14: Digital Forensics and Incident Response (DFIR)**
*   **Topic:** Memory forensics with Volatility.
*   **Learning Objectives:**
    *   Understand the importance of memory analysis in DFIR.
    *   Use Volatility to analyze memory dumps for signs of compromise.
*   **Reading:** `Module-4/Study-Materials/Week-14-Digital-Forensics-and-Incident-Response.md`
*   **Lab:** `Module-4/Labs/Week-14-Lab-Memory-Forensics-with-Volatility.md` (Dataset: `memdump.rar`)

### **Week 15: Malware Analysis with FlareVM**
*   **Topic:** Setting up FlareVM and performing static and dynamic malware analysis.
*   **Learning Objectives:**
    *   Set up a secure malware analysis environment.
    *   Perform static analysis to understand malware capabilities.
    *   Perform dynamic analysis to observe malware behavior.
*   **Reading:** `Module-4/Study-Materials/Week-15-Malware-Analysis.md`
*   **Labs:**
    *   `Module-4/Labs/Week-15-Lab-B-Setting-Up-Flare-VM.md`
    *   `Module-4/Labs/Week-15-Lab-C-Static-Malware-Analysis.md` (Dataset: PMAT Labs Samples)
    *   `Module-4/Labs/Week-15-Lab-D-Dynamic-Malware-Analysis.md` (Dataset: PMAT Labs Samples)

### **Week 16: Phishing Email Analysis**
*   **Topic:** Analyzing phishing emails to identify threats.
*   **Learning Objectives:**
    *   Analyze email headers and attachments.
    *   Identify malicious links and payloads.
*   **Reading:** `Module-4/Study-Materials/Week-16-Phishing-Email-Analysis.md`
*   **Lab:** `Module-4/Labs/Week-16-Lab-Phishing-Email-Analysis.md` (Dataset: `phishing_email.eml`)
*   **Assignment:** `Module-4/Assignments/Module-4-Assignment-Endpoint-Forensics-Challenge.md` (Dataset: `memdump.rar`)

---

## Module 5: Cloud SOC Monitoring (Weeks 17-20)

### **Week 17: Introduction to Cloud Security**
*   **Topic:** Understanding cloud security concepts and challenges.
*   **Learning Objectives:**
    *   Understand the shared responsibility model.
    *   Identify common cloud security threats.
*   **Reading:** `Module-5-Cloud-SOC-Monitoring/Study-Materials/Week-17-Introduction-to-Cloud-Security.md`
*   **Lab:** `Module-5-Cloud-SOC-Monitoring/Labs/Week-17-Lab-Setting-Up-a-Cloud-Environment.md`

### **Week 18: Cloud SOC Monitoring with CSE-CIC-IDS2018**
*   **Topic:** Analyzing cloud traffic and detecting threats in a cloud environment.
*   **Learning Objectives:**
    *   Analyze cloud-specific attack scenarios.
    *   Use Splunk to detect threats in the CSE-CIC-IDS2018 dataset.
*   **Lab:** `Module-5-Cloud-SOC-Monitoring/Labs/Week-18-Lab-CSE-CIC-IDS2018-Dataset-Analysis.md` (Dataset: CSE-CIC-IDS2018)

### **Week 19: AWS Security Services**
*   **Topic:** Introduction to AWS security services (GuardDuty, CloudTrail, Security Hub).
*   **Learning Objectives:**
    *   Understand the role of each service in cloud security.
    *   Configure and use these services for threat detection.
*   **Reading:** (To be created)
*   **Lab:** (To be created)

### **Week 20: Azure and GCP Security Services**
*   **Topic:** Introduction to Azure Sentinel and Google Cloud Security Command Center.
*   **Learning Objectives:**
    *   Understand the capabilities of Azure Sentinel and GCP SCC.
    *   Compare and contrast cloud-native SIEM solutions.
*   **Reading:** (To be created)
*   **Lab:** (To be created)

---

## Module 6: Threat Hunting & Cyber Threat Intelligence (Weeks 21-22)

### **Week 21: Introduction to Threat Hunting**
*   **Topic:** Proactive threat hunting methodologies and techniques.
*   **Learning Objectives:**
    *   Understand the difference between threat hunting and incident response.
    *   Develop threat hunting hypotheses.
*   **Reading:** `Module-6-Threat-Hunting-and-Cyber-Threat-Intelligence/Study-Materials/Week-21-Introduction-to-Threat-Hunting.md`
*   **Lab:** `Module-6-Threat-Hunting-and-Cyber-Threat-Intelligence/Labs/Week-21-Lab-Developing-a-Threat-Hunt-Hypothesis.md`

### **Week 22: Advanced Threat Hunting**
*   **Topic:** Using advanced tools and techniques for threat hunting.
*   **Learning Objectives:**
    *   Use the MITRE ATT&CK framework for threat hunting.
    *   Automate threat hunting with scripting.
*   **Reading:** (To be created)
*   **Lab:** (To be created)

---

## Module 7: AI/ML in SOC & Capstone (Weeks 23-24)

### **Week 23: AI and Machine Learning in SOC**
*   **Topic:** Using AI and ML for threat detection and response.
*   **Learning Objectives:**
    *   Understand the role of AI/ML in a modern SOC.
    *   Evaluate AI-powered security tools.
*   **Reading:** `Module-7-AI-and-Machine-Learning-in-SOC/Study-Materials/Week-25-Introduction-to-AI-and-ML-in-Cybersecurity.md`
*   **Lab:** (To be created)

### **Week 24: Capstone Project & Final Exam**
*   **Topic:** Comprehensive SOC simulation and final assessment.
*   **Learning Objectives:**
    *   Apply all the skills learned in the program to a real-world scenario.
    *   Demonstrate proficiency in all aspects of SOC operations.
*   **Capstone Project:** `Capstone-Project/Capstone-Project.md`
*   **Final Exam:** `Assessments/Final-Exam.md`
