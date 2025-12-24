# SOC Training Program - Comprehensive Lab Guide

## Introduction

This guide provides a comprehensive overview of all the labs in the SOC Training Program. It includes setup instructions, objectives, and links to the datasets for each lab.

## Lab Environment Setup

All labs are designed to be run in a virtualized environment. You will need the following software:

- **VirtualBox:** For creating and managing virtual machines
- **FlareVM:** A pre-configured Windows-based security distribution for malware analysis
- **Security Onion:** A Linux-based distribution for intrusion detection, network security monitoring, and log management

Refer to the Week 2 lab for detailed instructions on setting up your SOC home lab.

## Module 1: SOC Fundamentals & Home Lab Setup

- **Week 1 Lab:** Threat Intelligence Research
- **Week 2 Lab:** Home Lab Setup
- **Week 3 Lab:** Log Analysis with CLI Tools
- **Week 4 Lab:** Windows Log Analysis with PowerShell

## Module 2: Network Security & Traffic Analysis

- **Week 5 Lab:** Packet Analysis with Wireshark
- **Week 6 Lab:** Introduction to Security Onion
- **Week 7 Lab:** Firewall Log Analysis
- **Week 8 Lab:** Detecting C2 Traffic
- **Week 8 Lab B:** CIC-IDS2017 Dataset Analysis

## Module 3: SIEM & Log Management

- **Week 9 Lab:** Introduction to Splunk
- **Week 10 Lab:** Creating Correlation Searches in Splunk
- **Week 11 Lab:** Integrating Threat Intelligence in Splunk
- **Week 12 Lab:** Advanced Splunk Searches

## Module 4: Endpoint Security & Malware Analysis

- **Week 13 Lab:** Introduction to Wazuh
- **Week 14 Lab:** Memory Forensics with Volatility
- **Week 15 Lab B:** Setting Up FlareVM for Malware Analysis
- **Week 15 Lab C:** Static Malware Analysis
- **Week 15 Lab D:** Dynamic Malware Analysis
- **Week 16 Lab:** Phishing Email Analysis

## Module 5: Cloud SOC Monitoring

- **Week 17 Lab:** Setting Up a Cloud Environment
- **Week 18 Lab:** CSE-CIC-IDS2018 Dataset Analysis

## Module 6: Threat Hunting & Cyber Threat Intelligence

- **Week 21 Lab:** Developing a Threat Hunt Hypothesis

## Datasets

All datasets are located in the `Datasets` directory. Each dataset has a `README.md` file with detailed information and download instructions.

- **CIC-IDS2017:** Comprehensive intrusion detection dataset
- **CSE-CIC-IDS2018:** Large-scale cloud intrusion detection dataset
- **CIC-DDoS2019:** DDoS evaluation dataset
- **CTU-13:** Labeled botnet traffic dataset
- **UNSW-NB15:** Comprehensive network intrusion dataset

## Safety Precautions

When working with malware samples, always follow the safety precautions outlined in the `malware_samples/README.md` file. Never run malware samples on your host machine.

## Contributing

We welcome contributions to the labs and datasets. Please refer to the `CONTRIBUTING.md` file for guidelines.
