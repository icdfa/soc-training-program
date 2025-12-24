# CIC-DDoS2019 Dataset

## Overview

The CIC-DDoS2019 dataset is a comprehensive DDoS evaluation dataset that includes the most common DDoS attacks. It was created by the Canadian Institute for Cybersecurity (CIC) at the University of New Brunswick to address the lack of publicly available, up-to-date DDoS datasets.

## Dataset Details

**Source:** Canadian Institute for Cybersecurity, University of New Brunswick

**Size:** Approximately 12 GB (compressed)

**Format:** PCAP files and CSV files

**Duration:** 2 days of network traffic

## Attack Scenarios

The dataset includes the following DDoS attack types:

**Reflection-Based Attacks:**
- DNS Reflection
- NTP Reflection
- SSDP Reflection
- NetBIOS Reflection
- SNMP Reflection
- CharGEN Reflection
- LDAP Reflection
- MSSQL Reflection

**Exploitation-Based Attacks:**
- Syn Flood
- UDP Flood
- UDP-Lag

**Web-Based Attacks:**
- WebDDoS

## Download Instructions

1. Visit the official CIC-DDoS2019 dataset page:
   https://www.unb.ca/cic/datasets/ddos-2019.html

2. Download the dataset files

3. Extract the files to this directory:
   ```
   unzip CIC-DDoS2019.zip -d /path/to/soc-training-program/Datasets/CIC-DDoS2019/
   ```

## File Structure

After extraction, you should have:
```
CIC-DDoS2019/
├── CSV-01-12/
│   ├── DrDoS_DNS.csv
│   ├── DrDoS_LDAP.csv
│   ├── DrDoS_MSSQL.csv
│   ├── DrDoS_NetBIOS.csv
│   ├── DrDoS_NTP.csv
│   ├── DrDoS_SNMP.csv
│   ├── DrDoS_SSDP.csv
│   ├── DrDoS_UDP.csv
│   ├── Syn.csv
│   ├── TFTP.csv
│   ├── UDPLag.csv
│   └── WebDDoS.csv
└── PCAPs-01-12/
    └── [PCAP files for each attack type]
```

## Features

The CSV files contain 87 features extracted from the network traffic using CICFlowMeter, including:

- Flow-based features (duration, packet count, byte count)
- Statistical features (mean, std, max, min)
- Protocol-specific features
- Time-based features
- Label (attack type or benign)

## Attack Characteristics

**Reflection-Based Attacks:**
These attacks exploit publicly accessible UDP services to amplify attack traffic. The attacker sends requests with a spoofed source IP address (the victim's IP) to vulnerable servers, which then send large responses to the victim.

**Exploitation-Based Attacks:**
These attacks exploit vulnerabilities or weaknesses in network protocols to overwhelm the target with traffic.

**Web-Based Attacks:**
These attacks target web servers and applications, attempting to exhaust server resources through HTTP/HTTPS requests.

## Usage in Labs

This dataset is used in the following labs:

- **Module 2 Labs:** DDoS Detection and Mitigation
- **Module 3 Labs:** Advanced SIEM Correlation for DDoS
- **Module 6 Labs:** Threat Hunting for DDoS Indicators

## Citation

If you use this dataset in your research, please cite:

Sharafaldin, I., Lashkari, A.H., Hakak, S., & Ghorbani, A.A. (2019). Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy. In 2019 International Carnahan Conference on Security Technology (ICCST), Chennai, India, 2019, pp. 1-8.

## Additional Resources

- **Research Paper:** https://ieeexplore.ieee.org/document/8888419
- **Dataset Page:** https://www.unb.ca/cic/datasets/ddos-2019.html
- **DDoS Mitigation Techniques:** https://www.cloudflare.com/learning/ddos/
