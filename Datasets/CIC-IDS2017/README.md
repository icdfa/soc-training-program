# CIC-IDS2017 Dataset

## Overview

The CIC-IDS2017 dataset contains benign and the most up-to-date common attacks, which resembles the true real-world data (PCAPs). It also includes the results of the network traffic analysis using CICFlowMeter with labeled flows based on the time stamp, source and destination IPs, source and destination ports, protocols and attack.

## Dataset Details

**Source:** Canadian Institute for Cybersecurity, University of New Brunswick

**Size:** Approximately 8 GB (compressed)

**Format:** PCAP files and CSV files

**Duration:** 5 days of network traffic (Monday to Friday)

## Attack Scenarios

The dataset includes the following attack scenarios:

**Monday (Benign):**
- Normal user activity

**Tuesday:**
- FTP-Patator (Brute Force FTP)
- SSH-Patator (Brute Force SSH)

**Wednesday:**
- DoS slowloris
- DoS Slowhttptest
- DoS Hulk
- DoS GoldenEye
- Heartbleed

**Thursday:**
- Web Attack - Brute Force
- Web Attack - XSS
- Web Attack - SQL Injection
- Infiltration

**Friday:**
- Botnet ARES
- PortScan
- DDoS LOIT

## Download Instructions

1. Visit the official CIC-IDS2017 dataset page:
   https://www.unb.ca/cic/datasets/ids-2017.html

2. Download the following files:
   - GeneratedLabelledFlows.zip (CSV files with labeled flows)
   - PCAPs.zip (Raw packet captures)

3. Extract the files to this directory:
   ```
   unzip GeneratedLabelledFlows.zip -d /path/to/soc-training-program/Datasets/CIC-IDS2017/
   unzip PCAPs.zip -d /path/to/soc-training-program/Datasets/CIC-IDS2017/
   ```

## File Structure

After extraction, you should have:
```
CIC-IDS2017/
├── GeneratedLabelledFlows/
│   ├── Monday-WorkingHours.pcap_ISCX.csv
│   ├── Tuesday-WorkingHours.pcap_ISCX.csv
│   ├── Wednesday-workingHours.pcap_ISCX.csv
│   ├── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
│   ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv
│   ├── Friday-WorkingHours-Morning.pcap_ISCX.csv
│   └── Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
└── PCAPs/
    ├── Monday-WorkingHours.pcap
    ├── Tuesday-WorkingHours.pcap
    ├── Wednesday-workingHours.pcap
    ├── Thursday-WorkingHours-Morning-WebAttacks.pcap
    ├── Thursday-WorkingHours-Afternoon-Infilteration.pcap
    ├── Friday-WorkingHours-Morning.pcap
    └── Friday-WorkingHours-Afternoon-DDos.pcap
```

## Features

The CSV files contain 78 features extracted from the network traffic, including:

- Flow duration
- Total forward/backward packets
- Total length of forward/backward packets
- Forward/backward packet length max, min, mean, std
- Flow bytes/s
- Flow packets/s
- Flow IAT mean, std, max, min
- Forward/backward IAT total, mean, std, max, min
- Forward/backward PSH flags
- Forward/backward URG flags
- Forward/backward header length
- Forward/backward packets/s
- Min/max/mean/std packet length
- Fin flag count
- SYN flag count
- RST flag count
- PSH flag count
- ACK flag count
- URG flag count
- CWE flag count
- ECE flag count
- Down/up ratio
- Average packet size
- Forward/backward segment size average
- Forward/backward bytes/bulk average
- Forward/backward packet/bulk average
- Forward/backward bulk rate average
- Subflow forward/backward packets
- Subflow forward/backward bytes
- Init_Win_bytes_forward
- Init_Win_bytes_backward
- act_data_pkt_fwd
- min_seg_size_forward
- Active mean, std, max, min
- Idle mean, std, max, min
- Label (attack type or benign)

## Usage in Labs

This dataset is used in the following labs:

- **Week 8 Lab B:** CIC-IDS2017 Dataset Analysis
- **Module 2 Assignment:** Network Forensics Challenge

## Citation

If you use this dataset in your research, please cite:

Sharafaldin, I., Lashkari, A.H., & Ghorbani, A.A. (2018). Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization. In Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), Portugal, January 2018.

## Additional Resources

- **Research Paper:** https://www.scitepress.org/Papers/2018/66398/66398.pdf
- **CICFlowMeter Tool:** https://github.com/ahlashkari/CICFlowMeter
- **Analysis Tutorials:** https://www.unb.ca/cic/datasets/ids-2017.html
