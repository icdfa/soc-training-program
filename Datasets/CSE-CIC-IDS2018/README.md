# CSE-CIC-IDS2018 Dataset

## Overview

The CSE-CIC-IDS2018 dataset is a large-scale, diverse, and labeled dataset for intrusion detection in cloud environments. It was created by the Communications Security Establishment (CSE) and the Canadian Institute for Cybersecurity (CIC) at the University of New Brunswick.

## Dataset Details

**Source:** Canadian Institute for Cybersecurity, University of New Brunswick

**Size:** Approximately 15 GB (compressed)

**Format:** PCAP files and CSV files

**Duration:** 10 days of network traffic

**Environment:** AWS cloud infrastructure

## Attack Scenarios

The dataset includes the following attack scenarios over 10 days:

**Day 1 (February 14, 2018 - Wednesday):**
- Benign traffic

**Day 2 (February 15, 2018 - Thursday):**
- FTP-BruteForce
- SSH-Bruteforce

**Day 3 (February 16, 2018 - Friday):**
- DoS attacks - GoldenEye
- DoS attacks - Slowloris

**Day 4 (February 20, 2018 - Tuesday):**
- DoS attacks - Slowhttptest
- DoS attacks - Hulk

**Day 5 (February 21, 2018 - Wednesday):**
- DDoS attacks - LOIC-HTTP
- DDoS attacks - HOIC

**Day 6 (February 22, 2018 - Thursday):**
- DDoS attacks - LOIC-UDP

**Day 7 (February 23, 2018 - Friday):**
- Infiltration from inside network
- Botnet activity

**Day 8 (February 28, 2018 - Wednesday):**
- Web attacks - Brute Force
- Web attacks - XSS
- Web attacks - SQL Injection

**Day 9 (March 1, 2018 - Thursday):**
- Infiltration of the network from inside

**Day 10 (March 2, 2018 - Friday):**
- Botnet traffic

## Download Instructions

1. Visit the official CSE-CIC-IDS2018 dataset page:
   https://www.unb.ca/cic/datasets/ids-2018.html

2. Download the dataset files (organized by day)

3. Extract the files to this directory:
   ```
   unzip CSE-CIC-IDS2018.zip -d /path/to/soc-training-program/Datasets/CSE-CIC-IDS2018/
   ```

## File Structure

After extraction, you should have:
```
CSE-CIC-IDS2018/
├── Processed Traffic Data for ML Algorithms/
│   ├── Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
│   ├── Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
│   ├── Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
│   └── Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
└── Original Network Traffic and Log data/
    └── [PCAP files organized by day]
```

## Features

The CSV files contain 79 features extracted from the network traffic using CICFlowMeter, similar to CIC-IDS2017 but with additional cloud-specific features.

## Cloud Infrastructure

The dataset was generated in an AWS environment with the following components:

- Multiple Ubuntu and Windows servers
- Routers and switches
- Firewall
- Web servers
- Database servers
- File servers

## Usage in Labs

This dataset is used in the following labs:

- **Week 18 Lab:** CSE-CIC-IDS2018 Dataset Analysis
- **Module 5 Assignment:** Cloud SOC Challenge

## Citation

If you use this dataset in your research, please cite:

Sharafaldin, I., Lashkari, A.H., Hakak, S., & Ghorbani, A.A. (2019). Developing Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy. In 2019 International Carnahan Conference on Security Technology (ICCST), Chennai, India, 2019, pp. 1-8.

## Additional Resources

- **Research Paper:** https://ieeexplore.ieee.org/document/8888419
- **Dataset Page:** https://www.unb.ca/cic/datasets/ids-2018.html
- **Analysis Tools:** CICFlowMeter, Wireshark, Splunk
