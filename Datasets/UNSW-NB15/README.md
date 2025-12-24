# UNSW-NB15 Dataset

## Overview

The UNSW-NB15 dataset is a comprehensive network intrusion dataset created by the Cyber Range Lab of the Australian Centre for Cyber Security (ACCS) at the University of New South Wales (UNSW). It contains a hybrid of real modern normal activities and synthetic contemporary attack behaviors.

## Dataset Details

**Source:** University of New South Wales, Australian Centre for Cyber Security

**Size:** Approximately 100 GB (uncompressed PCAP), 2 GB (CSV files)

**Format:** PCAP files and CSV files

**Duration:** 31 hours and 11 minutes

**Records:** 2,540,044 records

## Attack Categories

The dataset includes 9 families of attacks:

**Fuzzers:** Attempts to cause a program or network to suspend by feeding it randomly generated data

**Analysis:** Includes port scans, spam, and HTML file penetrations

**Backdoors:** A technique in which a system security mechanism is bypassed to access a computer or its data

**DoS (Denial of Service):** An attempt to make a machine or network resource unavailable

**Exploits:** A sequence of commands that takes advantage of a bug or vulnerability to compromise the security of a computer or network system

**Generic:** A technique that works against all block ciphers, without regard to their structure

**Reconnaissance:** A mission to obtain information by visual observation or other detection methods

**Shellcode:** A small piece of code used as the payload in the exploitation of a software vulnerability

**Worms:** A self-replicating malware that spreads to other computers

## Download Instructions

1. Visit the official UNSW-NB15 dataset page:
   https://research.unsw.edu.au/projects/unsw-nb15-dataset

2. Download the following files:
   - UNSW-NB15_1.csv
   - UNSW-NB15_2.csv
   - UNSW-NB15_3.csv
   - UNSW-NB15_4.csv
   - UNSW-NB15_features.csv (feature descriptions)
   - UNSW-NB15_LIST_EVENTS.csv (ground truth)

3. Place the files in this directory:
   ```
   /path/to/soc-training-program/Datasets/UNSW-NB15/
   ```

## File Structure

After download, you should have:
```
UNSW-NB15/
├── UNSW-NB15_1.csv
├── UNSW-NB15_2.csv
├── UNSW-NB15_3.csv
├── UNSW-NB15_4.csv
├── UNSW-NB15_features.csv
├── UNSW-NB15_LIST_EVENTS.csv
└── README.md (this file)
```

## Features

The dataset contains 49 features with the class label, including:

**Flow Features:** srcip, sport, dstip, dsport, proto, state, dur, sbytes, dbytes, sttl, dttl, sloss, dloss, service, Sload, Dload, Spkts, Dpkts

**Basic Features:** swin, dwin, stcpb, dtcpb, smeansz, dmeansz, trans_depth, res_bdy_len

**Content Features:** Sjit, Djit, Stime, Ltime, Sintpkt, Dintpkt, tcprtt, synack, ackdat

**Time Features:** is_sm_ips_ports, ct_state_ttl, ct_flw_http_mthd, is_ftp_login, ct_ftp_cmd, ct_srv_src, ct_srv_dst, ct_dst_ltm, ct_src_ltm, ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm

**Label:** attack_cat (attack category), label (0 for normal, 1 for attack)

## Training and Testing Sets

The dataset is divided into:

- **Training set:** UNSW_NB15_training-set.csv (175,341 records)
- **Testing set:** UNSW_NB15_testing-set.csv (82,332 records)

## Usage in Labs

This dataset is used in the following labs:

- **Module 3 Labs:** Machine Learning for Intrusion Detection
- **Module 7 Labs:** AI/ML in SOC Operations
- **Capstone Project:** Comprehensive SOC Analysis

## Citation

If you use this dataset in your research, please cite:

Moustafa, N., & Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set). In 2015 Military Communications and Information Systems Conference (MilCIS) (pp. 1-6). IEEE.

## Additional Resources

- **Dataset Page:** https://research.unsw.edu.au/projects/unsw-nb15-dataset
- **Research Paper:** https://ieeexplore.ieee.org/document/7348942
- **Feature Descriptions:** UNSW-NB15_features.csv
