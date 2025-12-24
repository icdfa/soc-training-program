# Week 8 Lab B: CIC-IDS2017 Dataset Analysis

## Learning Outcomes

By the end of this lab, you will be able to:

- Understand the structure and contents of the CIC-IDS2017 dataset.
- Use Wireshark to analyze PCAP files from the dataset.
- Use Splunk to ingest and query the labeled flow data.
- Differentiate between benign traffic and various attack types (Brute Force, DoS, Web Attacks).

## Objective

This lab will provide hands-on experience with the CIC-IDS2017 dataset, a comprehensive intrusion detection dataset. You will learn to identify and analyze various types of network attacks using this dataset.

## Dataset

- **CIC-IDS2017 Dataset:** Contains benign and the most up-to-date common attacks, which resembles the true real-world data (PCAPs). It also includes the results of the network traffic analysis using CICFlowMeter with labeled flows based on the time stamp, source and destination IPs, source and destination ports, protocols and attack.

## Tools

- **Wireshark:** For packet analysis
- **CICFlowMeter:** For flow-based traffic analysis
- **Splunk:** For log analysis and correlation

## Lab Setup

1. **Download the CIC-IDS2017 Dataset:**
   - Navigate to the [CIC-IDS2017 dataset page](https://www.unb.ca/cic/datasets/ids-2017.html).
   - Download the "GeneratedLabelledFlows" and "PCAPs" directories.

2. **Import Data into Splunk:**
   - Follow the instructions in the Week 9 lab to import the CSV files from the "GeneratedLabelledFlows" directory into Splunk.

## Exercises

### Exercise 1: Analyze Benign Traffic

1. Open the benign traffic PCAP file in Wireshark.
2. Analyze the protocols and communication patterns.
3. In Splunk, search for the benign traffic flows and analyze the flow characteristics.

### Exercise 2: Analyze Brute Force Attacks

1. Open the brute force attack PCAP file in Wireshark.
2. Identify the source of the attack and the targeted service.
3. In Splunk, write a query to identify the brute force attack flows.

### Exercise 3: Analyze DoS/DDoS Attacks

1. Open the DoS/DDoS attack PCAP file in Wireshark.
2. Analyze the attack traffic and identify the attack type.
3. In Splunk, create a dashboard to visualize the DoS/DDoS attack.

### Exercise 4: Analyze Web Attacks

1. Open the web attack PCAP file in Wireshark.
2. Identify the web attack type (e.g., SQL injection, XSS).
3. In Splunk, write a query to detect the web attack flows.

## Deliverables

- A report summarizing your findings for each exercise.
- Screenshots of your Wireshark analysis and Splunk queries.
- A Splunk dashboard visualizing the DoS/DDoS attack.
