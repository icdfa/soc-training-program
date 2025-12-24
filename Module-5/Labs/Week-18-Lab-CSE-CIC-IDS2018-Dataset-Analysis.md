# Week 18 Lab: CSE-CIC-IDS2018 Dataset Analysis

## Objective

This lab will provide hands-on experience with the CSE-CIC-IDS2018 dataset, a large-scale, diverse, and labeled dataset for intrusion detection. You will learn to analyze and detect various attacks in a cloud environment.

## Dataset

- **CSE-CIC-IDS2018 Dataset:** Contains a large-scale, diverse, and labeled dataset of network traffic and system logs from a cloud environment. It includes various attack scenarios, such as DoS, DDoS, brute force, web attacks, and infiltration.

## Tools

- **Wireshark:** For packet analysis
- **Splunk:** For log analysis and correlation
- **AWS/Azure/GCP:** For cloud environment setup

## Lab Setup

1. **Download the CSE-CIC-IDS2018 Dataset:**
   - Navigate to the [CSE-CIC-IDS2018 dataset page](https://www.unb.ca/cic/datasets/ids-2018.html).
   - Download the dataset.

2. **Set up a Cloud Environment:**
   - Follow the instructions in the Week 17 lab to set up a cloud environment in AWS, Azure, or GCP.

3. **Import Data into Splunk:**
   - Import the dataset into Splunk running in your cloud environment.

## Exercises

### Exercise 1: Analyze Cloud Traffic

1. Analyze the benign cloud traffic to understand normal communication patterns.
2. Identify the different cloud services being used.

### Exercise 2: Detect Infiltration

1. Analyze the infiltration scenario in the dataset.
2. Identify the initial compromise and lateral movement.
3. Write a Splunk query to detect the infiltration.

### Exercise 3: Analyze Botnet Activity

1. Analyze the botnet scenario in the dataset.
2. Identify the C2 communication and botnet activity.
3. Create a Splunk dashboard to monitor botnet activity.

## Deliverables

- A report summarizing your findings for each exercise.
- Screenshots of your analysis and Splunk queries.
- A Splunk dashboard visualizing the botnet activity.
