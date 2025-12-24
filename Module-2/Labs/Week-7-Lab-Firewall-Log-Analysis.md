# Week 7 Lab: Firewall Log Analysis

## Objective

To practice analyzing firewall logs to identify and investigate suspicious network traffic.

## Scenario

You are a SOC analyst at a company that has recently experienced a series of port scans against its public-facing web server. You have been provided with the firewall logs from the time of the incident and you need to analyze them to determine the source of the scans and what ports were targeted.

## Instructions

1. **Download the Sample Log File:**
   - A sample `firewall.log` file is provided in the `resources` directory of this lab.

2. **Analyze the Log File:**
   - Use your preferred command-line tools (`grep`, `awk`, `sed`) or a log analysis tool like Splunk to answer the following questions:
     - What is the IP address of the attacker?
     - What is the time range of the port scan?
     - What ports were targeted in the scan?
     - Were there any successful connections from the attacker's IP address?
     - What is the geographic location of the attacker's IP address? (Use an online tool for this).

3. **Document Your Findings:**
   - Create a new Markdown document named `Firewall-Log-Analysis-Report.md`.
   - In this document, provide the answers to the questions above, along with the commands or queries you used to find them.

## Deliverables

- A Markdown document (`Firewall-Log-Analysis-Report.md`) containing your firewall log analysis report.
