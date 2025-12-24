# Week 8 Lab: Detecting C2 Traffic

## Learning Outcomes

By the end of this lab, you will be able to:

- Identify the characteristics of C2 traffic, such as beaconing and DNS tunneling.
- Use Wireshark to filter and analyze network traffic for signs of C2 communication.
- Differentiate between normal and malicious network traffic patterns.
- Document findings and report on potential C2 activity.

## Objective

To practice analyzing network traffic to identify command and control (C2) communication.

## Scenario

You are a SOC analyst and you have been provided with a PCAP file containing traffic from a suspected compromised host. You need to analyze the traffic to determine if the host is communicating with a C2 server.

## Instructions

1. **Download the Sample PCAP File:**
   - A sample `c2-traffic.pcap` file is provided in the `resources` directory of this lab.

2. **Analyze the PCAP File:**
   - Open the PCAP file in Wireshark or your preferred network analysis tool.
   - Look for evidence of C2 communication, such as:
     - Beaconing activity (regular callbacks to a specific IP address).
     - DNS tunneling (unusual DNS queries).
     - Use of non-standard ports or protocols.
     - Long-lived connections with small amounts of data being transferred.

3. **Document Your Findings:**
   - Create a new Markdown document named `C2-Detection-Report.md`.
   - In this document, provide a summary of your findings, including:
     - The IP address of the suspected compromised host.
     - The IP address of the suspected C2 server.
     - The evidence you found to support your conclusion.
     - Any other relevant information.

## Deliverables

- A Markdown document (`C2-Detection-Report.md`) containing your C2 detection report.
