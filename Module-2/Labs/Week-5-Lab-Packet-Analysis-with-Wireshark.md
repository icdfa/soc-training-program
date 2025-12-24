# Week 5 Lab: Packet Analysis with Wireshark

## Objective

To practice using Wireshark to analyze network traffic and identify common protocols and potential security issues.

## Scenario

You are a SOC analyst tasked with analyzing a packet capture (PCAP) file from a user's computer who is suspected of visiting a malicious website. You need to use Wireshark to analyze the traffic and determine what happened.

## Instructions

1. **Download the Sample PCAP File:**
   - A sample `suspicious-traffic.pcap` file is provided in the `resources` directory of this lab.

2. **Analyze the PCAP File:**
   - Open the PCAP file in Wireshark.
   - Use Wireshark's display filters to answer the following questions:
     - What is the IP address of the user's computer?
     - What is the IP address of the DNS server?
     - What domain name did the user try to resolve?
     - What is the IP address of the web server that the user connected to?
     - What is the name of the file that the user downloaded?
     - What is the MD5 hash of the downloaded file?
     - Is there any evidence of malicious activity?

3. **Document Your Findings:**
   - Create a new Markdown document named `Packet-Analysis-Report.md`.
   - In this document, provide the answers to the questions above, along with screenshots from Wireshark to support your findings.

## Deliverables

- A Markdown document (`Packet-Analysis-Report.md`) containing your packet analysis report.

## Example Report Structure

```markdown
# Packet Analysis Report

## 1. User's IP Address

**Answer:** 192.168.1.101

**Screenshot:**

![User IP Address](path/to/screenshot.png)

## 2. DNS Server IP Address

**Answer:** 8.8.8.8

**Screenshot:**

![DNS Server IP Address](path/to/screenshot.png)

... (continue for all questions)
```
