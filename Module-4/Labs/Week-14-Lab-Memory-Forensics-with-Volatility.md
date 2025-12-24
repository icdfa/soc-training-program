# Week 14 Lab: Memory Forensics with Volatility

## Objective

To practice using Volatility to analyze a memory dump from a compromised system.

## Scenario

You are a SOC analyst and you have been provided with a memory dump from a Windows machine that is suspected of being infected with malware. You need to use Volatility to analyze the memory dump and determine what happened.

## Instructions

1. **Download the Sample Memory Dump:**
   - A sample memory dump (`memdump.vmem`) is provided in the `resources` directory of this lab.

2. **Analyze the Memory Dump:**
   - Use Volatility to answer the following questions:
     - What is the operating system of the compromised machine?
     - What was the date and time the memory dump was taken?
     - What processes were running on the machine?
     - What network connections were active?
     - Is there any evidence of malware?

3. **Document Your Findings:**
   - Create a new Markdown document named `Memory-Forensics-Report.md`.
   - In this document, provide the answers to the questions above, along with the Volatility commands you used to find them.

## Deliverables

- A Markdown document (`Memory-Forensics-Report.md`) containing your memory forensics report.
