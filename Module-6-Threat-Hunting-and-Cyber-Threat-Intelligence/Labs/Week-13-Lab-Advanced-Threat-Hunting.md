_# Week 13 Lab: Advanced Threat Hunting

## Learning Outcomes

By the end of this lab, you will be able to:

- Apply the threat hunting loop to a real-world scenario.
- Use advanced search techniques to hunt for threats in large datasets.
- Pivot between different data sources to build a complete picture of an attack.
- Document and report on the findings of a threat hunt.

## 1. Objective

In this lab, you will conduct a full threat hunt from hypothesis to conclusion. You will use the skills you have learned throughout this course to hunt for evidence of a sophisticated adversary in a large dataset.

## 2. Scenario

You are a threat hunter at a large financial institution. Your team has received a threat intelligence report about a new APT group called "FIN10" that is targeting financial institutions. The report indicates that FIN10 uses a custom PowerShell-based backdoor for persistence and lateral movement.

## 3. Your Task

Your mission is to hunt for evidence of FIN10 activity in your organization's network. You have been provided with a large dataset of Windows event logs, firewall logs, and proxy logs.

## 4. The Hunt

### Step 1: Hypothesis

Based on the threat intelligence report, develop a hypothesis to guide your hunt. For example:

"FIN10 is active in our network and is using a PowerShell-based backdoor for persistence. We can detect this by searching for suspicious PowerShell execution in our Windows event logs."

### Step 2: Data Collection

Identify the data sources you will need to test your hypothesis. In this case, you will need:

-   Windows Security Event Logs (for PowerShell execution events)
-   Windows PowerShell Script Block Logging
-   Firewall logs (for C2 communication)
-   Proxy logs (for malicious downloads)

### Step 3: Investigation

Use your SIEM (Splunk) to search for evidence of suspicious PowerShell execution. Look for:

-   Obfuscated PowerShell commands
-   PowerShell commands that download and execute code from the internet
-   PowerShell commands that create new services or scheduled tasks
-   PowerShell commands that connect to unusual IP addresses

### Step 4: Analysis

If you find any suspicious activity, pivot to other data sources to gather more information. For example:

-   If you find a suspicious IP address, search for it in your firewall and proxy logs.
-   If you find a suspicious file hash, search for it in your EDR logs.

### Step 5: Conclusion

Based on your findings, draw a conclusion about whether or not FIN10 is active in your network. Document your findings and present them to your team.

## 5. Deliverables

-   A written report documenting your threat hunt.
-   Your threat hunt hypothesis.
-   The search queries you used to hunt for threats.
-   A timeline of the attack (if you found one).
-   A list of all Indicators of Compromise (IOCs) you identified.
_
