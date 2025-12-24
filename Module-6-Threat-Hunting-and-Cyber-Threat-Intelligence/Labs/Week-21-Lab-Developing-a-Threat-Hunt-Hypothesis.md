# Week 21 Lab: Developing a Threat Hunt Hypothesis

## Learning Outcomes

By the end of this lab, you will be able to:

- Develop a threat hunting hypothesis based on a real-world threat scenario.
- Identify the data sources required to test a threat hunting hypothesis.
- Formulate search queries to search for evidence of malicious activity.
- Understand the importance of a structured approach to threat hunting.

## 1. Objective

In this lab, you will practice developing a threat hunt hypothesis based on a real-world threat scenario. This is a critical first step in the threat hunting process.

## 2. Scenario

A new ransomware variant called "LockData" has been reported in the news. It is known to use a specific technique for lateral movement: PsExec. Your organization uses Windows systems extensively.

## 3. Your Task

Develop a threat hunt hypothesis to search for evidence of LockData ransomware in your organization's network. Your hypothesis should be specific, measurable, and testable.

## 4. Hypothesis Development

1.  **Identify the threat:** LockData ransomware.
2.  **Identify the technique:** Lateral movement using PsExec.
3.  **Identify the target:** Windows systems in your organization.
4.  **Formulate the hypothesis:** "The LockData ransomware is present in our network and is using PsExec for lateral movement between Windows hosts. We can detect this by searching for evidence of PsExec execution in our logs."

## 5. Data Sources

What data sources would you need to test this hypothesis? (e.g., Windows event logs, firewall logs, etc.)

## 6. Search Queries

What search queries would you use to search for evidence of PsExec execution? (e.g., Splunk queries, PowerShell scripts, etc.)

## 7. Deliverables

- Your documented threat hunt hypothesis.
- A list of required data sources.
- Example search queries.
