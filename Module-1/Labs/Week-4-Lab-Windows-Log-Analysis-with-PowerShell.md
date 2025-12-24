# Week 4 Lab: Windows Log Analysis with PowerShell

## Learning Outcomes

By the end of this lab, you will be able to:

- Use the `Get-WinEvent` cmdlet to query and filter Windows Security Event Logs.
- Extract specific properties from event log entries.
- Use PowerShell pipelining to group, sort, and count event data.
- Analyze logon events to identify potential brute-force attacks.

## Objective

To practice using PowerShell to analyze Windows Security Event Logs and identify suspicious activity.

## Scenario

You are a SOC analyst investigating a series of failed login attempts on a Windows Server. You need to use PowerShell to analyze the Security Event Log and determine the source of the attacks.

## Instructions

1. **Generate Failed Login Attempts:**
   - On your Windows Server virtual machine, intentionally enter the wrong password several times to generate failed login events (Event ID 4625).

2. **Analyze the Security Event Log:**
   - Use PowerShell to answer the following questions:
     - How many total failed login attempts were there in the last 24 hours?
     - What are the top 5 source IP addresses of the failed login attempts?
     - What are the top 5 usernames that were targeted?
     - What is the most common logon type for the failed attempts?

3. **Document Your Findings:**
   - Create a new Markdown document named `Windows-Log-Analysis-Report.md`.
   - In this document, provide the answers to the questions above, along with the PowerShell commands you used to find them.

## Deliverables

- A Markdown document (`Windows-Log-Analysis-Report.md`) containing your log analysis report.

## Example Report Structure

```markdown
# Windows Log Analysis Report

## 1. Total Failed Login Attempts

**Answer:** 42

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{LogName=\'Security\'; ID=4625; StartTime=(Get-Date).AddDays(-1)} | Measure-Object
```

## 2. Top 5 Source IP Addresses

**Answer:**
- 10.0.2.2
- 192.168.1.100
- ...

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{LogName=\'Security\'; ID=4625} | ForEach-Object { $_.Properties[19].Value } | Group-Object | Sort-Object -Descending -Property Count | Select-Object -First 5
```

... (continue for all questions)
```
