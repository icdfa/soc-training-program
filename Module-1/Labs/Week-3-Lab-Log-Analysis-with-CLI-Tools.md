# Week 3 Lab: Log Analysis with CLI Tools

## Objective

To practice using essential Linux command-line tools (`grep`, `awk`, `sed`) to parse and analyze log files.

## Scenario

You are a SOC analyst investigating a potential security incident. You have been provided with a sample Apache web server access log (`access.log`) and you need to analyze it to identify any suspicious activity.

## Instructions

1. **Download the Sample Log File:**
   - A sample `access.log` file is provided in the `resources` directory of this lab.

2. **Analyze the Log File:**
   - Use the `grep`, `awk`, and `sed` commands to answer the following questions:
     - How many total requests are in the log file?
     - How many unique IP addresses made requests?
     - What are the top 10 most frequent IP addresses?
     - What is the total number of 404 errors?
     - What are the top 5 requested URLs that resulted in a 404 error?
     - How many requests were made by the user agent "Nikto"?
     - Extract all IP addresses that made POST requests.

3. **Document Your Findings:**
   - Create a new Markdown document named `Log-Analysis-Report.md`.
   - In this document, provide the answers to the questions above, along with the commands you used to find them.

## Deliverables

- A Markdown document (`Log-Analysis-Report.md`) containing your log analysis report.

## Example Report Structure

```markdown
# Log Analysis Report

## 1. Total Requests

**Answer:** 12345

**Command:**
```bash
wc -l access.log
```

## 2. Unique IP Addresses

**Answer:** 123

**Command:**
```bash
awk '{print $1}' access.log | sort -u | wc -l
```

... (continue for all questions)
```
