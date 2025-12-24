# Week 3 Lab: Log Analysis with CLI Tools

## Learning Outcomes

By the end of this lab, you will be able to:

- Use `grep` to search for specific patterns in log files
- Utilize `awk` to extract and manipulate specific fields from log data
- Employ `sed` to perform basic text transformations on log entries
- Chain command-line tools together to perform complex log analysis tasks
- Identify suspicious activity in web server logs
- Create professional log analysis reports

## Objective

Master essential Linux command-line tools (`grep`, `awk`, `sed`, `cut`, `sort`, `uniq`) to parse and analyze log files for security investigations.

## Scenario

You are a SOC analyst at SecureCorp investigating a potential web application attack. The security team has detected unusual traffic patterns to the company's web server. You have been provided with Apache web server access logs and need to analyze them to identify suspicious activity, potential attack vectors, and compromised systems.

## Prerequisites

- Linux system (Ubuntu VM from Week 2 lab, or Kali Linux)
- Basic understanding of Apache log format
- Text editor (nano, vim, or VS Code)

## Lab Duration

Approximately 2-3 hours

---

## Part 1: Understanding Apache Log Format (15 minutes)

### Step 1: Apache Combined Log Format

Apache logs use the "Combined Log Format" by default:

```
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
```

**Example log entry:**
```
192.168.1.100 - - [10/Jan/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

**Field breakdown:**

| Field | Position | Description | Example |
|-------|----------|-------------|---------|
| IP Address | $1 | Client IP address | 192.168.1.100 |
| Identity | $2 | RFC 1413 identity (usually `-`) | - |
| Username | $3 | HTTP auth username (usually `-`) | - |
| Timestamp | $4 | Request timestamp | [10/Jan/2024:13:55:36 +0000] |
| Request | $5-$7 | HTTP method, path, protocol | "GET /index.html HTTP/1.1" |
| Status Code | $8 | HTTP response code | 200 |
| Size | $9 | Response size in bytes | 2326 |
| Referer | $10 | Referring URL | "-" |
| User-Agent | $11+ | Client browser/tool | "Mozilla/5.0..." |

### Step 2: Download Sample Log File

1. **Create a working directory:**
   ```bash
   mkdir -p ~/soc-labs/week3
   cd ~/soc-labs/week3
   ```

2. **Download sample log file:**
   ```bash
   # Option 1: Use provided sample from repository
   cp /path/to/soc-training-program/Lab-Resources/Sample-Data/apache-access.log .
   
   # Option 2: Generate sample log (if not available)
   wget https://raw.githubusercontent.com/elastic/examples/master/Common%20Data%20Formats/apache_logs/apache_logs -O access.log
   ```

3. **Verify the file:**
   ```bash
   ls -lh access.log
   head -5 access.log
   ```

---

## Part 2: Basic Log Analysis Commands (30 minutes)

### Exercise 1: Count Total Requests

**Question:** How many total requests are in the log file?

**Command:**
```bash
wc -l access.log
```

**Explanation:**
- `wc` = word count command
- `-l` = count lines
- Each line = one request

**Expected output:**
```
10000 access.log
```

**Document this:** Note the total number of requests in your report.

---

### Exercise 2: Extract IP Addresses

**Question:** How many unique IP addresses made requests?

**Step-by-step approach:**

1. **Extract just the IP addresses (first field):**
   ```bash
   awk '{print $1}' access.log | head -10
   ```
   
   **Explanation:**
   - `awk '{print $1}'` = print first field (IP address)
   - `| head -10` = show first 10 results

2. **Sort the IP addresses:**
   ```bash
   awk '{print $1}' access.log | sort | head -10
   ```
   
   **Explanation:**
   - `sort` = arrange in alphabetical/numerical order
   - This groups duplicate IPs together

3. **Remove duplicates:**
   ```bash
   awk '{print $1}' access.log | sort | uniq | head -10
   ```
   
   **Explanation:**
   - `uniq` = remove adjacent duplicate lines
   - Must be used after `sort`

4. **Count unique IPs:**
   ```bash
   awk '{print $1}' access.log | sort | uniq | wc -l
   ```

**Alternative (more efficient):**
```bash
awk '{print $1}' access.log | sort -u | wc -l
```

**Explanation:**
- `sort -u` = sort and remove duplicates in one step

---

### Exercise 3: Find Top Talkers

**Question:** What are the top 10 most frequent IP addresses?

**Command:**
```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10
```

**Step-by-step breakdown:**

1. `awk '{print $1}'` - Extract IP addresses
2. `sort` - Sort them
3. `uniq -c` - Count occurrences of each unique IP
4. `sort -rn` - Sort by count (reverse numerical)
5. `head -10` - Show top 10

**Expected output:**
```
    523 192.168.1.100
    412 10.0.0.50
    387 172.16.0.25
    ...
```

**Analysis:** IPs with high request counts could indicate:
- Legitimate heavy users
- Web scrapers/bots
- Potential DDoS attacks
- Compromised systems

---

### Exercise 4: Analyze HTTP Status Codes

**Question:** How many 404 (Not Found) errors occurred?

**Command:**
```bash
grep " 404 " access.log | wc -l
```

**Explanation:**
- `grep " 404 "` = search for lines containing " 404 " (with spaces to avoid matching 4040, etc.)
- `wc -l` = count matching lines

**Better approach (using awk):**
```bash
awk '$9 == 404' access.log | wc -l
```

**Explanation:**
- `$9 == 404` = match lines where 9th field (status code) equals 404

**Analyze all status codes:**
```bash
awk '{print $9}' access.log | sort | uniq -c | sort -rn
```

**Expected output:**
```
   7523 200
   1245 404
    523 301
    234 500
    ...
```

---

### Exercise 5: Identify Suspicious URLs

**Question:** What are the top 5 requested URLs that resulted in a 404 error?

**Command:**
```bash
awk '$9 == 404 {print $7}' access.log | sort | uniq -c | sort -rn | head -5
```

**Step-by-step:**
1. `$9 == 404` - Filter for 404 errors
2. `{print $7}` - Extract the URL (7th field)
3. `sort | uniq -c` - Count occurrences
4. `sort -rn` - Sort by frequency
5. `head -5` - Top 5

**Expected output:**
```
     45 /admin/config.php
     32 /wp-admin/
     28 /.env
     23 /phpMyAdmin/
     19 /admin/
```

**Security Analysis:**
- `/admin/` paths = reconnaissance for admin panels
- `/.env` = searching for exposed environment files
- `/phpMyAdmin/` = looking for database management tools
- These are typical attack patterns!

---

## Part 3: Advanced Pattern Matching with grep (45 minutes)

### Exercise 6: Detect Scanning Activity

**Question:** How many requests were made by the user agent "Nikto"?

**Background:** Nikto is a web vulnerability scanner. Its presence indicates security scanning (could be authorized or malicious).

**Command:**
```bash
grep -i "nikto" access.log | wc -l
```

**Explanation:**
- `grep -i` = case-insensitive search
- Searches in the entire line (including User-Agent field)

**Extract full details:**
```bash
grep -i "nikto" access.log | head -5
```

**Get unique IPs using Nikto:**
```bash
grep -i "nikto" access.log | awk '{print $1}' | sort -u
```

---

### Exercise 7: Detect SQL Injection Attempts

**Question:** Find potential SQL injection attempts in the logs.

**Common SQL injection patterns:**
- `' OR '1'='1`
- `UNION SELECT`
- `DROP TABLE`
- `; --` (SQL comment)
- `%27` (URL-encoded single quote)

**Commands:**

1. **Search for SQL keywords:**
   ```bash
   grep -iE "(union|select|insert|update|delete|drop|exec|script)" access.log | wc -l
   ```

   **Explanation:**
   - `-i` = case-insensitive
   - `-E` = extended regex
   - `|` = OR operator

2. **Search for encoded SQL:**
   ```bash
   grep -E "(%27|%20union|%20select)" access.log
   ```

3. **Extract suspicious requests:**
   ```bash
   grep -iE "(union|select)" access.log | awk '{print $1, $7}' | head -10
   ```

   **Output shows:** IP address and requested URL

4. **Count by IP:**
   ```bash
   grep -iE "(union|select)" access.log | awk '{print $1}' | sort | uniq -c | sort -rn
   ```

---

### Exercise 8: Detect XSS Attempts

**Question:** Find potential Cross-Site Scripting (XSS) attempts.

**XSS patterns:**
- `<script>`
- `javascript:`
- `onerror=`
- `%3Cscript%3E` (URL-encoded)

**Command:**
```bash
grep -iE "(<script|javascript:|onerror=|%3Cscript)" access.log
```

**Count XSS attempts:**
```bash
grep -iE "(<script|javascript:|onerror=|%3Cscript)" access.log | wc -l
```

**Identify attackers:**
```bash
grep -iE "(<script|javascript:|onerror=)" access.log | awk '{print $1}' | sort | uniq -c | sort -rn
```

---

### Exercise 9: Detect Directory Traversal

**Question:** Find directory traversal attempts.

**Traversal patterns:**
- `../`
- `..%2F` (URL-encoded)
- `....//`

**Command:**
```bash
grep -E "(\.\./|\.\.%2[Ff])" access.log
```

**Count attempts:**
```bash
grep -E "(\.\./|\.\.%2[Ff])" access.log | wc -l
```

---

## Part 4: Advanced Analysis with awk (45 minutes)

### Exercise 10: Analyze Traffic by Time

**Question:** What hours had the most traffic?

**Command:**
```bash
awk '{print $4}' access.log | cut -d: -f2 | sort | uniq -c | sort -rn
```

**Step-by-step:**
1. `awk '{print $4}'` - Extract timestamp field
2. `cut -d: -f2` - Extract hour from timestamp (split by `:`, take 2nd field)
3. `sort | uniq -c` - Count per hour
4. `sort -rn` - Sort by count

**Expected output:**
```
    1523 14
    1245 13
    1198 15
    ...
```

**Analysis:** Unusual traffic spikes at odd hours (e.g., 3 AM) could indicate automated attacks.

---

### Exercise 11: Analyze Request Methods

**Question:** What HTTP methods are being used?

**Command:**
```bash
awk '{print $6}' access.log | tr -d '"' | sort | uniq -c | sort -rn
```

**Explanation:**
- `awk '{print $6}'` - Extract method (GET, POST, etc.)
- `tr -d '"'` - Remove quotes
- Count and sort

**Expected output:**
```
   8523 GET
   1245 POST
     45 HEAD
     12 OPTIONS
      3 PUT
```

**Security note:** Unusual methods (PUT, DELETE, TRACE) could indicate attack attempts.

---

### Exercise 12: Extract POST Requests

**Question:** Extract all IP addresses that made POST requests.

**Command:**
```bash
awk '$6 == "\"POST"' access.log | awk '{print $1}' | sort -u
```

**Or combined:**
```bash
awk '$6 == "\"POST" {print $1}' access.log | sort -u
```

**Get POST request details:**
```bash
awk '$6 == "\"POST" {print $1, $7, $9}' access.log | head -10
```

**Output:** IP, URL, Status Code

---

### Exercise 13: Calculate Bandwidth Usage

**Question:** What is the total bandwidth used?

**Command:**
```bash
awk '{sum += $10} END {print sum/1024/1024 " MB"}' access.log
```

**Explanation:**
- `{sum += $10}` - Add up all bytes (field 10)
- `END {print sum/1024/1024}` - Convert to MB and print

**Bandwidth by IP:**
```bash
awk '{bytes[$1] += $10} END {for (ip in bytes) print ip, bytes[ip]/1024/1024 " MB"}' access.log | sort -k2 -rn | head -10
```

---

## Part 5: Text Transformation with sed (30 minutes)

### Exercise 14: Extract and Format IPs

**Question:** Create a clean list of unique IPs (one per line, no duplicates).

**Command:**
```bash
awk '{print $1}' access.log | sort -u > unique_ips.txt
```

**Verify:**
```bash
wc -l unique_ips.txt
head unique_ips.txt
```

---

### Exercise 15: Anonymize IP Addresses

**Question:** Replace the last octet of IP addresses with "XXX" for privacy.

**Command:**
```bash
sed 's/\([0-9]\{1,3\}\.\)\{3\}[0-9]\{1,3\}/\1XXX/' access.log | head -5
```

**Simpler approach:**
```bash
sed 's/\.[0-9]*\( \)/\.XXX\1/' access.log | head -5
```

---

### Exercise 16: Extract URLs Only

**Question:** Create a file with just the requested URLs.

**Command:**
```bash
awk '{print $7}' access.log | sort -u > urls.txt
```

**Filter for specific file types:**
```bash
awk '{print $7}' access.log | grep -E "\.(php|asp|jsp)$" | sort -u
```

---

## Part 6: Creating Your Analysis Report (30 minutes)

### Step 17: Document Your Findings

Create a comprehensive report: `Log-Analysis-Report.md`

**Template:**

```markdown
# Apache Log Analysis Report

**Analyst:** [Your Name]  
**Date:** [Analysis Date]  
**Log File:** access.log  
**Analysis Period:** [Date range from logs]

---

## Executive Summary

[2-3 sentence summary of key findings]

---

## 1. Traffic Overview

### Total Requests
**Answer:** [number]

**Command:**
```bash
wc -l access.log
```

### Unique IP Addresses
**Answer:** [number]

**Command:**
```bash
awk '{print $1}' access.log | sort -u | wc -l
```

### Top 10 IP Addresses
**Answer:**
```
[paste output]
```

**Command:**
```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -10
```

---

## 2. HTTP Status Code Analysis

### Status Code Distribution
**Answer:**
```
[paste output]
```

**Command:**
```bash
awk '{print $9}' access.log | sort | uniq -c | sort -rn
```

### 404 Errors
**Total 404 errors:** [number]

**Top 5 URLs with 404:**
```
[paste output]
```

**Command:**
```bash
awk '$9 == 404 {print $7}' access.log | sort | uniq -c | sort -rn | head -5
```

**Analysis:** [Your interpretation of the 404 errors]

---

## 3. Security Analysis

### Scanning Activity (Nikto)
**Requests from Nikto:** [number]

**Command:**
```bash
grep -i "nikto" access.log | wc -l
```

**Source IPs:**
```
[paste IPs]
```

### SQL Injection Attempts
**Total attempts:** [number]

**Command:**
```bash
grep -iE "(union|select|insert|drop)" access.log | wc -l
```

**Attacking IPs:**
```
[paste output]
```

**Sample malicious requests:**
```
[paste 2-3 examples]
```

### XSS Attempts
**Total attempts:** [number]

**Command:**
```bash
grep -iE "(<script|javascript:|onerror=)" access.log | wc -l
```

### Directory Traversal
**Total attempts:** [number]

**Command:**
```bash
grep -E "(\.\./|\.\.%2[Ff])" access.log | wc -l
```

---

## 4. Request Method Analysis

**Distribution:**
```
[paste output]
```

**Command:**
```bash
awk '{print $6}' access.log | tr -d '"' | sort | uniq -c | sort -rn
```

---

## 5. Suspicious Activity Summary

### High-Risk IP Addresses

| IP Address | Requests | Suspicious Activities |
|------------|----------|----------------------|
| [IP] | [count] | [SQL injection, scanning, etc.] |
| [IP] | [count] | [Activities] |

### Recommended Actions

1. **Block the following IPs:**
   - [IP 1] - Reason: [SQL injection attempts]
   - [IP 2] - Reason: [Web scanning]

2. **Investigate further:**
   - [Specific finding requiring investigation]

3. **Patch/Update:**
   - [Vulnerabilities discovered]

---

## 6. Bandwidth Analysis

**Total bandwidth:** [X MB/GB]

**Top 10 bandwidth consumers:**
```
[paste output]
```

---

## Conclusion

[Summary of the analysis, key findings, and overall security posture]

---

## Appendices

### Appendix A: All Commands Used
```bash
[List all commands]
```

### Appendix B: Suspicious IPs List
```
[Full list of suspicious IPs]
```
```

---

## Deliverables

Submit the following:

1. **Log-Analysis-Report.md** - Your complete analysis report
2. **unique_ips.txt** - List of all unique IP addresses
3. **suspicious_ips.txt** - List of IPs involved in attacks
4. **urls.txt** - List of all requested URLs

---

## Evaluation Criteria

- **Completeness:** Did you answer all questions?
- **Command Accuracy:** Are your commands correct and efficient?
- **Analysis Quality:** Did you provide meaningful security insights?
- **Documentation:** Is your report well-organized and professional?
- **Security Awareness:** Did you identify and explain security threats?

---

## Additional Challenges (Optional)

1. **Create a bash script** that automates this entire analysis
2. **Generate visualizations** using gnuplot or similar
3. **Compare multiple log files** from different days
4. **Create detection rules** for a SIEM based on your findings
5. **Write a one-liner** to find the most dangerous IP address

---

## Additional Resources

- [Apache Log Format Documentation](https://httpd.apache.org/docs/current/logs.html)
- [Grep Tutorial](https://www.gnu.org/software/grep/manual/grep.html)
- [Awk Tutorial](https://www.gnu.org/software/gawk/manual/gawk.html)
- [Sed Tutorial](https://www.gnu.org/software/sed/manual/sed.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Beginner to Intermediate
