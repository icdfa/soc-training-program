# Week 8 Lab B: CIC-IDS2017 Dataset Analysis

## Learning Outcomes

By the end of this lab, you will be able to:

- Understand the structure and contents of the CIC-IDS2017 dataset
- Use Wireshark to analyze PCAP files from the dataset
- Use Splunk to ingest and query the labeled flow data
- Differentiate between benign traffic and various attack types (Brute Force, DoS, Web Attacks)

## Objective

This lab will provide hands-on experience with the CIC-IDS2017 dataset, a comprehensive intrusion detection dataset. You will learn to identify and analyze various types of network attacks using this dataset.

## Dataset Overview

The **CIC-IDS2017 dataset** contains benign and the most up-to-date common attacks, which resembles true real-world data. It includes:

- **PCAPs:** Raw packet captures of network traffic
- **Labeled Flow Data:** CSV files with extracted flow features and attack labels
- **Attack Types:** Brute Force, DoS, DDoS, Web Attacks, Infiltration, Botnet
- **Duration:** 5 days of network activity (Monday to Friday)
- **Total Size:** Approximately 8GB

**Dataset Location:** `/home/ubuntu/soc-training-program/Datasets/CIC-IDS2017/`

## Prerequisites

- Wireshark installed on your analysis machine
- Splunk instance running (from Week 9 lab)
- At least 20GB of free disk space
- Basic understanding of network protocols (TCP, UDP, HTTP, DNS)

## Lab Duration

Approximately 4-5 hours

---

## Part 1: Dataset Download and Preparation (30 minutes)

### Step 1: Download the CIC-IDS2017 Dataset

The dataset is available from the Canadian Institute for Cybersecurity (CIC).

1. Navigate to the dataset directory:
   ```bash
   cd /home/ubuntu/soc-training-program/Datasets/CIC-IDS2017/
   ```

2. Read the README file for download instructions:
   ```bash
   cat README.md
   ```

3. Download the dataset from the official source:
   - **Official URL:** https://www.unb.ca/cic/datasets/ids-2017.html
   - Download both the **PCAPs** and **GeneratedLabelledFlows** directories

4. Verify the download:
   ```bash
   ls -lh
   ```

### Step 2: Understand the Dataset Structure

The CIC-IDS2017 dataset is organized by day:

```
CIC-IDS2017/
├── Monday-WorkingHours.pcap           # Benign traffic only
├── Tuesday-WorkingHours.pcap          # FTP-Patator, SSH-Patator
├── Wednesday-WorkingHours.pcap        # DoS/DDoS attacks
├── Thursday-WorkingHours.pcap         # Web attacks, Infiltration
├── Friday-WorkingHours.pcap           # Botnet, DDoS
└── GeneratedLabelledFlows/
    ├── Monday-WorkingHours.pcap_ISCX.csv
    ├── Tuesday-WorkingHours.pcap_ISCX.csv
    ├── Wednesday-workingHours.pcap_ISCX.csv
    ├── Thursday-WorkingHours.pcap_ISCX.csv
    └── Friday-WorkingHours.pcap_ISCX.csv
```

**Attack Schedule:**

| Day       | Time Period      | Attack Type                                    |
|-----------|------------------|------------------------------------------------|
| Monday    | All day          | Benign (Normal) traffic only                   |
| Tuesday   | 9:20 AM - 10:20 AM | FTP-Patator (Brute Force)                     |
| Tuesday   | 2:00 PM - 3:00 PM | SSH-Patator (Brute Force)                     |
| Wednesday | 9:47 AM - 10:10 AM | DoS GoldenEye                                 |
| Wednesday | 10:14 AM - 10:35 AM | DoS Hulk                                     |
| Wednesday | 10:43 AM - 11:00 AM | DoS Slowhttptest                             |
| Wednesday | 11:10 AM - 11:23 AM | DoS Slowloris                                |
| Wednesday | 3:00 PM - 4:00 PM | Heartbleed                                    |
| Thursday  | 9:20 AM - 10:00 AM | Web Attack - Brute Force                     |
| Thursday  | 10:15 AM - 10:35 AM | Web Attack - XSS                            |
| Thursday  | 10:40 AM - 10:42 AM | Web Attack - SQL Injection                  |
| Thursday  | 2:30 PM - 3:30 PM | Infiltration                                  |
| Friday    | 10:00 AM - 11:00 AM | Botnet ARES                                  |
| Friday    | 3:00 PM - 4:00 PM | DDoS LOIT                                     |

### Step 3: Examine the CSV Flow Data

1. Navigate to the GeneratedLabelledFlows directory:
   ```bash
   cd GeneratedLabelledFlows/
   ```

2. View the first few lines of a CSV file:
   ```bash
   head -20 Monday-WorkingHours.pcap_ISCX.csv
   ```

3. Count the number of flows:
   ```bash
   wc -l Monday-WorkingHours.pcap_ISCX.csv
   ```

**CSV File Structure:**

The CSV files contain 79 features extracted from each network flow, including:

- **Flow identifiers:** Source IP, Destination IP, Source Port, Destination Port, Protocol
- **Flow statistics:** Duration, packet counts, byte counts
- **Timing features:** Flow IAT (Inter-Arrival Time), Packet IAT
- **Flag counts:** FIN, SYN, RST, PSH, ACK, URG, CWE, ECE
- **Packet length statistics:** Mean, Std, Max, Min
- **Label:** The attack type or "BENIGN"

---

## Part 2: Analyzing Benign Traffic (45 minutes)

### Exercise 1: Wireshark Analysis of Benign Traffic

**Objective:** Establish a baseline of normal network activity.

1. Open Monday's PCAP file in Wireshark:
   ```bash
   wireshark Monday-WorkingHours.pcap &
   ```

2. **Analyze Protocol Distribution:**
   - Go to **Statistics → Protocol Hierarchy**
   - Document the percentage of each protocol (HTTP, HTTPS, DNS, etc.)

3. **Identify Top Talkers:**
   - Go to **Statistics → Conversations**
   - Sort by "Bytes" to find the most active hosts
   - Document the top 5 IP addresses and their traffic volume

4. **Examine HTTP Traffic:**
   - Apply filter: `http`
   - Analyze typical HTTP requests
   - Document common User-Agents and requested URLs

5. **Examine DNS Traffic:**
   - Apply filter: `dns`
   - Analyze DNS query patterns
   - Document frequently queried domains

**Questions to Answer:**

1. What is the most common protocol in benign traffic?
2. What are the top 5 destination ports?
3. What is the average packet size?
4. What User-Agents are present in HTTP traffic?
5. Are there any unusual patterns in the benign traffic?

### Exercise 2: Splunk Analysis of Benign Traffic

**Objective:** Import and analyze benign flow data in Splunk.

1. **Import CSV into Splunk:**
   - Log in to your Splunk instance
   - Go to **Settings → Add Data → Upload**
   - Upload `Monday-WorkingHours.pcap_ISCX.csv`
   - Set source type to `csv`
   - Create a new index called `cic_ids_2017`

2. **Basic Splunk Queries:**

   **Query 1: Count total flows**
   ```spl
   index=cic_ids_2017 source="*Monday*"
   | stats count
   ```

   **Query 2: Count flows by label**
   ```spl
   index=cic_ids_2017 source="*Monday*"
   | stats count by Label
   ```

   **Query 3: Top source IPs**
   ```spl
   index=cic_ids_2017 source="*Monday*"
   | stats count by "Source IP"
   | sort -count
   | head 10
   ```

   **Query 4: Protocol distribution**
   ```spl
   index=cic_ids_2017 source="*Monday*"
   | stats count by Protocol
   ```

   **Query 5: Average flow duration**
   ```spl
   index=cic_ids_2017 source="*Monday*"
   | stats avg("Flow Duration") as avg_duration
   ```

3. **Create a Baseline Dashboard:**
   - Create a new dashboard called "CIC-IDS2017 Baseline"
   - Add the following panels:
     - Protocol distribution (pie chart)
     - Top source IPs (bar chart)
     - Flow duration over time (line chart)
     - Packet size distribution (histogram)

**Deliverable:** Screenshot of your Splunk dashboard showing benign traffic analysis.

---

## Part 3: Analyzing Brute Force Attacks (60 minutes)

### Exercise 3: FTP Brute Force Attack (Tuesday 9:20-10:20 AM)

**Attack Description:** FTP-Patator is a brute force attack tool that attempts to guess FTP credentials by trying multiple username/password combinations.

1. **Open Tuesday's PCAP in Wireshark:**
   ```bash
   wireshark Tuesday-WorkingHours.pcap &
   ```

2. **Filter for FTP traffic during the attack window:**
   ```
   ftp && frame.time >= "2017-07-04 09:20:00" && frame.time <= "2017-07-04 10:20:00"
   ```

3. **Analyze the attack:**
   - Identify the attacker's IP address
   - Count the number of FTP login attempts
   - Examine the FTP responses (530 Login incorrect)
   - Look for successful logins (230 Login successful)

4. **Follow an FTP stream:**
   - Right-click on an FTP packet → Follow → TCP Stream
   - Observe the brute force attempts

**Wireshark Questions:**

1. What is the attacker's IP address?
2. What is the target's IP address?
3. How many FTP login attempts were made?
4. What usernames were tried?
5. Were any login attempts successful?

### Exercise 4: SSH Brute Force Attack (Tuesday 2:00-3:00 PM)

1. **Filter for SSH traffic during the attack window:**
   ```
   ssh && frame.time >= "2017-07-04 14:00:00" && frame.time <= "2017-07-04 15:00:00"
   ```

2. **Analyze SSH connection attempts:**
   - Look for multiple SSH handshakes from the same source
   - Identify failed authentication attempts
   - Calculate the rate of connection attempts

**Splunk Analysis:**

1. **Import Tuesday's CSV into Splunk**

2. **Detect FTP Brute Force:**
   ```spl
   index=cic_ids_2017 source="*Tuesday*" Label="FTP-Patator"
   | stats count by "Source IP", "Destination IP"
   | sort -count
   ```

3. **Detect SSH Brute Force:**
   ```spl
   index=cic_ids_2017 source="*Tuesday*" Label="SSH-Patator"
   | stats count by "Source IP", "Destination IP"
   | sort -count
   ```

4. **Create a detection rule:**
   ```spl
   index=cic_ids_2017 "Destination Port"=21 OR "Destination Port"=22
   | stats count by "Source IP", "Destination IP", "Destination Port"
   | where count > 100
   | eval attack_type=if('Destination Port'=21, "FTP Brute Force", "SSH Brute Force")
   ```

5. **Save as alert:** Save this search as an alert that triggers when count > 100

**Deliverable:** 
- Wireshark screenshots showing brute force attempts
- Splunk query results identifying the attacks
- A written analysis of the attack patterns

---

## Part 4: Analyzing DoS/DDoS Attacks (60 minutes)

### Exercise 5: DoS GoldenEye Attack (Wednesday 9:47-10:10 AM)

**Attack Description:** GoldenEye is a HTTP DoS tool that sends legitimate HTTP requests to overwhelm the target server.

1. **Open Wednesday's PCAP in Wireshark:**
   ```bash
   wireshark Wednesday-workingHours.pcap &
   ```

2. **Filter for the attack window:**
   ```
   frame.time >= "2017-07-05 09:47:00" && frame.time <= "2017-07-05 10:10:00"
   ```

3. **Analyze HTTP traffic:**
   - Apply filter: `http`
   - Go to **Statistics → HTTP → Requests**
   - Identify the target web server
   - Count the request rate

4. **Examine packet patterns:**
   - Look for high packet rates from specific IPs
   - Analyze HTTP request headers
   - Check for randomized User-Agents

**Splunk Analysis:**

1. **Import Wednesday's CSV into Splunk**

2. **Detect DoS GoldenEye:**
   ```spl
   index=cic_ids_2017 source="*Wednesday*" Label="DoS GoldenEye"
   | timechart span=1m count by "Source IP"
   ```

3. **Calculate packets per second:**
   ```spl
   index=cic_ids_2017 source="*Wednesday*" Label="DoS GoldenEye"
   | bin _time span=1s
   | stats count as packets_per_second by _time, "Source IP"
   | stats avg(packets_per_second) as avg_pps, max(packets_per_second) as max_pps by "Source IP"
   ```

### Exercise 6: DoS Slowloris Attack (Wednesday 11:10-11:23 AM)

**Attack Description:** Slowloris is a low-bandwidth DoS attack that keeps many connections open to the target server.

1. **Filter for Slowloris timeframe:**
   ```
   frame.time >= "2017-07-05 11:10:00" && frame.time <= "2017-07-05 11:23:00"
   ```

2. **Analyze connection patterns:**
   - Go to **Statistics → Conversations → TCP**
   - Look for many long-lived connections from the same source
   - Examine incomplete HTTP requests

**Splunk Analysis:**

```spl
index=cic_ids_2017 source="*Wednesday*" Label="DoS Slowloris"
| stats avg("Flow Duration") as avg_duration, count by "Source IP"
| where avg_duration > 10000
```

**Deliverable:**
- Comparison table of different DoS attack characteristics
- Splunk dashboard showing attack timelines
- Detection rules for each DoS type

---

## Part 5: Analyzing Web Attacks (60 minutes)

### Exercise 7: Web Attack - SQL Injection (Thursday 10:40-10:42 AM)

**Attack Description:** SQL Injection attempts to manipulate database queries through web application input fields.

1. **Open Thursday's PCAP in Wireshark:**
   ```bash
   wireshark Thursday-WorkingHours.pcap &
   ```

2. **Filter for HTTP traffic during attack:**
   ```
   http && frame.time >= "2017-07-06 10:40:00" && frame.time <= "2017-07-06 10:42:00"
   ```

3. **Examine HTTP requests:**
   - Right-click on HTTP packets → Follow → HTTP Stream
   - Look for SQL keywords in URLs or POST data:
     - `' OR '1'='1`
     - `UNION SELECT`
     - `DROP TABLE`
     - `--` (SQL comment)

4. **Extract malicious payloads:**
   - Go to **File → Export Objects → HTTP**
   - Save suspicious requests for analysis

**Splunk Analysis:**

```spl
index=cic_ids_2017 source="*Thursday*" Label="Web Attack � Sql Injection"
| stats count by "Source IP", "Destination IP"
| sort -count
```

### Exercise 8: Web Attack - XSS (Thursday 10:15-10:35 AM)

**Attack Description:** Cross-Site Scripting (XSS) attempts to inject malicious scripts into web pages.

1. **Filter for XSS timeframe:**
   ```
   http && frame.time >= "2017-07-06 10:15:00" && frame.time <= "2017-07-06 10:35:00"
   ```

2. **Look for XSS patterns:**
   - `<script>` tags in URLs or POST data
   - JavaScript event handlers (`onclick`, `onerror`, etc.)
   - Encoded payloads (`%3Cscript%3E`)

**Splunk Detection Rule:**

```spl
index=cic_ids_2017 source="*Thursday*" 
(Label="Web Attack � XSS" OR Label="Web Attack � Sql Injection" OR Label="Web Attack � Brute Force")
| stats count by Label, "Source IP"
| sort -count
```

**Deliverable:**
- List of extracted malicious payloads
- Screenshots of XSS and SQL injection attempts
- Splunk alert for web attack detection

---

## Part 6: Creating a Comprehensive Dashboard (30 minutes)

### Exercise 9: Build a Security Monitoring Dashboard

Create a comprehensive Splunk dashboard that displays:

1. **Overview Panel:**
   - Total flows analyzed
   - Benign vs. malicious traffic ratio
   - Attack type distribution

2. **Timeline Panel:**
   - Attacks over time (by day and hour)

3. **Top Attackers Panel:**
   - Source IPs with most malicious flows
   - Geographic location (if available)

4. **Attack Type Breakdown:**
   - Count of each attack type
   - Pie chart visualization

5. **Target Analysis:**
   - Most targeted destination IPs
   - Most targeted ports

**Sample Dashboard Query:**

```spl
index=cic_ids_2017
| eval attack_category=case(
    Label="BENIGN", "Benign",
    Label LIKE "%Brute Force%", "Brute Force",
    Label LIKE "%DoS%", "Denial of Service",
    Label LIKE "%DDoS%", "DDoS",
    Label LIKE "%Web Attack%", "Web Attack",
    Label="Infiltration", "Infiltration",
    Label="Bot", "Botnet",
    1=1, "Other"
)
| stats count by attack_category
```

---

## Deliverables

Submit the following:

1. **Lab Report (PDF or Markdown):**
   - Answers to all questions in each exercise
   - Screenshots of Wireshark analysis
   - Screenshots of Splunk queries and results
   - Analysis of each attack type

2. **Splunk Dashboard:**
   - Export your dashboard as XML
   - Include screenshots of the dashboard

3. **Detection Rules:**
   - Document all Splunk queries you created
   - Explain the logic behind each detection rule

4. **IOC List:**
   - Compile a list of all malicious IP addresses
   - Document attack signatures and patterns

## Evaluation Criteria

- **Completeness:** Did you complete all exercises?
- **Technical Accuracy:** Are your analyses correct?
- **Detection Rules:** Are your Splunk queries effective?
- **Documentation:** Is your report well-organized and detailed?
- **Dashboard:** Is your dashboard informative and well-designed?

## Additional Challenges (Optional)

1. **Create a machine learning model** to classify traffic as benign or malicious
2. **Write a Python script** to automatically parse the CSV files and generate statistics
3. **Compare the CIC-IDS2017 dataset** with other datasets (UNSW-NB15, CTU-13)
4. **Develop custom Wireshark filters** for each attack type

## References

- [CIC-IDS2017 Dataset Paper](https://www.unb.ca/cic/datasets/ids-2017.html)
- [CICFlowMeter Documentation](https://github.com/ahlashkari/CICFlowMeter)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)

## Next Steps

After completing this lab, you will have hands-on experience analyzing real-world network attacks. In the next module, you will learn how to use a SIEM to automate the detection of these attacks and create correlation rules to identify complex attack patterns.
