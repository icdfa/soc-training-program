# Week 18 Lab: CSE-CIC-IDS2018 Dataset Analysis

## Learning Outcomes

By the end of this lab, you will be able to:

- Understand the structure and contents of the CSE-CIC-IDS2018 dataset
- Analyze network traffic and system logs from a cloud environment
- Detect various attack scenarios, such as infiltration and botnet activity
- Use Splunk to analyze and visualize large-scale security datasets

## Objective

This lab will provide hands-on experience with the CSE-CIC-IDS2018 dataset, a large-scale, diverse, and labeled dataset for intrusion detection. You will learn to analyze and detect various attacks in a cloud environment.

## Dataset Overview

The **CSE-CIC-IDS2018 dataset** contains network traffic and system logs from a cloud-based infrastructure. It was created by the Canadian Institute for Cybersecurity (CIC) and includes:

- **10 days of network activity** (Wednesday to Friday over two weeks)
- **Multiple attack scenarios:** Brute Force, DoS, DDoS, Web Attacks, Infiltration, Botnet
- **80+ features** extracted from network flows
- **Labeled data** with attack types and timestamps
- **Total size:** Approximately 16GB (compressed)

**Dataset Location:** `/home/ubuntu/soc-training-program/Datasets/CSE-CIC-IDS2018/`

## Attack Timeline

| Date | Day | Attack Type | Time Window |
|------|-----|-------------|-------------|
| 14/02/2018 | Wednesday | Benign | All day |
| 15/02/2018 | Thursday | Benign | All day |
| 16/02/2018 | Friday | Benign | All day |
| 20/02/2018 | Tuesday | FTP-BruteForce | 10:00 - 11:00 |
| 20/02/2018 | Tuesday | SSH-Bruteforce | 14:00 - 15:00 |
| 21/02/2018 | Wednesday | DoS-GoldenEye | 10:00 - 11:00 |
| 21/02/2018 | Wednesday | DoS-Slowloris | 15:00 - 16:00 |
| 22/02/2018 | Thursday | DoS-SlowHTTPTest | 10:00 - 11:00 |
| 22/02/2018 | Thursday | DoS-Hulk | 15:00 - 16:00 |
| 23/02/2018 | Friday | DDoS-LOIC-HTTP | 10:00 - 11:00 |
| 23/02/2018 | Friday | DDoS-HOIC | 15:30 - 16:30 |
| 28/02/2018 | Wednesday | Infiltration | 14:00 - 17:00 |
| 01/03/2018 | Thursday | Botnet | 10:00 - 12:00 |
| 02/03/2018 | Friday | Web Attack - Brute Force | 10:00 - 11:00 |
| 02/03/2018 | Friday | Web Attack - XSS | 13:30 - 14:30 |
| 02/03/2018 | Friday | Web Attack - SQL Injection | 15:30 - 16:00 |

## Prerequisites

- Splunk instance running (from Module 3)
- At least 30GB of free disk space
- Basic understanding of cloud infrastructure
- Wireshark installed
- Python 3.x with pandas library (for data analysis)

## Lab Duration

Approximately 5-6 hours

---

## Part 1: Dataset Download and Preparation (45 minutes)

### Step 1: Download the CSE-CIC-IDS2018 Dataset

1. Navigate to the dataset directory:
   ```bash
   cd /home/ubuntu/soc-training-program/Datasets/CSE-CIC-IDS2018/
   ```

2. Read the README for download instructions:
   ```bash
   cat README.md
   ```

3. Download the dataset from the official source:
   - **Official URL:** https://www.unb.ca/cic/datasets/ids-2018.html
   - Download both **CSV files** and **PCAPs** (if available)

4. Verify the download:
   ```bash
   ls -lh
   du -sh *
   ```

### Step 2: Understand the Dataset Structure

The dataset is organized by date and attack type:

```
CSE-CIC-IDS2018/
├── Processed Traffic Data for ML Algorithms/
│   ├── Friday-02-03-2018_TrafficForML_CICFlowMeter.csv
│   ├── Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv
│   ├── Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Friday-23-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Tuesday-20-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Friday-16-02-2018_TrafficForML_CICFlowMeter.csv
│   ├── Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv
│   └── Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv
└── README.md
```

### Step 3: Examine the CSV Structure

1. View the first few lines of a CSV file:
   ```bash
   head -20 "Processed Traffic Data for ML Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv"
   ```

2. Count the number of rows:
   ```bash
   wc -l "Processed Traffic Data for ML Algorithms/"*.csv
   ```

3. Get column names:
   ```bash
   head -1 "Processed Traffic Data for ML Algorithms/Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv" | tr ',' '\n' | nl
   ```

**Key Features in the Dataset:**

- **Flow identifiers:** Dst Port, Protocol, Timestamp, Flow ID
- **Packet statistics:** Tot Fwd Pkts, Tot Bwd Pkts, TotLen Fwd Pkts, TotLen Bwd Pkts
- **Timing features:** Flow Duration, Flow IAT Mean, Flow IAT Std, Flow IAT Max, Flow IAT Min
- **Flag counts:** FIN Flag Cnt, SYN Flag Cnt, RST Flag Cnt, PSH Flag Cnt, ACK Flag Cnt
- **Packet length statistics:** Fwd Pkt Len Max, Fwd Pkt Len Min, Fwd Pkt Len Mean, Fwd Pkt Len Std
- **Label:** Attack type or "Benign"

---

## Part 2: Importing Data into Splunk (60 minutes)

### Step 4: Prepare Data for Splunk Ingestion

1. Create a new index in Splunk for the CSE-CIC-IDS2018 dataset:
   - Log in to Splunk
   - Go to **Settings → Indexes → New Index**
   - Index name: `cse_cic_ids_2018`
   - Max size: 50GB
   - Click **Save**

2. **Optional:** Combine all CSV files into one (for easier ingestion):
   ```bash
   cd "Processed Traffic Data for ML Algorithms/"
   
   # Extract header from first file
   head -1 Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv > combined_dataset.csv
   
   # Append all data (skip headers)
   for file in *.csv; do
       tail -n +2 "$file" >> combined_dataset.csv
   done
   
   # Check the combined file
   wc -l combined_dataset.csv
   ```

### Step 5: Upload Data to Splunk

**Method 1: Web UI Upload (for smaller files)**

1. Go to **Settings → Add Data → Upload**
2. Select the CSV file
3. **Set Source Type:**
   - Source type: `csv`
   - Delimiter: `,` (comma)
   - Header: Check "Extract field names"
4. **Input Settings:**
   - Index: `cse_cic_ids_2018`
   - Source type: `cse_cic_ids_2018_csv`
5. Click **Submit**

**Method 2: Splunk Forwarder (for large files)**

1. Copy the CSV files to the Splunk monitored directory:
   ```bash
   sudo cp *.csv /opt/splunk/var/spool/splunk/
   ```

2. Configure inputs.conf:
   ```bash
   sudo nano /opt/splunk/etc/system/local/inputs.conf
   ```

3. Add the following:
   ```ini
   [monitor:///opt/splunk/var/spool/splunk/*.csv]
   disabled = false
   index = cse_cic_ids_2018
   sourcetype = csv
   ```

4. Restart Splunk:
   ```bash
   sudo /opt/splunk/bin/splunk restart
   ```

### Step 6: Verify Data Ingestion

1. Search for the ingested data:
   ```spl
   index=cse_cic_ids_2018
   | stats count
   ```

2. Check the time range:
   ```spl
   index=cse_cic_ids_2018
   | stats min(_time) as earliest, max(_time) as latest
   | eval earliest=strftime(earliest, "%Y-%m-%d %H:%M:%S"), latest=strftime(latest, "%Y-%m-%d %H:%M:%S")
   ```

3. Verify labels:
   ```spl
   index=cse_cic_ids_2018
   | stats count by Label
   | sort -count
   ```

---

## Part 3: Analyzing Infiltration Attack (90 minutes)

### Exercise 1: Understanding the Infiltration Scenario

**Attack Description:** The infiltration attack simulates an Advanced Persistent Threat (APT) scenario where an attacker:
1. Gains initial access through a vulnerability
2. Establishes persistence
3. Performs reconnaissance
4. Moves laterally within the network
5. Exfiltrates data

**Date:** Wednesday, 28/02/2018, 14:00 - 17:00

### Step 7: Filter Infiltration Traffic in Splunk

1. **Basic infiltration query:**
   ```spl
   index=cse_cic_ids_2018 Label="Infiltration"
   | table _time, "Src IP", "Dst IP", "Src Port", "Dst Port", Protocol, "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts"
   ```

2. **Identify the attacker's IP:**
   ```spl
   index=cse_cic_ids_2018 Label="Infiltration"
   | stats count by "Src IP"
   | sort -count
   ```

3. **Identify targeted systems:**
   ```spl
   index=cse_cic_ids_2018 Label="Infiltration"
   | stats count by "Dst IP"
   | sort -count
   ```

4. **Analyze the timeline:**
   ```spl
   index=cse_cic_ids_2018 Label="Infiltration"
   | timechart span=5m count by "Src IP"
   ```

### Step 8: Identify Initial Compromise

1. **Find the first infiltration event:**
   ```spl
   index=cse_cic_ids_2018 Label="Infiltration"
   | sort _time
   | head 10
   | table _time, "Src IP", "Dst IP", "Dst Port", Protocol
   ```

2. **Analyze port usage:**
   ```spl
   index=cse_cic_ids_2018 Label="Infiltration"
   | stats count by "Dst Port"
   | sort -count
   ```

**Questions to Answer:**

1. What is the attacker's IP address?
2. What was the first port targeted?
3. What protocol was used for initial access?
4. How long did the infiltration last?

### Step 9: Detect Lateral Movement

1. **Identify connections between internal hosts:**
   ```spl
   index=cse_cic_ids_2018 Label="Infiltration"
   | where match("Src IP", "^192\.168\.") AND match("Dst IP", "^192\.168\.")
   | stats count by "Src IP", "Dst IP"
   | sort -count
   ```

2. **Visualize lateral movement:**
   ```spl
   index=cse_cic_ids_2018 Label="Infiltration"
   | stats count by "Src IP", "Dst IP"
   | where count > 10
   | eval connection="Src IP" + " -> " + "Dst IP"
   | table connection, count
   ```

3. **Create a network diagram:**
   - Use the Splunk Force Directed app (if available)
   - Or export data and visualize with Gephi/Cytoscape

### Step 10: Detect Data Exfiltration

1. **Find large data transfers:**
   ```spl
   index=cse_cic_ids_2018 Label="Infiltration"
   | eval total_bytes="TotLen Fwd Pkts" + "TotLen Bwd Pkts"
   | where total_bytes > 1000000
   | table _time, "Src IP", "Dst IP", total_bytes
   | sort -total_bytes
   ```

2. **Identify outbound connections:**
   ```spl
   index=cse_cic_ids_2018 Label="Infiltration"
   | where NOT match("Dst IP", "^192\.168\.")
   | stats sum("TotLen Fwd Pkts") as bytes_sent by "Src IP", "Dst IP"
   | sort -bytes_sent
   ```

**Deliverable:** Create a timeline of the infiltration attack with key events:
- Initial compromise
- Reconnaissance activities
- Lateral movement
- Data exfiltration

---

## Part 4: Analyzing Botnet Activity (90 minutes)

### Exercise 2: Detecting Botnet C2 Communication

**Attack Description:** The botnet scenario includes infected hosts communicating with a Command and Control (C2) server.

**Date:** Thursday, 01/03/2018, 10:00 - 12:00

### Step 11: Identify Botnet Traffic Patterns

1. **Filter botnet traffic:**
   ```spl
   index=cse_cic_ids_2018 Label="Bot"
   | table _time, "Src IP", "Dst IP", "Dst Port", Protocol, "Flow Duration", "Flow IAT Mean"
   ```

2. **Identify potential C2 servers:**
   ```spl
   index=cse_cic_ids_2018 Label="Bot"
   | stats count, dc("Src IP") as unique_sources by "Dst IP"
   | where unique_sources > 5
   | sort -count
   ```

3. **Analyze beaconing behavior:**
   ```spl
   index=cse_cic_ids_2018 Label="Bot"
   | stats avg("Flow IAT Mean") as avg_interval, stdev("Flow IAT Mean") as stdev_interval by "Src IP", "Dst IP"
   | where stdev_interval < 1000
   | sort avg_interval
   ```

**Beaconing Characteristics:**
- Regular, periodic connections
- Low standard deviation in connection intervals
- Small packet sizes
- Long-lived connections

### Step 12: Analyze Botnet Communication Patterns

1. **Packet size analysis:**
   ```spl
   index=cse_cic_ids_2018 Label="Bot"
   | stats avg("Fwd Pkt Len Mean") as avg_fwd_size, avg("Bwd Pkt Len Mean") as avg_bwd_size by "Src IP"
   | eval size_ratio=avg_fwd_size/avg_bwd_size
   | table "Src IP", avg_fwd_size, avg_bwd_size, size_ratio
   ```

2. **Connection duration analysis:**
   ```spl
   index=cse_cic_ids_2018 Label="Bot"
   | stats avg("Flow Duration") as avg_duration, max("Flow Duration") as max_duration by "Src IP"
   | sort -avg_duration
   ```

3. **Protocol analysis:**
   ```spl
   index=cse_cic_ids_2018 Label="Bot"
   | stats count by Protocol, "Dst Port"
   | sort -count
   ```

### Step 13: Create a Botnet Detection Dashboard

Create a Splunk dashboard with the following panels:

1. **Botnet Activity Timeline:**
   ```spl
   index=cse_cic_ids_2018 Label="Bot"
   | timechart span=10m count
   ```

2. **Top Infected Hosts:**
   ```spl
   index=cse_cic_ids_2018 Label="Bot"
   | stats count by "Src IP"
   | sort -count
   | head 10
   ```

3. **C2 Servers:**
   ```spl
   index=cse_cic_ids_2018 Label="Bot"
   | stats count, dc("Src IP") as infected_hosts by "Dst IP"
   | sort -infected_hosts
   ```

4. **Beaconing Visualization:**
   ```spl
   index=cse_cic_ids_2018 Label="Bot"
   | timechart span=1m count by "Src IP" limit=5
   ```

**Deliverable:** Screenshot of your botnet detection dashboard

---

## Part 5: Comparative Analysis of Attack Types (60 minutes)

### Exercise 3: Compare Multiple Attack Scenarios

1. **Create a comparison query:**
   ```spl
   index=cse_cic_ids_2018
   | eval attack_category=case(
       Label="Benign", "Benign",
       Label LIKE "%Brute%", "Brute Force",
       Label LIKE "%DoS%", "Denial of Service",
       Label LIKE "%DDoS%", "DDoS",
       Label LIKE "%Web Attack%", "Web Attack",
       Label="Infiltration", "Infiltration",
       Label="Bot", "Botnet",
       1=1, "Other"
   )
   | stats count, avg("Flow Duration") as avg_duration, avg("Tot Fwd Pkts") as avg_fwd_pkts, avg("Tot Bwd Pkts") as avg_bwd_pkts by attack_category
   | sort -count
   ```

2. **Analyze packet characteristics by attack type:**
   ```spl
   index=cse_cic_ids_2018
   | stats avg("Fwd Pkt Len Mean") as avg_fwd_len, avg("Bwd Pkt Len Mean") as avg_bwd_len, avg("Flow IAT Mean") as avg_iat by Label
   | sort Label
   ```

3. **Create a feature comparison table:**
   ```spl
   index=cse_cic_ids_2018
   | stats 
       avg("Flow Duration") as avg_duration,
       avg("Tot Fwd Pkts") as avg_fwd_pkts,
       avg("Tot Bwd Pkts") as avg_bwd_pkts,
       avg("Flow Byts/s") as avg_bytes_per_sec,
       avg("Flow Pkts/s") as avg_pkts_per_sec
       by Label
   | sort Label
   ```

### Exercise 4: Build a Machine Learning Model (Optional)

If you have Python with scikit-learn installed:

1. **Export data from Splunk:**
   ```spl
   index=cse_cic_ids_2018
   | fields "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "Flow Byts/s", "Flow Pkts/s", Label
   | outputlookup cse_cic_ids_2018_ml_data.csv
   ```

2. **Train a simple classifier:**
   ```python
   import pandas as pd
   from sklearn.model_selection import train_test_split
   from sklearn.ensemble import RandomForestClassifier
   from sklearn.metrics import classification_report, confusion_matrix
   
   # Load data
   data = pd.read_csv("cse_cic_ids_2018_ml_data.csv")
   
   # Prepare features and labels
   X = data.drop("Label", axis=1)
   y = data["Label"]
   
   # Split data
   X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
   
   # Train model
   clf = RandomForestClassifier(n_estimators=100, random_state=42)
   clf.fit(X_train, y_train)
   
   # Evaluate
   y_pred = clf.predict(X_test)
   print(classification_report(y_test, y_pred))
   print(confusion_matrix(y_test, y_pred))
   ```

---

## Part 6: Creating Detection Rules (45 minutes)

### Step 14: Develop Splunk Alerts

1. **Infiltration Detection Alert:**
   ```spl
   index=cse_cic_ids_2018
   | where match("Src IP", "^192\.168\.") AND NOT match("Dst IP", "^192\.168\.")
   | stats sum("TotLen Fwd Pkts") as bytes_sent by "Src IP"
   | where bytes_sent > 10000000
   | eval alert_type="Potential Data Exfiltration"
   ```
   - Save as alert: "Potential Data Exfiltration"
   - Trigger: When results > 0
   - Schedule: Every 5 minutes

2. **Botnet Beaconing Detection Alert:**
   ```spl
   index=cse_cic_ids_2018
   | stats count, avg("Flow IAT Mean") as avg_interval, stdev("Flow IAT Mean") as stdev_interval by "Src IP", "Dst IP"
   | where count > 20 AND stdev_interval < 1000
   | eval alert_type="Potential Botnet Beaconing"
   ```
   - Save as alert: "Botnet Beaconing Detected"
   - Trigger: When results > 0
   - Schedule: Every 10 minutes

3. **Brute Force Detection Alert:**
   ```spl
   index=cse_cic_ids_2018 "Dst Port" IN (21, 22, 3389)
   | stats count by "Src IP", "Dst IP", "Dst Port"
   | where count > 50
   | eval alert_type="Brute Force Attack"
   ```
   - Save as alert: "Brute Force Attack Detected"
   - Trigger: When results > 0
   - Schedule: Every 5 minutes

---

## Deliverables

Submit the following:

1. **Lab Report (Markdown or PDF):**
   - Analysis of infiltration attack with timeline
   - Analysis of botnet activity with C2 identification
   - Comparison of attack types
   - Answers to all questions

2. **Splunk Dashboards:**
   - Infiltration attack dashboard
   - Botnet detection dashboard
   - Overall security monitoring dashboard
   - Export as XML or screenshots

3. **Detection Rules:**
   - All Splunk queries and alerts
   - Explanation of detection logic

4. **IOC List:**
   - Malicious IP addresses
   - C2 servers
   - Attack signatures

5. **Optional: ML Model Results:**
   - Classification report
   - Confusion matrix
   - Feature importance analysis

## Evaluation Criteria

- **Completeness:** Did you complete all exercises?
- **Technical Accuracy:** Are your analyses correct?
- **Detection Rules:** Are your Splunk queries effective?
- **Documentation:** Is your report well-organized?
- **Dashboards:** Are your dashboards informative?
- **Insights:** Did you provide meaningful insights?

## Additional Resources

- [CSE-CIC-IDS2018 Dataset Paper](https://www.unb.ca/cic/datasets/ids-2018.html)
- [Splunk Machine Learning Toolkit](https://docs.splunk.com/Documentation/MLApp/latest/User/WelcometotheMLTK)
- [MITRE ATT&CK: Infiltration](https://attack.mitre.org/tactics/TA0010/)
- [MITRE ATT&CK: Command and Control](https://attack.mitre.org/tactics/TA0011/)

## Next Steps

After completing this lab, you will have experience analyzing sophisticated attacks in a cloud environment. In the next module, you will learn about threat hunting and proactive security monitoring techniques.
