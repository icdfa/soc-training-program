# Week 6: Network Security Monitoring (NSM) Tools

## 6.1 Introduction to Network Security Monitoring

Network Security Monitoring (NSM) is the collection, analysis, and response to network traffic data to detect and respond to security incidents. It is a proactive approach to security that focuses on identifying threats before they can cause damage.

### The NSM Cycle

The NSM cycle consists of three phases:

1. **Collection:** Collecting network traffic data from various sources, such as network taps, SPAN ports, and network devices.
2. **Detection:** Analyzing the collected data to identify potential security threats.
3. **Analysis:** Investigating the detected threats to determine their nature and scope.

## 6.2 Security Onion

Security Onion is a free and open-source Linux distribution for intrusion detection, enterprise security monitoring, and log management. It is a powerful tool that combines a variety of open-source security tools into a single platform.

### Key Features of Security Onion

- **Full Packet Capture:** Security Onion can capture and store all network traffic, allowing you to go back in time and analyze past events.
- **Intrusion Detection:** Security Onion includes the Snort and Suricata intrusion detection systems, which can detect a wide range of attacks.
- **Log Management:** Security Onion uses the ELK Stack (Elasticsearch, Logstash, and Kibana) to collect, store, and analyze logs from a variety of sources.
- **Network Security Monitoring:** Security Onion includes a variety of NSM tools, such as Zeek (formerly Bro), which can provide detailed information about network traffic.

## 6.3 Zeek (formerly Bro)

Zeek is a powerful network analysis framework that is much different from the typical IDS you may know. It is a passive, open-source network traffic analyzer that can be used to detect a wide range of malicious activity.

### How Zeek Works

Zeek works by parsing network traffic and generating a series of log files that provide detailed information about the traffic. These log files can then be analyzed to identify potential security threats.

### Zeek Log Files

Zeek generates a variety of log files, including:

- `conn.log`: A log of all network connections.
- `http.log`: A log of all HTTP traffic.
- `dns.log`: A log of all DNS traffic.
- `files.log`: A log of all files transferred over the network.

## 6.4 Suricata

Suricata is a free and open-source intrusion detection system (IDS) and intrusion prevention system (IPS). It is a powerful tool that can be used to detect a wide range of attacks.

### How Suricata Works

Suricata works by inspecting network traffic and comparing it to a set of rules. If the traffic matches a rule, Suricata will generate an alert.

### Suricata Rules

Suricata uses a flexible and powerful rule language that allows you to create custom rules to detect specific threats. There are also a variety of free and commercial rule sets available for Suricata.
