# Week 8: Advanced Traffic Analysis

## 8.1 Encrypted Traffic Analysis

As more and more web traffic becomes encrypted with TLS/SSL, it is becoming increasingly difficult for SOC analysts to inspect the content of network traffic. However, there are still ways to analyze encrypted traffic to detect malicious activity.

### TLS Handshake Analysis

The TLS handshake is the process by which a client and server establish a secure connection. By analyzing the TLS handshake, a SOC analyst can gain valuable information about the connection, such as:

- The version of TLS being used.
- The cipher suites being offered by the client and server.
- The certificate being used by the server.

### JA3/JA3S Hashing

JA3 and JA3S are methods for fingerprinting the TLS client and server, respectively. By creating a hash of the fields in the TLS handshake, a SOC analyst can identify specific clients and servers, even if they are using different IP addresses.

## 8.2 Command and Control (C2) Detection

Command and control (C2) is the method by which an attacker communicates with a compromised system. Detecting C2 traffic is a critical task for a SOC analyst.

### Common C2 Techniques

- **HTTP/HTTPS:** Many attackers use HTTP or HTTPS for C2 communication because it is often allowed through firewalls.
- **DNS Tunneling:** This technique involves encoding data in DNS queries and responses to exfiltrate data or communicate with a C2 server.
- **Beaconing:** This is a common C2 technique where the compromised system periodically calls back to the C2 server to check for new commands.

## 8.3 Network Forensics

Network forensics is the process of collecting, analyzing, and preserving network traffic data to investigate security incidents. It is a critical component of incident response.

### Network Forensics Tools

- **Wireshark:** A powerful tool for analyzing packet captures.
- **NetworkMiner:** A network forensic analysis tool that can extract files, images, and other artifacts from packet captures.
- **tcpdump:** A command-line tool for capturing network traffic.

## 8.4 Network Traffic Visualization

Visualizing network traffic can help a SOC analyst to quickly identify patterns and anomalies that may not be apparent from looking at raw log files. There are a variety of tools available for visualizing network traffic, such as:

- **Kibana:** The visualization component of the ELK Stack.
- **Grafana:** A popular open-source platform for monitoring and observability.
- **AfterGlow:** A script that can be used to generate link graphs of network traffic.
