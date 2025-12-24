# Week 13: Endpoint Security & EDR

## 13.1 Introduction to Endpoint Security

Endpoint security is the practice of securing endpoints, such as desktops, laptops, and mobile devices, from threats. Endpoints are a common target for attackers because they are often the weakest link in an organization's security.

### Common Endpoint Threats

- **Malware:** Malicious software, such as viruses, worms, and ransomware, that is designed to damage or disable computers.
- **Phishing:** A type of social engineering attack where an attacker attempts to trick a user into revealing sensitive information, such as usernames, passwords, and credit card details.
- **Exploits:** A piece of code that takes advantage of a vulnerability in a software application or operating system.

## 13.2 Endpoint Detection and Response (EDR)

Endpoint Detection and Response (EDR) is a type of security solution that is designed to detect and respond to threats on endpoints. EDR solutions work by continuously monitoring endpoints for suspicious activity and providing tools for investigating and remediating threats.

### Key Features of EDR

- **Real-Time Monitoring:** EDR solutions continuously monitor endpoints for suspicious activity, such as process creations, file modifications, and network connections.
- **Threat Detection:** EDR solutions use a variety of techniques to detect threats, such as signature-based detection, behavioral analysis, and machine learning.
- **Investigation and Response:** EDR solutions provide tools for investigating threats and responding to them, such as isolating a compromised endpoint from the network and remotely remediating the threat.

## 13.3 Wazuh

Wazuh is a free and open-source EDR solution. It is a powerful tool that can be used to monitor endpoints for threats, collect and analyze logs, and respond to security incidents.

### Wazuh Components

- **Wazuh Agent:** A lightweight agent that is installed on endpoints to collect data and send it to the Wazuh server.
- **Wazuh Server:** The component that analyzes the data from the agents and generates alerts.
- **Wazuh Indexer:** The component that stores and indexes the data.
- **Wazuh Dashboard:** The web interface for viewing alerts and managing the Wazuh deployment.

## 13.4 Sysmon for Endpoint Monitoring

Sysmon (System Monitor) is a free tool from Microsoft that can be used to enhance the security of Windows endpoints. It provides detailed information about process creations, network connections, and changes to the file system. Sysmon is an essential tool for any SOC analyst.

analyst.
