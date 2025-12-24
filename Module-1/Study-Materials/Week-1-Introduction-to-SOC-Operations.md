# Week 1: Introduction to SOC Operations

## 1.1 What is a Security Operations Center (SOC)?

A Security Operations Center (SOC) is a centralized unit that deals with security issues on an organizational and technical level. It comprises the three building blocks of people, processes, and technology for managing and enhancing an organization’s security posture. The primary goal of a SOC is to detect, analyze, and respond to cybersecurity incidents using a combination of technology solutions and a strong set of processes.

### SOC Models

There are several models for deploying a SOC, each with its own advantages and disadvantages:

- **Internal SOC:** A dedicated, in-house team of security professionals. This model provides the most control and customization but is also the most expensive to build and maintain.
- **Managed SOC (SOC-as-a-Service):** An outsourced team of security experts that provides SOC services. This model is more cost-effective and provides access to a wider range of expertise.
- **Hybrid SOC:** A combination of an internal team and a managed service. This model allows organizations to retain control over critical functions while outsourcing others.

## 1.2 SOC Roles and Responsibilities

A typical SOC team is structured in tiers, with each tier having specific responsibilities:

- **Tier 1 (Triage Specialist):** The first line of defense. Tier 1 analysts are responsible for monitoring alerts, collecting data, and escalating incidents to Tier 2.
- **Tier 2 (Incident Responder):** In-depth investigation of incidents escalated by Tier 1. Tier 2 analysts use threat intelligence to understand the scope of an attack and develop a response plan.
- **Tier 3 (Threat Hunter):** Proactive threat hunting and advanced incident response. Tier 3 analysts are the most experienced members of the team and are responsible for identifying unknown threats and vulnerabilities.
- **SOC Manager:** Oversees the entire SOC team, manages resources, and reports to senior management.

## 1.3 The Threat Landscape

The threat landscape is constantly evolving, with new threats emerging every day. It is crucial for SOC analysts to stay up-to-date on the latest threats and attack techniques. Some of the most common threats include:

- **Malware:** Malicious software designed to disrupt operations, steal data, or gain unauthorized access to systems.
- **Phishing:** Social engineering attacks that use deceptive emails and websites to steal sensitive information.
- **Ransomware:** A type of malware that encrypts files and demands a ransom for their release.
- **Denial-of-Service (DoS) Attacks:** Attacks that flood a system with traffic, making it unavailable to legitimate users.
- **Advanced Persistent Threats (APTs):** Sophisticated, long-term attacks that are often sponsored by nation-states.

## 1.4 The Cyber Kill Chain

The Cyber Kill Chain is a framework developed by Lockheed Martin that outlines the stages of a cyber attack. Understanding the Cyber Kill Chain can help SOC analysts to detect and respond to attacks at each stage.

1. **Reconnaissance:** The attacker gathers information about the target.
2. **Weaponization:** The attacker creates a malicious payload, such as a virus or worm.
3. **Delivery:** The attacker transmits the weapon to the target, for example, via an email attachment.
4. **Exploitation:** The attacker exploits a vulnerability to execute code on the target’s system.
5. **Installation:** The attacker installs malware on the target’s system.
6. **Command and Control (C2):** The attacker establishes a command and control channel to communicate with the compromised system.
7. **Actions on Objectives:** The attacker takes action to achieve their goals, such as data exfiltration or destruction.

## 1.5 The MITRE ATT&CK Framework

The MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) framework is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations. It is a valuable resource for SOC analysts to understand and defend against cyber attacks.

ATT&CK is organized into tactics, which represent the “why” of an attack, and techniques, which represent the “how” an attacker achieves their goals. By mapping security alerts to the ATT&CK framework, SOC analysts can gain a better understanding of the attacker’s objectives and techniques.
