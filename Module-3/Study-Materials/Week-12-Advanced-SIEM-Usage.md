# Week 12: Advanced SIEM Usage

## 12.1 Advanced SPL Commands

Splunk Search Processing Language (SPL) has a rich set of commands that can be used to perform complex analysis on your data.

### `eval`

The `eval` command is used to create new fields or modify existing fields. It is a powerful command that can be used to perform a wide range of operations, such as:

- Performing mathematical calculations.
- Concatenating strings.
- Using conditional statements.

### `transaction`

The `transaction` command is used to group related events into a single transaction. This is useful for analyzing events that span multiple log entries, such as a user session or a multi-stage attack.

### `geostats`

The `geostats` command is used to generate statistics about the geographic location of IP addresses. This can be used to create maps that show the location of your users or the source of attacks.

## 12.2 Data Models and the CIM

Splunk data models are a way to create a structured representation of your data. They can be used to simplify your searches and make it easier to create reports and dashboards.

The Common Information Model (CIM) is a standard data model for security data in Splunk. It provides a set of pre-defined fields and tags that can be used to normalize your data and make it compatible with other Splunk apps and add-ons.

## 12.3 Splunk Enterprise Security (ES)

Splunk Enterprise Security (ES) is a premium Splunk app that provides a comprehensive set of security monitoring and analysis capabilities. It includes a variety of features, such as:

- A pre-built set of correlation searches and dashboards.
- A framework for managing and investigating security incidents.
- A variety of tools for threat intelligence and risk analysis.

## 12.4 User Behavior Analytics (UBA)

User Behavior Analytics (UBA) is a type of security analytics that focuses on detecting threats by identifying anomalous user behavior. UBA solutions can be used to detect a variety of threats, such as insider threats, compromised accounts, and data exfiltration.

Splunk User Behavior Analytics (UBA) is a premium Splunk app that provides UBA capabilities. It uses machine learning to baseline normal user behavior and detect anomalies that may be indicative of a threat.
