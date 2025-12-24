# Week 11: Threat Intelligence Integration

## 11.1 Introduction to Threat Intelligence

Threat intelligence is evidence-based knowledge, including context, mechanisms, indicators, implications, and actionable advice, about an existing or emerging menace or hazard to assets. It can be used to inform decisions regarding the subject's response to that menace or hazard.

### Types of Threat Intelligence

- **Strategic Threat Intelligence:** High-level information about the threat landscape, such as trends, motivations, and attack vectors.
- **Tactical Threat Intelligence:** Information about the TTPs of specific threat actors.
- **Operational Threat Intelligence:** Information about specific attacks, such as IOCs.

## 11.2 Threat Intelligence Feeds

Threat intelligence feeds are a common way to consume threat intelligence. A threat intelligence feed is a stream of data that provides information about potential threats, such as malicious IP addresses, domain names, and file hashes.

### Open-Source Threat Intelligence Feeds

There are a variety of free and open-source threat intelligence feeds available, such as:

- **Abuse.ch:** A non-profit organization that provides a variety of threat intelligence feeds, including a list of malicious IP addresses and domain names.
- **Emerging Threats:** A provider of open-source and commercial threat intelligence feeds.
- **AlienVault OTX:** An open threat intelligence community where anyone can contribute and consume threat intelligence.

## 11.3 Integrating Threat Intelligence into Splunk

Splunk can be used to integrate threat intelligence feeds and use them to enrich your data and detect potential threats.

### Using Lookup Files

Lookup files are a simple way to integrate threat intelligence into Splunk. A lookup file is a CSV file that contains a list of known malicious indicators, such as IP addresses or domain names. You can then use the `lookup` command in your Splunk searches to compare your data to the data in the lookup file.

### Using the Splunk App for Threat Intelligence

The Splunk App for Threat Intelligence is a free app that makes it easy to integrate and manage threat intelligence in Splunk. The app provides a variety of features, such as:

- A centralized repository for all of your threat intelligence.
- A dashboard for visualizing your threat intelligence.
- A set of pre-built correlation searches that use threat intelligence to detect potential threats.

## 11.4 Threat Intelligence Platforms (TIPs)

A Threat Intelligence Platform (TIP) is a solution that helps organizations manage the entire lifecycle of threat intelligence, from collection and analysis to dissemination and action. TIPs can be used to:

- Aggregate threat intelligence from a variety of sources.
- Analyze and correlate threat intelligence to identify potential threats.
- Disseminate threat intelligence to security tools and teams.
- Track the effectiveness of threat intelligence.
