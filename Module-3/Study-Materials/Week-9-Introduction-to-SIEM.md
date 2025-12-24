# Week 9: Introduction to SIEM (Splunk)

## 9.1 What is a SIEM?

A Security Information and Event Management (SIEM) system is a solution that helps organizations detect, analyze, and respond to security threats before they harm business operations. SIEMs work by collecting log and event data from a variety of sources, correlating that data to identify suspicious activity, and generating alerts when potential threats are detected.

### Key Functions of a SIEM

- **Log Collection:** SIEMs can collect logs from a wide range of sources, including servers, network devices, security appliances, and applications.
- **Log Normalization:** SIEMs normalize log data into a common format, which makes it easier to search and analyze.
- **Correlation:** SIEMs use correlation rules to identify relationships between events and detect potential security threats.
- **Alerting:** SIEMs generate alerts when potential threats are detected, allowing SOC analysts to investigate and respond.
- **Reporting and Dashboards:** SIEMs provide a variety of reporting and dashboarding capabilities to help organizations visualize their security posture and track key metrics.

## 9.2 Introduction to Splunk

Splunk is one of the most popular SIEM platforms on the market. It is a powerful tool for collecting, searching, and analyzing machine-generated data.

### Splunk Components

- **Splunk Forwarder:** A lightweight agent that is installed on endpoints to collect and forward data to a Splunk indexer.
- **Splunk Indexer:** The component that processes and stores the data.
- **Splunk Search Head:** The component that provides the user interface for searching and analyzing the data.

## 9.3 Splunk Search Processing Language (SPL)

Splunk Search Processing Language (SPL) is the query language used to search and analyze data in Splunk. It is a powerful and flexible language that allows you to perform a wide range of operations on your data.

### Basic SPL Commands

- `search`: The most basic command, used to search for keywords or phrases in your data.
- `|`: The pipe character, used to chain commands together.
- `table`: Used to display the results of a search in a table.
- `stats`: Used to perform statistical calculations on your data.
- `top`: Used to find the most common values in a field.
- `rare`: Used to find the least common values in a field.

## 9.4 Data Onboarding in Splunk

Data onboarding is the process of getting data into Splunk. There are a variety of ways to onboard data into Splunk, including:

- **Using the Splunk Universal Forwarder:** The most common method for onboarding data from servers and endpoints.
- **Using the Splunk HTTP Event Collector (HEC):** A fast and efficient way to send data to Splunk from applications and scripts.
- **Using Splunk Apps and Add-ons:** There are a variety of apps and add-ons available for Splunk that make it easy to onboard data from specific sources, common sources.
