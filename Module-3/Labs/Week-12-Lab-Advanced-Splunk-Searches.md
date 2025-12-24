# Week 12 Lab: Advanced Splunk Searches

## Learning Outcomes

By the end of this lab, you will be able to:

- Use the `eval` command to create new fields and perform calculations.
- Use the `transaction` command to group related events into a single transaction.
- Use the `geostats` command to visualize data on a map.
- Apply advanced SPL commands to gain deeper insights from log data.

## Objective

To practice using advanced Splunk SPL commands to perform complex analysis on your data.

## Scenario

You are a SOC analyst and you have been tasked with creating a set of advanced Splunk searches to gain deeper insights into your data.

## Instructions

### Part 1: Use the `eval` Command

1. Write a Splunk search that uses the `eval` command to create a new field called `is_malicious` that is set to `true` if a log entry contains the word "malware" and `false` otherwise.
2. Create a table showing the `is_malicious` field and the original log entry.

### Part 2: Use the `transaction` Command

1. Write a Splunk search that uses the `transaction` command to group all of the events related to a single user session.
2. The transaction should start with a successful login event and end with a logout event.
3. Calculate the duration of each user session.

### Part 3: Use the `geostats` Command

1. Write a Splunk search that uses the `geostats` command to create a map showing the geographic location of all of the source IP addresses in your firewall logs.
2. The map should show the number of connections from each country.

## Deliverables

- Screenshots of your Splunk search results for each of the searches in this lab.
- A brief write-up explaining the results of each search.
