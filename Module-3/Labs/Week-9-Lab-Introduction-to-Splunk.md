# Week 9 Lab: Introduction to Splunk

## Objective

To gain hands-on experience with Splunk by installing it in your lab, onboarding data, and running basic searches.

## Scenario

You are a new SOC analyst and you have been tasked with setting up a Splunk instance in your lab to start collecting and analyzing logs from your target machines.

## Instructions

### Part 1: Install Splunk

1. If you haven't already, download the free version of Splunk from the official website.
2. Install Splunk on your dedicated SIEM virtual machine (Ubuntu Server).
3. Access the Splunk web interface and complete the initial setup.

### Part 2: Onboard Data

1. On your Splunk server, configure a new receiving port (e.g., 9997) to receive data from your forwarders.
2. Install the Splunk Universal Forwarder on your Windows and Linux target machines.
3. Configure the forwarders to send data to your Splunk server.
4. Verify that data is being received in Splunk by searching for events from your target machines.

### Part 3: Basic Searches

1. Use the Splunk search interface to run the following searches:
   - Find all events from your Windows target machine.
   - Find all events from your Linux target machine.
   - Find all failed login attempts on your Windows machine (Event ID 4625).
   - Find all successful sudo commands on your Linux machine.
   - Create a simple table showing the source IP addresses of all SSH connections to your Linux machine.

## Deliverables

- Screenshots of your Splunk search results for each of the searches in Part 3.
- A brief write-up explaining the results of each search.
