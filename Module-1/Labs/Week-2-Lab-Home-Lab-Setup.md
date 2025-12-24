# Week 2 Lab: Home Lab Setup

## Objective

To build a virtual SOC home lab with a pfSense firewall, a Splunk SIEM, and target machines.

## Instructions

This lab is a hands-on project that you will be working on throughout the course. By the end of this lab, you will have a fully functional SOC home lab that you can use to practice your skills.

### Part 1: Install and Configure pfSense

1. Download the latest version of pfSense from the official website.
2. Create a new virtual machine in VirtualBox or VMware.
3. Configure the virtual machine with two network adapters:
   - **Adapter 1 (WAN):** Bridged to your physical network adapter.
   - **Adapter 2 (LAN):** Host-only network.
4. Install pfSense on the virtual machine.
5. Configure the WAN and LAN interfaces with appropriate IP addresses.

### Part 2: Install and Configure Splunk

1. Download the free version of Splunk from the official website.
2. Create a new virtual machine running Ubuntu Server.
3. Install Splunk on the virtual machine.
4. Configure Splunk to receive data on port 9997.

### Part 3: Install and Configure Target Machines

1. Create two new virtual machines:
   - One running Windows Server (evaluation version).
   - One running Ubuntu Server.
2. Install the operating systems on the virtual machines.
3. Install the Splunk Universal Forwarder on both target machines.
4. Configure the forwarders to send logs to your Splunk server.

## Deliverables

- Screenshots of your pfSense web interface, Splunk web interface, and the console of each of your target machines.
- A brief document describing the IP addressing scheme you used for your lab network.
