# Week 2: Building Your SOC Home Lab

## 2.1 Introduction to Virtualization

Virtualization is the process of creating a virtual version of something, such as a server, desktop, storage device, operating system, or network. It is the fundamental technology that allows us to create a SOC home lab without the need for multiple physical computers.

We will be using a Type 2 hypervisor, which runs on top of a host operating system. The two most popular choices are:

- **VirtualBox:** A free and open-source hypervisor from Oracle.
- **VMware Workstation Player / Fusion:** A free-for-personal-use hypervisor from VMware.

## 2.2 Home Lab Architecture

Our home lab will consist of the following components:

- **pfSense Firewall:** A free and open-source firewall and router that will be used to segment our lab network.
- **SIEM Server:** A virtual machine running a SIEM platform, such as Splunk or the ELK Stack, to collect and analyze logs.
- **Target Machines:** Virtual machines running Windows and Linux that will be the targets of our simulated attacks.
- **Attacker Machine:** A virtual machine running Kali Linux, which will be used to launch attacks against our target machines.

## 2.3 Installing and Configuring pfSense

pfSense is a powerful firewall that will act as the gateway for our lab network. It will allow us to control the flow of traffic between our lab and the internet, as well as between the different segments of our lab network.

**Installation Steps:**

1. Download the latest version of pfSense from the official website.
2. Create a new virtual machine in VirtualBox or VMware.
3. Configure the virtual machine with at least two network adapters: one for the WAN interface (connected to your home network) and one for the LAN interface (for your lab network).
4. Install pfSense by booting the virtual machine from the downloaded ISO file.
5. Configure the WAN and LAN interfaces with the appropriate IP addresses.

## 2.4 Installing and Configuring the SIEM

We will be using Splunk as our SIEM platform. Splunk is a powerful tool for collecting, searching, and analyzing machine-generated data.

**Installation Steps:**

1. Download the free version of Splunk from the official website.
2. Create a new virtual machine running a Linux distribution, such as Ubuntu Server.
3. Install Splunk on the virtual machine by following the official documentation.
4. Configure Splunk to receive data from our target machines by installing the Splunk Universal Forwarder on them.

## 2.5 Installing and Configuring Target Machines

We will be using a combination of Windows and Linux virtual machines as our targets.

- **Windows:** We will use a Windows Server evaluation version, which is available for free from the Microsoft Evaluation Center.
- **Linux:** We will use a lightweight Linux distribution, such as Ubuntu Server or CentOS.

**Installation Steps:**

1. Download the ISO files for the desired operating systems.
2. Create new virtual machines for each target.
3. Install the operating systems on the virtual machines.
4. Install the Splunk Universal Forwarder on each target machine to forward logs to our Splunk server.
