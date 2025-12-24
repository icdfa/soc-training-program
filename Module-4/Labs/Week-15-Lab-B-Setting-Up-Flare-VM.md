# Week 15 Lab B: Setting Up Flare VM for Malware Analysis

## Learning Outcomes

By the end of this lab, you will be able to:

- Install and configure Flare VM in a virtualized environment.
- Understand the purpose of a malware analysis lab.
- Identify the key tools included in the Flare VM distribution.
- Create and manage snapshots for safe malware analysis.

## 1. Objective

In this lab, you will set up Flare VM, a Windows-based security distribution designed for malware analysis, penetration testing, and reverse engineering. This will provide you with a safe, isolated environment to analyze malicious files.

## 2. Prerequisites

- A Windows 10 or 11 virtual machine (VM). You can download a free evaluation copy from the Microsoft Evaluation Center.
- At least 4GB of RAM and 60GB of disk space allocated to the VM.
- Internet access from within the VM.

## 3. Installation Steps

1.  **Create a VM Snapshot:** Before you begin, take a snapshot of your clean Windows VM. This will allow you to easily revert to a clean state after analyzing malware.
2.  **Open PowerShell as Administrator:** Open a PowerShell terminal with administrative privileges.
3.  **Set Execution Policy:** Run the following command to allow the installation script to run:
    ```powershell
    Set-ExecutionPolicy Unrestricted
    ```
4.  **Download and Run the Flare VM Installer:** Run the following command to download and execute the Flare VM installation script:
    ```powershell
    (New-Object net.webclient).DownloadFile('http://box-starter.com/bootstrapper.ps1', 'bootstrapper.ps1'); .\bootstrapper.ps1; install flare-vm
    ```
5.  **Wait for the Installation to Complete:** The installation process can take a significant amount of time (1-2 hours or more) as it downloads and installs a large number of tools. Be patient and let the script run to completion.
6.  **Reboot and Take a New Snapshot:** Once the installation is complete, reboot the VM. After rebooting, take a new snapshot of your fully configured Flare VM. This will be your starting point for malware analysis.

## 4. Deliverables

- A screenshot of your Flare VM desktop showing the installed tools.
- A list of 5 tools that were installed as part of the Flare VM package.
