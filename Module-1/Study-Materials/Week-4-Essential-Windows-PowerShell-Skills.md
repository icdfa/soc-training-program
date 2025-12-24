# Week 4: Essential Windows & PowerShell Skills

## 4.1 Introduction to Windows Security

Windows is the most widely used desktop operating system in the world, making it a prime target for attackers. As a SOC analyst, it is crucial to have a deep understanding of Windows security features and how to analyze Windows logs.

### Windows Event Logs

Windows Event Logs are the primary source of information for security monitoring on Windows systems. The most important event logs for a SOC analyst are:

- **Security Log:** Contains events related to security, such as login attempts, file access, and policy changes.
- **System Log:** Contains events related to the operating system, such as driver failures and system startup/shutdown.
- **Application Log:** Contains events logged by applications.

### Sysmon

Sysmon (System Monitor) is a free tool from Microsoft that provides detailed information about process creations, network connections, and changes to the file system. It is an essential tool for a SOC analyst to have on all Windows endpoints.

## 4.2 Introduction to PowerShell

PowerShell is a powerful command-line shell and scripting language from Microsoft. It is built on the .NET Framework and provides a rich set of commands (called cmdlets) for managing Windows systems.

### Basic PowerShell Commands

- `Get-Help`: Get help on any PowerShell cmdlet.
- `Get-Process`: Get a list of running processes.
- `Get-Service`: Get a list of services.
- `Get-EventLog`: Get events from an event log.
- `Get-Content`: Get the content of a file.

## 4.3 PowerShell for Security

PowerShell is an invaluable tool for a SOC analyst to automate security tasks, such as:

- **Log Analysis:** PowerShell can be used to parse and analyze Windows Event Logs and other log files.
- **Incident Response:** PowerShell can be used to collect forensic data from a compromised system, such as running processes, network connections, and registry keys.
- **System Hardening:** PowerShell can be used to automate the process of hardening Windows systems by disabling unnecessary services, configuring security policies, and more.

## 4.4 PowerShell Remoting

PowerShell Remoting allows you to run PowerShell commands on remote computers. This is a powerful feature that can be used to manage and collect data from multiple systems at once.

**Enabling PowerShell Remoting:**

```powershell
Enable-PSRemoting -Force
```

**Running a Command on a Remote Computer:**

```powershell
Invoke-Command -ComputerName <ComputerName> -ScriptBlock { Get-Process }
```
