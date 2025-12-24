# Week 4 Lab: Windows Log Analysis with PowerShell

## Learning Outcomes

By the end of this lab, you will be able to:

- Use the `Get-WinEvent` cmdlet to query and filter Windows Security Event Logs
- Extract specific properties from event log entries using XML parsing
- Use PowerShell pipelining to group, sort, and count event data
- Analyze logon events to identify potential brute-force attacks
- Detect lateral movement and privilege escalation attempts
- Create automated PowerShell scripts for log analysis
- Generate professional security reports from Windows Event Logs

## Objective

Master PowerShell for Windows Security Event Log analysis to detect and investigate security incidents including brute-force attacks, lateral movement, and privilege escalation.

## Scenario

You are a SOC analyst at FinanceCorp investigating suspicious activity on critical Windows servers. The security team has detected multiple failed login attempts and unusual account behavior. You need to use PowerShell to analyze Windows Security Event Logs, identify attack patterns, and determine the scope of the compromise.

## Prerequisites

- Windows 10/11 or Windows Server VM from Week 2 lab
- Administrator access
- PowerShell 5.1 or higher
- Basic understanding of Windows Event Logs
- Text editor (VS Code with PowerShell extension recommended)

## Lab Duration

Approximately 3-4 hours

---

## Part 1: Understanding Windows Security Event IDs (30 minutes)

### Step 1: Key Security Event IDs

Before analyzing logs, understand the most important security event IDs:

| Event ID | Description | Category |
|----------|-------------|----------|
| 4624 | Successful logon | Authentication |
| 4625 | Failed logon | Authentication |
| 4634 | Logon session terminated | Authentication |
| 4648 | Logon using explicit credentials | Authentication |
| 4672 | Special privileges assigned to new logon | Privilege Use |
| 4720 | User account created | Account Management |
| 4722 | User account enabled | Account Management |
| 4724 | Password reset attempt | Account Management |
| 4728 | Member added to security-enabled global group | Account Management |
| 4732 | Member added to security-enabled local group | Account Management |
| 4756 | Member added to security-enabled universal group | Account Management |
| 4768 | Kerberos TGT requested | Kerberos |
| 4769 | Kerberos service ticket requested | Kerberos |
| 4771 | Kerberos pre-authentication failed | Kerberos |
| 4776 | Domain controller attempted to validate credentials | Authentication |
| 5140 | Network share accessed | Object Access |
| 5145 | Network share object checked for access | Object Access |

### Step 2: Logon Types

Understanding logon types is crucial for analysis:

| Type | Name | Description | Common Use |
|------|------|-------------|------------|
| 2 | Interactive | Local keyboard/screen logon | Physical access |
| 3 | Network | Network connection (SMB, RPC) | File shares, remote admin |
| 4 | Batch | Scheduled task | Automation |
| 5 | Service | Service startup | Windows services |
| 7 | Unlock | Workstation unlock | User returning |
| 8 | NetworkCleartext | Network logon with cleartext password | IIS basic auth |
| 9 | NewCredentials | RunAs with different credentials | Privilege escalation |
| 10 | RemoteInteractive | RDP/Terminal Services | Remote desktop |
| 11 | CachedInteractive | Cached credentials (offline) | Laptop users |

### Step 3: Open PowerShell as Administrator

1. **On your Windows VM:**
   - Press `Win + X`
   - Select **Windows PowerShell (Admin)** or **Terminal (Admin)**

2. **Verify PowerShell version:**
   ```powershell
   $PSVersionTable.PSVersion
   ```

   Should be 5.1 or higher.

3. **Set execution policy (if needed):**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

---

## Part 2: Basic PowerShell Event Log Queries (45 minutes)

### Exercise 1: View Recent Security Events

**Command:**
```powershell
Get-WinEvent -LogName Security -MaxEvents 10
```

**Explanation:**
- `Get-WinEvent` = cmdlet to retrieve event logs
- `-LogName Security` = specify the Security log
- `-MaxEvents 10` = limit to 10 most recent events

**Output:** You'll see the 10 most recent security events.

---

### Exercise 2: Filter by Event ID

**Question:** View the last 20 successful logon events (Event ID 4624).

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 20
```

**Explanation:**
- `-FilterHashtable` = efficient filtering method
- `@{LogName='Security'; ID=4624}` = hashtable with filter criteria

**Better formatting:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 20 | 
    Select-Object TimeCreated, Id, Message | 
    Format-Table -AutoSize
```

---

### Exercise 3: Filter by Time Range

**Question:** Get all security events from the last 24 hours.

**Command:**
```powershell
$StartTime = (Get-Date).AddDays(-1)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    StartTime=$StartTime
} -MaxEvents 100
```

**Explanation:**
- `(Get-Date).AddDays(-1)` = 24 hours ago
- `StartTime=$StartTime` = filter from that time forward

**Last hour:**
```powershell
$StartTime = (Get-Date).AddHours(-1)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    StartTime=$StartTime
}
```

**Specific date range:**
```powershell
$StartTime = Get-Date "2024-01-01 00:00:00"
$EndTime = Get-Date "2024-01-02 00:00:00"
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    StartTime=$StartTime
    EndTime=$EndTime
}
```

---

### Exercise 4: Count Events

**Question:** How many failed logon attempts (Event ID 4625) occurred in the last 24 hours?

**Command:**
```powershell
$StartTime = (Get-Date).AddDays(-1)
$FailedLogons = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=$StartTime
}
$FailedLogons.Count
```

**Or using Measure-Object:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddDays(-1)
} | Measure-Object | Select-Object -ExpandProperty Count
```

---

## Part 3: Extracting Event Properties (60 minutes)

### Exercise 5: Understanding Event Structure

Windows Event Logs store data in XML format. Let's examine the structure:

**Command:**
```powershell
$Event = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 1
$Event | Format-List *
```

**Key properties:**
- `TimeCreated` - When the event occurred
- `Id` - Event ID
- `Message` - Human-readable description
- `Properties` - Array of event-specific data

**View XML:**
```powershell
$Event.ToXml()
```

### Exercise 6: Extract Data from Failed Logons

Event ID 4625 (Failed Logon) contains valuable information in the Properties array:

| Index | Field | Description |
|-------|-------|-------------|
| 0 | SubjectUserSid | SID of account that reported the failure |
| 1 | SubjectUserName | Account name that reported the failure |
| 2 | SubjectDomainName | Domain of the account |
| 5 | TargetUserName | Account that failed to log on |
| 6 | TargetDomainName | Domain of the failed account |
| 8 | LogonType | Type of logon (see table above) |
| 10 | AuthenticationPackageName | Authentication package used |
| 11 | WorkstationName | Computer name where logon was attempted |
| 13 | FailureReason | Reason for failure |
| 19 | IpAddress | Source IP address |
| 20 | IpPort | Source port |

**Extract specific fields:**
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10 | 
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TargetUser = $_.Properties[5].Value
            SourceIP = $_.Properties[19].Value
            LogonType = $_.Properties[8].Value
            FailureReason = $_.Properties[13].Value
        }
    } | Format-Table -AutoSize
```

---

### Exercise 7: Analyze Failed Logon Attempts

**Question:** What are the top 5 source IP addresses with failed logon attempts?

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddDays(-1)
} | ForEach-Object {
    $_.Properties[19].Value
} | Where-Object { $_ -ne '-' -and $_ -ne '' } | 
    Group-Object | 
    Sort-Object Count -Descending | 
    Select-Object -First 5 Name, Count
```

**Explanation:**
1. Get all Event ID 4625 from last 24 hours
2. Extract IP address (index 19)
3. Filter out empty values
4. Group by IP address
5. Sort by count (descending)
6. Take top 5

**Better formatted output:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddDays(-1)
} | ForEach-Object {
    $_.Properties[19].Value
} | Where-Object { $_ -ne '-' -and $_ -ne '' } | 
    Group-Object | 
    Sort-Object Count -Descending | 
    Select-Object -First 5 @{Name='IP Address';Expression={$_.Name}}, @{Name='Failed Attempts';Expression={$_.Count}} |
    Format-Table -AutoSize
```

---

### Exercise 8: Identify Targeted Accounts

**Question:** What are the top 5 usernames targeted in failed logon attempts?

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddDays(-1)
} | ForEach-Object {
    $_.Properties[5].Value  # TargetUserName
} | Where-Object { $_ -ne '-' -and $_ -ne '' } | 
    Group-Object | 
    Sort-Object Count -Descending | 
    Select-Object -First 5 @{Name='Username';Expression={$_.Name}}, @{Name='Failed Attempts';Expression={$_.Count}} |
    Format-Table -AutoSize
```

---

### Exercise 9: Analyze Logon Types

**Question:** What is the distribution of logon types for failed attempts?

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddDays(-1)
} | ForEach-Object {
    $LogonType = $_.Properties[8].Value
    switch ($LogonType) {
        2 { 'Interactive' }
        3 { 'Network' }
        4 { 'Batch' }
        5 { 'Service' }
        7 { 'Unlock' }
        8 { 'NetworkCleartext' }
        9 { 'NewCredentials' }
        10 { 'RemoteInteractive' }
        11 { 'CachedInteractive' }
        default { "Unknown ($LogonType)" }
    }
} | Group-Object | 
    Sort-Object Count -Descending | 
    Select-Object @{Name='Logon Type';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}} |
    Format-Table -AutoSize
```

---

## Part 4: Detecting Brute-Force Attacks (45 minutes)

### Exercise 10: Identify Brute-Force Patterns

**Scenario:** A brute-force attack typically shows:
- Multiple failed logons from the same source IP
- Failed attempts against multiple usernames
- Attempts within a short time window

**Create a brute-force detection script:**

```powershell
# Define threshold
$FailureThreshold = 5
$TimeWindow = (Get-Date).AddHours(-1)

# Get failed logons
$FailedLogons = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=$TimeWindow
} | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        SourceIP = $_.Properties[19].Value
        TargetUser = $_.Properties[5].Value
        LogonType = $_.Properties[8].Value
    }
}

# Group by source IP
$SuspiciousIPs = $FailedLogons | 
    Where-Object { $_.SourceIP -ne '-' } |
    Group-Object SourceIP | 
    Where-Object { $_.Count -ge $FailureThreshold } |
    Sort-Object Count -Descending

# Display results
Write-Host "`n=== POTENTIAL BRUTE-FORCE ATTACKS DETECTED ===" -ForegroundColor Red
Write-Host "Time Window: Last 1 hour" -ForegroundColor Yellow
Write-Host "Threshold: $FailureThreshold failed attempts`n" -ForegroundColor Yellow

foreach ($IP in $SuspiciousIPs) {
    Write-Host "Source IP: $($IP.Name)" -ForegroundColor Red
    Write-Host "Failed Attempts: $($IP.Count)" -ForegroundColor Red
    Write-Host "Targeted Accounts:" -ForegroundColor Yellow
    $IP.Group | Select-Object -ExpandProperty TargetUser -Unique | ForEach-Object {
        Write-Host "  - $_"
    }
    Write-Host ""
}
```

**Save this as:** `Detect-BruteForce.ps1`

**Run it:**
```powershell
.\Detect-BruteForce.ps1
```

---

### Exercise 11: Generate Test Failed Logons

To test your detection, generate failed logon attempts:

**Method 1: Manual (from another machine or RDP):**
1. Try to RDP to your Windows VM
2. Enter wrong password 10 times

**Method 2: Using PowerShell (simulated):**
```powershell
# This will generate Event ID 4625
1..10 | ForEach-Object {
    # Attempt to access a network share with wrong credentials
    net use \\localhost\C$ /user:FakeUser WrongPassword 2>$null
    Start-Sleep -Seconds 2
}
```

**Verify events were created:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddMinutes(-5)
} | Select-Object TimeCreated, Message | Format-List
```

---

## Part 5: Detecting Lateral Movement (45 minutes)

### Exercise 12: Detect Explicit Credential Usage

Event ID 4648 indicates someone used explicit credentials (RunAs, PsExec, etc.) - common in lateral movement.

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4648
    StartTime=(Get-Date).AddDays(-1)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        SourceUser = $xml.Event.EventData.Data[1].'#text'
        TargetUser = $xml.Event.EventData.Data[5].'#text'
        TargetServer = $xml.Event.EventData.Data[8].'#text'
        Process = $xml.Event.EventData.Data[11].'#text'
    }
} | Format-Table -AutoSize
```

---

### Exercise 13: Detect Network Share Access

Event ID 5140 shows network share access - useful for detecting lateral movement.

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=5140
    StartTime=(Get-Date).AddHours(-1)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Account = $xml.Event.EventData.Data[1].'#text'
        SourceIP = $xml.Event.EventData.Data[3].'#text'
        ShareName = $xml.Event.EventData.Data[4].'#text'
    }
} | Format-Table -AutoSize
```

---

## Part 6: Detecting Privilege Escalation (30 minutes)

### Exercise 14: Monitor Admin Group Changes

Event ID 4732 indicates a user was added to a local admin group.

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4732
    StartTime=(Get-Date).AddDays(-7)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        AddedUser = $xml.Event.EventData.Data[0].'#text'
        GroupName = $xml.Event.EventData.Data[2].'#text'
        AddedBy = $xml.Event.EventData.Data[6].'#text'
    }
} | Format-Table -AutoSize
```

---

### Exercise 15: Detect Special Privilege Assignments

Event ID 4672 shows when special privileges are assigned (often to admin accounts).

**Command:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4672
    StartTime=(Get-Date).AddHours(-1)
} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        Account = $xml.Event.EventData.Data[1].'#text'
        LogonID = $xml.Event.EventData.Data[3].'#text'
    }
} | Where-Object { $_.Account -notlike '*$' } |  # Filter out system accounts
    Format-Table -AutoSize
```

---

## Part 7: Creating Comprehensive Analysis Scripts (45 minutes)

### Exercise 16: Create a Complete Security Analysis Script

Create a comprehensive script: `Analyze-SecurityLogs.ps1`

```powershell
<#
.SYNOPSIS
    Comprehensive Windows Security Log Analysis Script
.DESCRIPTION
    Analyzes Windows Security Event Logs for suspicious activity
.PARAMETER Hours
    Number of hours to analyze (default: 24)
.EXAMPLE
    .\Analyze-SecurityLogs.ps1 -Hours 24
#>

param(
    [int]$Hours = 24
)

$StartTime = (Get-Date).AddHours(-$Hours)

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Windows Security Log Analysis Report" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Analysis Period: Last $Hours hours" -ForegroundColor Yellow
Write-Host "Start Time: $StartTime" -ForegroundColor Yellow
Write-Host "========================================`n" -ForegroundColor Cyan

# 1. Failed Logon Analysis
Write-Host "[1] FAILED LOGON ANALYSIS" -ForegroundColor Green
Write-Host "-----------------------------------" -ForegroundColor Green

$FailedLogons = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=$StartTime
} -ErrorAction SilentlyContinue

if ($FailedLogons) {
    Write-Host "Total Failed Logons: $($FailedLogons.Count)" -ForegroundColor Yellow
    
    Write-Host "`nTop 5 Source IPs:" -ForegroundColor Cyan
    $FailedLogons | ForEach-Object { $_.Properties[19].Value } | 
        Where-Object { $_ -ne '-' } | 
        Group-Object | Sort-Object Count -Descending | Select-Object -First 5 |
        Format-Table @{Name='IP Address';Expression={$_.Name}}, @{Name='Attempts';Expression={$_.Count}} -AutoSize
    
    Write-Host "Top 5 Targeted Accounts:" -ForegroundColor Cyan
    $FailedLogons | ForEach-Object { $_.Properties[5].Value } | 
        Where-Object { $_ -ne '-' } | 
        Group-Object | Sort-Object Count -Descending | Select-Object -First 5 |
        Format-Table @{Name='Username';Expression={$_.Name}}, @{Name='Attempts';Expression={$_.Count}} -AutoSize
} else {
    Write-Host "No failed logons found." -ForegroundColor Green
}

# 2. Successful Logon Analysis
Write-Host "`n[2] SUCCESSFUL LOGON ANALYSIS" -ForegroundColor Green
Write-Host "-----------------------------------" -ForegroundColor Green

$SuccessfulLogons = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4624
    StartTime=$StartTime
} -ErrorAction SilentlyContinue

if ($SuccessfulLogons) {
    Write-Host "Total Successful Logons: $($SuccessfulLogons.Count)" -ForegroundColor Yellow
    
    Write-Host "`nLogon Type Distribution:" -ForegroundColor Cyan
    $SuccessfulLogons | ForEach-Object {
        $LogonType = $_.Properties[8].Value
        switch ($LogonType) {
            2 { 'Interactive' }
            3 { 'Network' }
            10 { 'RemoteInteractive' }
            default { "Type $LogonType" }
        }
    } | Group-Object | Sort-Object Count -Descending |
        Format-Table @{Name='Logon Type';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}} -AutoSize
}

# 3. Account Management
Write-Host "`n[3] ACCOUNT MANAGEMENT EVENTS" -ForegroundColor Green
Write-Host "-----------------------------------" -ForegroundColor Green

$AccountEvents = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4720,4722,4724,4732
    StartTime=$StartTime
} -ErrorAction SilentlyContinue

if ($AccountEvents) {
    Write-Host "Account Management Events: $($AccountEvents.Count)" -ForegroundColor Yellow
    $AccountEvents | Group-Object Id | 
        Format-Table @{Name='Event ID';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}} -AutoSize
} else {
    Write-Host "No account management events found." -ForegroundColor Green
}

# 4. Privilege Escalation
Write-Host "`n[4] PRIVILEGE ESCALATION INDICATORS" -ForegroundColor Green
Write-Host "-----------------------------------" -ForegroundColor Green

$PrivEsc = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4672,4648
    StartTime=$StartTime
} -ErrorAction SilentlyContinue

if ($PrivEsc) {
    Write-Host "Privilege-Related Events: $($PrivEsc.Count)" -ForegroundColor Yellow
    $PrivEsc | Group-Object Id | 
        Format-Table @{Name='Event ID';Expression={$_.Name}}, @{Name='Count';Expression={$_.Count}} -AutoSize
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Analysis Complete" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan
```

**Run the script:**
```powershell
.\Analyze-SecurityLogs.ps1 -Hours 24
```

---

## Part 8: Exporting Results (30 minutes)

### Exercise 17: Export to CSV

**Export failed logons to CSV:**
```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddDays(-1)
} | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        SourceIP = $_.Properties[19].Value
        TargetUser = $_.Properties[5].Value
        LogonType = $_.Properties[8].Value
        FailureReason = $_.Properties[13].Value
    }
} | Export-Csv -Path "FailedLogons.csv" -NoTypeInformation

Write-Host "Exported to FailedLogons.csv"
```

---

### Exercise 18: Export to HTML Report

**Create HTML report:**
```powershell
$FailedLogons = Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4625
    StartTime=(Get-Date).AddDays(-1)
} | ForEach-Object {
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        SourceIP = $_.Properties[19].Value
        TargetUser = $_.Properties[5].Value
        LogonType = $_.Properties[8].Value
    }
}

$HTML = $FailedLogons | ConvertTo-Html -Title "Failed Logon Report" -PreContent "<h1>Failed Logon Analysis</h1><p>Generated: $(Get-Date)</p>"

$HTML | Out-File "FailedLogons.html"

Write-Host "Exported to FailedLogons.html"
```

---

## Deliverables

Submit the following:

1. **Windows-Log-Analysis-Report.md** - Your comprehensive analysis report answering all questions
2. **Detect-BruteForce.ps1** - Your brute-force detection script
3. **Analyze-SecurityLogs.ps1** - Your comprehensive analysis script
4. **FailedLogons.csv** - Exported failed logon data
5. **Screenshots/** - Directory containing:
   - PowerShell commands and outputs
   - Script execution results
   - Event Viewer showing analyzed events

## Report Template

```markdown
# Windows Security Log Analysis Report

**Analyst:** [Your Name]  
**Date:** [Analysis Date]  
**System:** [Computer Name]  
**Analysis Period:** [Time Range]

---

## Executive Summary

[2-3 sentence summary of findings]

---

## 1. Failed Logon Analysis

### Total Failed Logons
**Count:** [number]

**Command:**
```powershell
[your command]
```

### Top 5 Source IP Addresses
[paste output]

**Command:**
```powershell
[your command]
```

### Top 5 Targeted Accounts
[paste output]

### Logon Type Distribution
[paste output]

---

## 2. Brute-Force Attack Detection

### Detection Criteria
- Threshold: [number] failed attempts
- Time window: [hours]

### Suspicious IPs Identified
[list IPs and attempt counts]

---

## 3. Lateral Movement Indicators

### Explicit Credential Usage (Event ID 4648)
[findings]

### Network Share Access (Event ID 5140)
[findings]

---

## 4. Privilege Escalation Indicators

### Admin Group Changes (Event ID 4732)
[findings]

### Special Privilege Assignments (Event ID 4672)
[findings]

---

## 5. Recommendations

1. **Immediate Actions:**
   - [Action 1]
   - [Action 2]

2. **Long-term Improvements:**
   - [Improvement 1]
   - [Improvement 2]

---

## Appendix: Commands Used

```powershell
[List all PowerShell commands]
```
```

---

## Evaluation Criteria

- **Command Accuracy:** Are your PowerShell commands correct and efficient?
- **Analysis Depth:** Did you thoroughly analyze the logs?
- **Detection Capability:** Can your scripts detect real attacks?
- **Documentation:** Is your report clear and professional?
- **Script Quality:** Are your scripts well-written and reusable?

---

## Additional Challenges (Optional)

1. **Create a scheduled task** to run your analysis script daily
2. **Add email alerting** when brute-force attacks are detected
3. **Integrate with Splunk** to forward Windows events
4. **Create a dashboard** using PowerShell Universal Dashboard
5. **Detect pass-the-hash attacks** using Event ID 4624 (Logon Type 3, NTLM)

---

## Additional Resources

- [Windows Security Log Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Microsoft Security Auditing](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/)
- [SANS Windows Event Log Cheat Sheet](https://www.sans.org/posters/windows-forensic-analysis/)

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** Intermediate
