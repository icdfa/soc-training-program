# Lab Expansion Template and Guidelines

## Purpose

This document provides a comprehensive template and guidelines for expanding the remaining labs in the Certified SOC Analyst (CSA) program to match the quality and depth of the completed labs.

## Completed Labs (Reference Examples)

The following 15 labs have been fully expanded and serve as templates:

**Module 1 (Foundations):**
- Week 1: Threat Intelligence Research (853 lines) - OpenCTI + AlienVault OTX
- Week 2: Home Lab Setup (600+ lines) - Complete VM environment
- Week 3: CLI Log Analysis (550+ lines) - grep, awk, sed mastery
- Week 4: PowerShell Log Analysis (700+ lines) - Windows event analysis

**Module 2 (Network Traffic Analysis):**
- Week 5: Wireshark Packet Analysis (740 lines) - Deep packet inspection
- Week 6: Security Onion (727 lines) - NSM platform deployment
- Week 7: Firewall Log Analysis (786 lines) - Advanced log parsing
- Week 8-B: CIC-IDS2017 Dataset (607 lines) - Dataset integration
- Week 8-C2: C2 Traffic Detection (900+ lines) - Advanced threat detection

**Module 3 (SIEM):**
- Week 9: Splunk Introduction (738 lines) - Complete SIEM deployment

**Module 4 (Incident Response):**
- Week 13: Wazuh HIDS/EDR (786 lines) - Endpoint security
- Week 14: Volatility Memory Forensics (752 lines) - Advanced forensics
- Week 15-C: Static Malware Analysis (596 lines) - Malware reverse engineering

**Module 5 (Cloud):**
- Week 18: CSE-CIC-IDS2018 Dataset (607 lines) - Advanced dataset analysis

**Module 6 (Threat Hunting):**
- Week 21: Threat Hunting (811 lines) - Hypothesis-driven hunting

---

## Lab Structure Template

Every expanded lab should follow this structure:

### 1. Header Section (100-150 lines)

```markdown
# Week X Lab: [Lab Title]

## Learning Outcomes

By the end of this lab, you will be able to:

- [Specific, measurable outcome 1]
- [Specific, measurable outcome 2]
- [Specific, measurable outcome 3]
- [Specific, measurable outcome 4]
- [Specific, measurable outcome 5]
- [Specific, measurable outcome 6]
- [Specific, measurable outcome 7]

## Objective

[2-3 sentences describing the overall goal and what students will accomplish]

## Scenario

[Detailed, realistic scenario that places the student in a professional role with specific tasks and context. Should be 2-3 paragraphs.]

## Prerequisites

- [Required software/tools]
- [Required knowledge]
- [System requirements]
- [Previous labs completed]

## Lab Duration

Approximately X-Y hours
```

### 2. Part 1: Understanding [Topic] (30-45 minutes, 100-150 lines)

```markdown
## Part 1: Understanding [Topic]

### Step 1: What is [Topic]?

[Comprehensive explanation with definitions, key concepts, and context]

**Key Concepts:**

| Term | Definition |
|------|------------|
| [Term 1] | [Definition] |
| [Term 2] | [Definition] |

**Architecture/Workflow Diagram:**
```
[ASCII diagram showing how components interact]
```

### Step 2: [Key Concept 2]

[Detailed explanation]

### Step 3: [Key Concept 3]

[Detailed explanation with examples]
```

### 3. Part 2: Installation/Setup (60-90 minutes, 150-200 lines)

```markdown
## Part 2: Installing/Configuring [Tool/System]

### Step 4: Download and Prepare

**System Requirements:**
- [Requirement 1]
- [Requirement 2]

**Download:**
```bash
# Detailed commands with explanations
wget [URL]
```

### Step 5: Installation

**Step-by-step installation:**
```bash
# Command 1 with explanation
sudo apt install [package]

# Command 2 with explanation
sudo systemctl start [service]
```

**Verify installation:**
```bash
# Verification commands
[command] --version
```

### Step 6: Initial Configuration

[Detailed configuration steps with code blocks]
```

### 4. Part 3-5: Core Exercises (60-90 minutes each, 200-300 lines each)

```markdown
## Part 3: [Core Topic 1]

### Exercise 1: [Specific Task]

**Objective:** [What students will accomplish]

**Steps:**
1. [Detailed step 1]
2. [Detailed step 2]
3. [Detailed step 3]

**Commands:**
```bash
# Command with explanation
[command]
```

**Expected Output:**
```
[Show what students should see]
```

**Analysis:**
[Explain what the output means and what to look for]

### Exercise 2: [Specific Task]

[Same structure as Exercise 1]

### Exercise 3: [Specific Task]

[Same structure as Exercise 1]
```

### 5. Deliverables Section (50-100 lines)

```markdown
## Deliverables

Submit the following:

1. **[Main-Report].md** - Comprehensive analysis report
2. **Screenshots/** - Directory containing:
   - [Screenshot 1 description]
   - [Screenshot 2 description]
   - [Screenshot 3 description]
3. **[Artifacts]/** - Directory containing:
   - [Artifact 1]
   - [Artifact 2]
4. **[Additional-Files]** - [Description]

## Report Template

```markdown
# [Lab Title] Report

**Analyst:** [Your Name]  
**Date:** [Date]  
**[Relevant Info]:** [Value]

---

## Executive Summary

[2-3 sentence summary]

---

## 1. [Section 1]

[Content with tables, screenshots, evidence]

---

## 2. [Section 2]

[Content]

---

[Continue with all relevant sections]

---

## Appendix

### Commands Used
```
[List all commands]
```

### Tools Used
- [Tool 1]
- [Tool 2]

---

**Analysis Completed:** [Date/Time]  
**Report Version:** 1.0
```
```

### 6. Evaluation Criteria (30-50 lines)

```markdown
## Evaluation Criteria

- **[Criterion 1]:** [Description]
- **[Criterion 2]:** [Description]
- **[Criterion 3]:** [Description]
- **[Criterion 4]:** [Description]
- **[Criterion 5]:** [Description]
- **[Criterion 6]:** [Description]

---

## Additional Resources

- [Resource 1 with link]
- [Resource 2 with link]
- [Resource 3 with link]
- [Resource 4 with link]

---

**Lab Completion Time:** [Record your time]  
**Difficulty Level:** [Beginner/Intermediate/Advanced/Expert]
```

---

## Remaining Labs to Expand

### Module 3 (SIEM and Log Management)

**Week 10: Creating Correlation Searches in Splunk**
- **Current:** 46 lines
- **Target:** 600-700 lines
- **Focus:** Advanced SPL, correlation rules, alerting, use cases
- **Reference:** Week 9 (Splunk Introduction)

**Week 11: Integrating Threat Intelligence in Splunk**
- **Current:** 50 lines
- **Target:** 500-600 lines
- **Focus:** Threat feeds, IOC matching, STIX/TAXII, automation
- **Reference:** Week 1 (Threat Intelligence), Week 9 (Splunk)

**Week 12: Advanced Splunk Searches**
- **Current:** 55 lines
- **Target:** 600-700 lines
- **Focus:** Complex SPL, subsearches, macros, data models, acceleration
- **Reference:** Week 9, Week 10

### Module 4 (Incident Response and Forensics)

**Week 15-Lab-Static-and-Dynamic-Malware-Analysis**
- **Current:** 60 lines
- **Target:** 400-500 lines (overview/introduction to both)
- **Focus:** Malware analysis workflow, tools overview, safety
- **Reference:** Week 15-C (Static), Week 15-D (Dynamic)

**Week 15-B-Setting-Up-Flare-VM**
- **Current:** 45 lines
- **Target:** 400-500 lines
- **Focus:** Flare VM installation, configuration, tool familiarization
- **Reference:** Week 2 (Home Lab Setup)

**Week 15-D-Dynamic-Malware-Analysis**
- **Current:** 70 lines
- **Target:** 700-800 lines
- **Focus:** Sandbox analysis, behavior monitoring, network analysis
- **Reference:** Week 15-C (Static Analysis), Week 8-C2 (C2 Detection)

**Week 16-Lab-Phishing-Email-Analysis**
- **Current:** 55 lines
- **Target:** 600-700 lines
- **Focus:** Email headers, attachment analysis, URL analysis, reporting
- **Reference:** Week 1 (Threat Intelligence), Week 15-C (Malware Analysis)

### Module 5 (Cloud SOC Monitoring)

**Week-17-Lab-Setting-Up-a-Cloud-Environment**
- **Current:** 50 lines
- **Target:** 600-700 lines
- **Focus:** AWS/Azure setup, cloud security services, logging, monitoring
- **Reference:** Week 2 (Home Lab Setup), Week 9 (Splunk)

**Week-12-Lab-Cloud-Security-Services** (Module 5)
- **Current:** 60 lines
- **Target:** 500-600 lines
- **Focus:** CloudTrail, GuardDuty, Security Hub, cloud-native SIEM
- **Reference:** Week 17 (Cloud Setup), Week 9 (Splunk)

### Module 6 (Threat Hunting and CTI)

**Week-13-Lab-Advanced-Threat-Hunting** (Module 6)
- **Current:** 55 lines
- **Target:** 600-700 lines
- **Focus:** Advanced hunting techniques, automation, threat intelligence integration
- **Reference:** Week 21 (Threat Hunting), Week 11 (Threat Intelligence)

### Module 7 (AI and Machine Learning in SOC)

**Week-14-Lab-AI-ML-in-SOC** (Module 7)
- **Current:** 50 lines
- **Target:** 500-600 lines
- **Focus:** ML for anomaly detection, UEBA, model training, evaluation
- **Reference:** Week 9 (Splunk), Week 21 (Threat Hunting)

---

## Expansion Guidelines

### Content Depth

**Each lab should include:**
- **Theory (20%):** Understanding concepts, architecture, use cases
- **Installation/Setup (15%):** Detailed setup instructions
- **Hands-on Exercises (50%):** Multiple practical exercises
- **Analysis (10%):** Interpreting results, identifying issues
- **Documentation (5%):** Report templates, deliverables

### Writing Style

**Follow these principles:**
- **Professional:** Academic tone, complete sentences
- **Clear:** Step-by-step instructions, no ambiguity
- **Comprehensive:** Cover all aspects thoroughly
- **Practical:** Real-world scenarios and use cases
- **Educational:** Explain the "why" not just the "how"

### Code Blocks

**Always include:**
- **Commands:** With explanations
- **Expected Output:** Show what students should see
- **Troubleshooting:** Common issues and solutions

### Tables

**Use tables for:**
- Comparing options/tools
- Listing key concepts
- Organizing data
- Evaluation criteria

### Visual Elements

**Include:**
- ASCII diagrams for architecture
- Process flow descriptions
- Timeline representations
- Structured data layouts

---

## Quality Checklist

Before considering a lab "expanded," verify:

- [ ] **Length:** 400-900 lines (depending on complexity)
- [ ] **Structure:** Follows template structure
- [ ] **Learning Outcomes:** 5-7 specific, measurable outcomes
- [ ] **Scenario:** Realistic, professional context
- [ ] **Prerequisites:** Clearly stated
- [ ] **Duration:** Estimated time provided
- [ ] **Theory Section:** Comprehensive explanation (100-150 lines)
- [ ] **Installation:** Detailed setup instructions (150-200 lines)
- [ ] **Exercises:** 3-6 hands-on exercises (200-400 lines)
- [ ] **Commands:** All commands explained
- [ ] **Expected Output:** Shown for key commands
- [ ] **Deliverables:** Clear list with report template
- [ ] **Evaluation Criteria:** 5-6 criteria listed
- [ ] **Resources:** 4-6 external resources linked
- [ ] **Difficulty Level:** Specified
- [ ] **Tables:** Used appropriately
- [ ] **Code Formatting:** Proper markdown code blocks
- [ ] **Professional Tone:** Maintained throughout

---

## Dataset Integration

For labs using datasets (CIC-IDS2017, CSE-CIC-IDS2018, etc.):

**Always include:**
1. **Dataset Description:** What it contains, attack types
2. **Download Instructions:** Where and how to get it
3. **Data Preparation:** Extraction, organization
4. **Analysis Exercises:** Specific attacks to investigate
5. **Sample Queries:** Pre-built queries for each attack type
6. **Expected Findings:** What students should discover

**Reference:** Week 8-B (CIC-IDS2017), Week 18 (CSE-CIC-IDS2018)

---

## Malware Sample Integration

For labs using malware samples:

**Always include:**
1. **Safety Warning:** Emphasize VM isolation
2. **Sample Location:** Path in repository
3. **Hash Values:** MD5, SHA256 for verification
4. **Analysis Tools:** Required tools listed
5. **Step-by-Step Analysis:** Detailed walkthrough
6. **IOC Extraction:** How to extract indicators
7. **Report Template:** Malware analysis report format

**Reference:** Week 15-C (Static Malware Analysis)

---

## Tool Integration

For labs introducing new tools:

**Always include:**
1. **Tool Overview:** What it does, why it's used
2. **Installation:** Detailed setup instructions
3. **Configuration:** Initial configuration steps
4. **Basic Usage:** Common commands/operations
5. **Advanced Features:** More complex capabilities
6. **Troubleshooting:** Common issues and solutions
7. **Best Practices:** Professional usage tips

**Reference:** Week 6 (Security Onion), Week 13 (Wazuh), Week 14 (Volatility)

---

## MITRE ATT&CK Integration

For labs involving threat detection/hunting:

**Always include:**
1. **Technique Mapping:** Map activities to ATT&CK
2. **Tactic Coverage:** Identify which tactics are covered
3. **Detection Methods:** How to detect each technique
4. **Table Format:** Organized ATT&CK mapping table

**Reference:** Week 21 (Threat Hunting), Week 14 (Volatility)

---

## Final Notes

**Remember:**
- Quality over quantity (but aim for 400-900 lines)
- Real-world applicability is key
- Students should feel prepared for SOC roles
- Every lab should build on previous knowledge
- Professional documentation is critical

**When in doubt:**
- Reference the 15 completed labs
- Follow the template structure
- Maintain consistent quality
- Focus on practical, hands-on learning

---

**Document Version:** 1.0  
**Last Updated:** 2024-01-15  
**Maintained By:** SOC Training Program Team
