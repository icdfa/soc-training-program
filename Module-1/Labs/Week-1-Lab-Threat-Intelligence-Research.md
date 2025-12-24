# Week 1 Lab: Threat Intelligence Research

## Objective

To research a recent, well-known cyber attack and document the attacker's tactics, techniques, and procedures (TTPs) using the MITRE ATT&CK framework.

## Scenario

You are a Junior SOC Analyst, and your manager has asked you to create a threat intelligence report on the SolarWinds Orion supply chain attack. This report will be used to improve the SOC's detection capabilities.

## Instructions

1. **Research the SolarWinds Attack:**
   - Use search engines and reputable cybersecurity news sources to gather information about the SolarWinds Orion supply chain attack.
   - Focus on the technical details of the attack, including the malware used (Sunburst/Solarigate), the initial access vector, and the post-exploitation activities.

2. **Map to MITRE ATT&CK:**
   - Use the MITRE ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) to map the TTPs used in the SolarWinds attack.
   - Create a new layer in the ATT&CK Navigator and name it "SolarWinds Attack".
   - For each technique you identify, add it to your layer and assign it a score of 1.

3. **Document Your Findings:**
   - Create a new Markdown document named `SolarWinds-Threat-Report.md`.
   - In this document, provide a brief summary of the attack.
   - List the MITRE ATT&CK techniques you identified, along with a brief explanation of how each technique was used in the attack.
   - Export your ATT&CK Navigator layer as a JSON file and include a link to it in your report.

## Deliverables

- A Markdown document (`SolarWinds-Threat-Report.md`) containing your threat intelligence report.
- A JSON file (`SolarWinds-Attack.json`) exported from the MITRE ATT&CK Navigator.

## Example Report Structure

```markdown
# SolarWinds Orion Supply Chain Attack - Threat Intelligence Report

## Summary

A brief summary of the SolarWinds attack, including the timeline, the attacker (suspected to be APT29/Cozy Bear), and the impact.

## MITRE ATT&CK Techniques

### Initial Access

- **T1195.002 - Supply Chain Compromise:** The attacker compromised the SolarWinds Orion build process to insert a backdoor into the software.

### Execution

- **T1059.003 - Windows Command Shell:** The Sunburst backdoor used the Windows command shell to execute commands.

### Persistence

- **T1543.003 - Windows Service:** The Sunburst backdoor was installed as a Windows service to maintain persistence.

... (continue for all identified techniques)

## ATT&CK Navigator Layer

[Link to SolarWinds-Attack.json](./SolarWinds-Attack.json)
```
