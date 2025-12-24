# Lab Resources

This directory contains additional resources to support the hands-on labs in the SOC Training Program.

## Directory Structure

```
Lab-Resources/
├── Sample-Data/          # Sample log files, PCAPs, and datasets for labs
├── Expected-Outputs/     # Example outputs and reports for reference
├── Templates/            # Report templates and documentation formats
└── Scripts/              # Helper scripts for lab automation
```

## Sample Data

The `Sample-Data/` directory contains smaller sample files for labs that don't require full datasets:

- **apache-access.log** - Sample Apache web server logs for Week 3 Lab
- **firewall.log** - Sample firewall logs for Week 7 Lab
- **c2-traffic.pcap** - Sample C2 communication for Week 8 Lab
- **suspicious-traffic.pcap** - Sample malicious traffic for Week 5 Lab
- **phishing-email.eml** - Sample phishing email for Week 16 Lab

## Expected Outputs

The `Expected-Outputs/` directory contains example deliverables to help you understand what is expected:

- **Threat-Intelligence-Report-Example.md** - Example threat intelligence report (Week 1)
- **Log-Analysis-Report-Example.md** - Example log analysis report (Week 3)
- **Malware-Analysis-Report-Example.md** - Example malware analysis report (Week 15)
- **Splunk-Dashboard-Example.xml** - Example Splunk dashboard configuration

## Templates

The `Templates/` directory contains report templates and documentation formats:

- **Threat-Intelligence-Report-Template.md** - Template for threat intelligence reports
- **Incident-Response-Report-Template.md** - Template for incident response reports
- **Malware-Analysis-Report-Template.md** - Template for malware analysis reports
- **Lab-Report-Template.md** - General lab report template

## Scripts

The `Scripts/` directory contains helper scripts for lab automation:

- **hash_calculator.py** - Calculate MD5, SHA1, SHA256 hashes for files
- **log_parser.py** - Parse and analyze log files
- **pcap_analyzer.py** - Basic PCAP analysis script
- **ioc_extractor.py** - Extract IOCs from text files

## Usage

### Sample Data

To use sample data in your labs:

1. Copy the sample file to your working directory
2. Follow the lab instructions using the sample data
3. Compare your results with the expected outputs

### Templates

To use a template:

1. Copy the template to your working directory
2. Rename it appropriately (e.g., `Week-1-Threat-Report.md`)
3. Fill in the sections with your findings

### Scripts

To use a helper script:

```bash
# Example: Calculate hashes
python3 Scripts/hash_calculator.py /path/to/malware.exe

# Example: Parse logs
python3 Scripts/log_parser.py Sample-Data/apache-access.log

# Example: Analyze PCAP
python3 Scripts/pcap_analyzer.py Sample-Data/suspicious-traffic.pcap
```

## Contributing

If you have created useful resources for the labs, please consider contributing them:

1. Fork the repository
2. Add your resources to the appropriate directory
3. Update this README
4. Submit a pull request

## Notes

- Sample data files are intentionally small for quick downloads
- For full datasets (CIC-IDS2017, CSE-CIC-IDS2018, etc.), refer to the Datasets directory
- Expected outputs are examples only - your results may vary
- Scripts are provided as-is and may require modification for your environment

---

**Developed by:** Aminu Idris, AMCPN | International Cybersecurity and Digital Forensics Academy (ICDFA)
