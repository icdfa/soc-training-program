# Module 3 Quiz: SIEM & Log Management - Answers

1. **What is the primary purpose of a SIEM?**
   - A SIEM (Security Information and Event Management) system is a security solution that helps organizations recognize and address potential security threats and vulnerabilities before they have a chance to disrupt business operations. It surfaces user behavior anomalies and uses artificial intelligence to automate many of the manual processes associated with threat detection and incident response. It is used to collect, store, and analyze log data from a variety of sources to provide a holistic view of an organization's security posture.

2. **What is the difference between a correlation search and a regular search in Splunk?**
   - A regular search is a one-time search that is executed manually. A correlation search is a saved search that is executed on a schedule and is used to identify suspicious patterns of behavior that may indicate a security threat.

3. **What is the purpose of a threat intelligence feed?**
   - A threat intelligence feed is a stream of data that provides information about potential security threats. This information can be used to identify and block malicious IP addresses, domains, and file hashes.

4. **What is the default port for Splunk web interface?**
   - The default port for the Splunk web interface is 8000.

5. **What is the purpose of the `tstats` command in Splunk?**
   - The `tstats` command is a faster and more efficient way to search for data in Splunk. It is used to perform statistical queries on indexed fields in tsidx files. It is much faster than the `stats` command because it does not have to read the raw data.
