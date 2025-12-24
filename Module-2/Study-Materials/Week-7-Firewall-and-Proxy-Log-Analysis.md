# Week 7: Firewall and Proxy Log Analysis

## 7.1 Introduction to Firewalls

A firewall is a network security device that monitors incoming and outgoing network traffic and decides whether to allow or block specific traffic based on a defined set of security rules. Firewalls are a first line of defense in network security.

### Types of Firewalls

- **Packet-Filtering Firewalls:** The most basic type of firewall, which inspects packets and allows or denies them based on rules such as source/destination IP address, port number, and protocol.
- **Stateful Inspection Firewalls:** These firewalls maintain the state of connections and can make more intelligent decisions about which packets to allow or block.
- **Next-Generation Firewalls (NGFWs):** These firewalls combine traditional firewall features with other security functions, such as intrusion prevention, application control, and threat intelligence.

## 7.2 Firewall Log Analysis

Firewall logs are a critical source of information for a SOC analyst. They can be used to:

- Identify malicious traffic that has been blocked by the firewall.
- Detect attempts to scan the network for open ports.
- Investigate security incidents by reconstructing the sequence of events.

### Common Firewall Log Fields

- **Timestamp:** The date and time the event occurred.
- **Source IP:** The IP address of the source of the traffic.
- **Destination IP:** The IP address of the destination of the traffic.
- **Source Port:** The source port of the traffic.
- **Destination Port:** The destination port of the traffic.
- **Protocol:** The protocol of the traffic (e.g., TCP, UDP, ICMP).
- **Action:** The action taken by the firewall (e.g., allow, deny, drop).

## 7.3 Introduction to Proxies

A proxy server is a server that acts as an intermediary for requests from clients seeking resources from other servers. Proxies can be used for a variety of purposes, including:

- **Caching:** Proxies can cache frequently accessed content to improve performance.
- **Filtering:** Proxies can be used to filter content, such as blocking access to certain websites.
- **Anonymity:** Proxies can be used to hide the IP address of the client.

## 7.4 Proxy Log Analysis

Proxy logs are another valuable source of information for a SOC analyst. They can be used to:

- Track the websites that users are visiting.
- Identify potential policy violations.
- Detect malware downloads and other malicious activity.

### Common Proxy Log Fields

- **Timestamp:** The date and time the request was made.
- **Client IP:** The IP address of the client that made the request.
- **URL:** The URL that was requested.
- **HTTP Method:** The HTTP method used (e.g., GET, POST).
- **User-Agent:** The user-agent string of the client's browser.
- **Status Code:** The HTTP status code returned by the server.
