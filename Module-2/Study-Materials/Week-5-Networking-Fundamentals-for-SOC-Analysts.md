# Week 5: Networking Fundamentals for SOC Analysts

## 5.1 The TCP/IP Model

The TCP/IP model is a conceptual framework that standardizes the functions of a telecommunication or computing system in terms of abstraction layers. It is a more concise version of the OSI model and is the foundation of the internet.

- **Layer 1: Physical Layer:** Responsible for the physical transmission of data, such as electrical signals and radio waves.
- **Layer 2: Data Link Layer:** Responsible for node-to-node data transfer and error correction. This is where MAC addresses reside.
- **Layer 3: Network Layer:** Responsible for routing data between different networks. This is where IP addresses reside.
- **Layer 4: Transport Layer:** Responsible for end-to-end communication and flow control. The two most common protocols at this layer are TCP and UDP.
- **Layer 5: Application Layer:** Responsible for providing network services to applications. This is where protocols such as HTTP, DNS, and SMTP reside.

## 5.2 The Three-Way Handshake

TCP (Transmission Control Protocol) is a connection-oriented protocol, which means that it establishes a connection before transmitting data. This is done through a process called the three-way handshake:

1. **SYN:** The client sends a SYN (synchronize) packet to the server.
2. **SYN-ACK:** The server responds with a SYN-ACK (synchronize-acknowledge) packet.
3. **ACK:** The client responds with an ACK (acknowledge) packet, and the connection is established.

## 5.3 Common Network Protocols

As a SOC analyst, it is crucial to have a good understanding of the most common network protocols:

- **HTTP/HTTPS:** The protocols used for web traffic.
- **DNS:** The protocol used to resolve domain names to IP addresses.
- **SMTP, POP3, IMAP:** The protocols used for email.
- **FTP/SFTP/FTPS:** The protocols used for file transfer.
- **SSH:** A secure protocol for remote administration.
- **RDP:** A protocol for remote desktop access.

## 5.4 Network Architecture

Understanding the basic components of a network is essential for a SOC analyst:

- **Routers:** Devices that route traffic between different networks.
- **Switches:** Devices that connect devices on the same network.
- **Firewalls:** Devices that filter traffic based on a set of rules.
- **Proxies:** Servers that act as an intermediary for requests from clients seeking resources from other servers.
- **IDS/IPS:** Intrusion Detection Systems and Intrusion Prevention Systems, which are used to detect and prevent malicious activity.
