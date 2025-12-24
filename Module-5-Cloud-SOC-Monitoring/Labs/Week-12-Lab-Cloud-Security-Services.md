_# Week 12 Lab: Exploring Cloud Security Services

## Learning Outcomes

By the end of this lab, you will be able to:

- Navigate the security services of a major cloud provider (AWS, Azure, or GCP).
- Configure a cloud-native firewall or security group.
- Enable and review cloud security logging and monitoring services.
- Understand the role of Identity and Access Management (IAM) in cloud security.

## 1. Objective

In this lab, you will explore the native security services of your chosen cloud provider. You will learn how to configure basic security controls and monitor for threats in a cloud environment.

## 2. Prerequisites

- A free tier account with AWS, Azure, or GCP (from Week 17 lab).
- A running virtual machine in your cloud environment.

## 3. Lab Steps

### Step 1: Configure Network Security

1.  **AWS:**
    -   Navigate to the EC2 dashboard and select "Security Groups".
    -   Create a new security group and configure inbound rules to allow SSH (port 22) and HTTP (port 80) traffic from your IP address only.
    -   Associate the new security group with your VM.
2.  **Azure:**
    -   Navigate to your VM's "Networking" settings.
    -   Create a new Network Security Group (NSG) and add inbound security rules for SSH (port 22) and HTTP (port 80).
    -   Apply the NSG to your VM's network interface.
3.  **GCP:**
    -   Navigate to the VPC network > Firewall rules.
    -   Create a new firewall rule to allow ingress traffic on TCP ports 22 and 80 from your IP address.
    -   Apply the rule to your VM using network tags.

### Step 2: Enable and Review Logging

1.  **AWS:**
    -   Enable AWS CloudTrail to log all API activity in your account.
    -   Enable VPC Flow Logs to capture IP traffic information for your VPC.
    -   Review the logs in Amazon CloudWatch.
2.  **Azure:**
    -   Enable Azure Monitor to collect and analyze telemetry data.
    -   Enable NSG Flow Logs to log IP traffic flowing through your NSG.
    -   Review the logs in the Azure Monitor console.
3.  **GCP:**
    -   Enable VPC Flow Logs for your VPC network.
    -   Enable Audit Logs to track administrative changes and data access.
    -   Review the logs in the Stackdriver Logging console.

### Step 3: Explore Identity and Access Management (IAM)

1.  **AWS:**
    -   Navigate to the IAM dashboard.
    -   Create a new IAM user with read-only access to EC2.
    -   Create a new IAM role with a specific policy attached.
2.  **Azure:**
    -   Navigate to the Azure Active Directory dashboard.
    -   Create a new user and assign them a built-in role (e.g., Reader).
    -   Explore the different roles and their permissions.
3.  **GCP:**
    -   Navigate to the IAM & Admin dashboard.
    -   Add a new member and assign them a predefined role (e.g., Viewer).
    -   Explore the different IAM roles and their permissions.

## 4. Deliverables

-   A screenshot of your configured security group/NSG/firewall rule.
-   A screenshot of your enabled logging service.
-   A screenshot of your newly created IAM user or role.
_
