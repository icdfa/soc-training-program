# Week 16 Lab: Phishing Email Analysis

## Objective

In this lab, you will analyze a sample phishing email to determine if it is malicious. You will use the techniques you learned this week to analyze the email headers, attachments, and URLs.

## Tools

*   An email header analyzer (e.g., [MXToolbox Email Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx))
*   A URL reputation checker (e.g., [VirusTotal](https://www.virustotal.com/gui/home/url))

## Phishing Email Sample

For this lab, you will be provided with a sample phishing email in a `.eml` file format. You can open this file in a text editor to view the raw email content, including the headers.

**Sample to download:**

*   [phishing_email.eml](./resources/phishing_email.eml)

## Instructions

1.  **Analyze the Email Headers:**
    *   Copy and paste the email headers into an email header analyzer.
    *   Analyze the `Received` headers to trace the path of the email.
    *   Look for any signs of spoofing, such as a mismatch between the `From` and `Return-Path` headers.

2.  **Analyze the Email Body:**
    *   Examine the email body for any suspicious content, such as urgent requests, spelling errors, or generic greetings.
    *   Hover over any links in the email to see the actual URL.

3.  **Analyze the URL:**
    *   Copy and paste the URL from the email into a URL reputation checker.
    *   Analyze the results to determine if the URL is malicious.

## Deliverables

*   A report summarizing your findings.
*   Screenshots of your email header analysis and URL analysis.
*   A list of all Indicators of Compromise (IOCs) you identified.
