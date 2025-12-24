# Week 10: Basic SIEM Alerting & Correlation

## 10.1 Introduction to SIEM Correlation

SIEM correlation is the process of linking events from different sources to identify potential security threats. By correlating events, a SOC analyst can gain a more complete picture of what is happening on the network and detect attacks that might otherwise go unnoticed.

### Types of Correlation

- **Rule-Based Correlation:** This is the most common type of correlation, which uses a set of predefined rules to identify suspicious patterns of activity.
- **Statistical Correlation:** This type of correlation uses statistical analysis to identify anomalies and deviations from normal behavior.
- **Machine Learning Correlation:** Some advanced SIEMs use machine learning algorithms to identify complex patterns of activity that may be indicative of a threat.

## 10.2 Creating Correlation Searches in Splunk

In Splunk, correlation searches are used to implement rule-based correlation. A correlation search is a saved search that runs on a regular schedule and creates an alert when the search results meet certain criteria.

### Creating a Correlation Search

1. **Create a Search:** Start by creating a search that identifies the suspicious activity you want to detect.
2. **Save the Search:** Save the search as a correlation search.
3. **Configure the Schedule:** Configure the search to run on a regular schedule (e.g., every 5 minutes).
4. **Configure the Alert:** Configure the search to create an alert when the search results meet certain criteria (e.g., when the number of results is greater than 0).

## 10.3 Building Dashboards in Splunk

Dashboards are a powerful way to visualize data in Splunk. They can be used to create a high-level overview of your security posture, track key metrics, and monitor for potential threats.

### Creating a Dashboard

1. **Create a New Dashboard:** Start by creating a new dashboard in Splunk.
2. **Add Panels:** Add panels to the dashboard to display the results of your searches.
3. **Configure the Panels:** Configure the panels to display the data in a variety of formats, such as charts, tables, and single value visualizations.

## 10.4 Managing Alerts in Splunk

When a correlation search is triggered, it creates an alert in Splunk. It is the job of the SOC analyst to investigate these alerts and determine whether they represent a real threat.

### The Alert Triage Process

1. **Prioritize Alerts:** Not all alerts are created equal. It is important to prioritize alerts based on their severity and potential impact.
2. **Investigate Alerts:** Once an alert has been prioritized, the SOC analyst needs to investigate it to determine whether it is a false positive or a real threat.
3. **Escalate Alerts:** If an alert is determined to be a real threat, it needs to be escalated to the appropriate team for further investigation and response.
