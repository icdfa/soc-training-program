# Week 10 Lab: Creating Correlation Searches in Splunk

## Learning Outcomes

By the end of this lab, you will be able to:

- Write SPL queries to identify specific security events.
- Create and configure correlation searches in Splunk.
- Set up alerts based on the results of correlation searches.
- Build a security dashboard to visualize alerts.

## Objective

To practice creating correlation searches in Splunk to detect suspicious activity.

## Scenario

You are a SOC analyst and you have been tasked with creating a set of correlation searches in Splunk to detect common attack techniques.

## Instructions

### Part 1: Create a Correlation Search for Brute-Force Attacks

1. **Create a Search:** Write a Splunk search that identifies multiple failed login attempts from the same source IP address within a short period of time.
2. **Save the Search:** Save the search as a correlation search named "Brute-Force Attack Detected".
3. **Configure the Schedule:** Configure the search to run every 5 minutes.
4. **Configure the Alert:** Configure the search to create an alert when the number of results is greater than or equal to 5.

### Part 2: Create a Correlation Search for Impossible Travel

1. **Create a Search:** Write a Splunk search that identifies successful logins for the same user from two different geographic locations within an impossible amount of time.
2. **Save the Search:** Save the search as a correlation search named "Impossible Travel Detected".
3. **Configure the Schedule:** Configure the search to run every hour.
4. **Configure the Alert:** Configure the search to create an alert when the number of results is greater than 0.

### Part 3: Create a Dashboard

1. **Create a New Dashboard:** Create a new dashboard named "Security Alerts".
2. **Add Panels:** Add panels to the dashboard to display the results of your correlation searches.
3. **Configure the Panels:** Configure the panels to display the data in a way that is easy to understand, such as a table or a chart.

## Deliverables

- Screenshots of your correlation searches and your dashboard.
- A brief write-up explaining the logic behind your correlation searches.
