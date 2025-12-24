# Week 3: Essential Linux & Command Line Skills

## 3.1 Introduction to the Linux Command Line

The Linux command line is a powerful tool for interacting with a Linux system. For a SOC analyst, proficiency in the command line is essential for tasks such as log analysis, file manipulation, and system administration.

### The Shell

The shell is a program that takes commands from the keyboard and gives them to the operating system to perform. The most common shell on Linux systems is the Bash shell (Bourne Again SHell).

### Basic Commands

- `ls`: List files and directories.
- `cd`: Change directory.
- `pwd`: Print working directory.
- `mkdir`: Create a new directory.
- `rm`: Remove files or directories.
- `cp`: Copy files or directories.
- `mv`: Move or rename files or directories.
- `cat`: Display the contents of a file.
- `less`: Display the contents of a file one page at a time.
- `head`: Display the first few lines of a file.
- `tail`: Display the last few lines of a file.

## 3.2 File Permissions

Linux uses a system of permissions to control access to files and directories. Each file and directory has three sets of permissions: one for the owner, one for the group, and one for everyone else.

The permissions are:

- `r`: Read
- `w`: Write
- `x`: Execute

## 3.3 Essential Command-Line Tools

### `grep`

`grep` is a command-line utility for searching plain-text data sets for lines that match a regular expression. It is an invaluable tool for a SOC analyst to quickly find relevant information in log files.

**Example:**

```bash
# Search for all lines containing the IP address "192.168.1.100" in a log file
grep "192.168.1.100" /var/log/auth.log
```

### `awk`

`awk` is a versatile programming language designed for text processing. It is often used to extract and manipulate data from structured text files, such as log files.

**Example:**

```bash
# Print the first and third columns of a log file
awk '{print $1, $3}' /var/log/auth.log
```

### `sed`

`sed` (stream editor) is a powerful utility for parsing and transforming text. It can be used to perform search and replace operations, delete lines, and more.

**Example:**

```bash
# Replace all occurrences of "error" with "ERROR" in a file
sed 's/error/ERROR/g' file.txt
```

## 3.4 Bash Scripting

Bash scripting allows you to automate repetitive tasks by writing scripts that can be executed from the command line. This can save a SOC analyst a significant amount of time and effort.

**Example:**

```bash
#!/bin/bash

# A simple script to count the number of failed login attempts
echo "Failed login attempts:"
grep "Failed password" /var/log/auth.log | wc -l
```
