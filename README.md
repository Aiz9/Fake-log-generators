# Random Log Generator

This Python script generates random logs in different formats, including Syslog, CEF, and JSON. The logs mimic real-world security events and provide useful simulation data for testing and analysis in cybersecurity environments.

## Features

- Generates random logs in **Syslog**, **CEF**, and **JSON** formats.
- Customizable fields such as IP addresses, hostnames, and user agents.
- Simulates **HTTP policy names**, **attack types**, **security policy violations**, and more.
- Supports randomness to simulate varying log events.

## Installation

Clone this repository to your local machine:

```bash
git clone https://github.com/Aiz9/Fake-log-generators.git
cd random-log-generator
```
Make sure you have Python installed, and then install any necessary dependencies:
```bash
pip install -r requirements.txt
```
 Note: This script uses built-in Python modules like random, json, and datetime, so no external libraries are required.

 # Usage
 The script allows you to generate logs in different formats. Simply run the script and select your preferred format.


 ## Available Log Formats
 - Syslog
 - CEF
 - Json

 To use the script, run the following commands:
```bash
python log_generator.py
```
You will be prompted to select the log format:
```bash
Choose log format (syslog/cef/json):
```
After selecting a format, You will be prompted to choose number of logs you want to generate:
```bash
Enter the number of logs to generate:
```


# Contributing

Feel Free to submit issues or pull requests if you want to contribute to the development of this log generator. All contribution are welcome.
