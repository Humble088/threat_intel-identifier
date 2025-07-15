# Automated Threat Intelligence Feeds Processor

## Overview
This application fetches Indicators of Compromise (IOCs) from various threat intelligence feeds, compares them against internal logs, and generates alerts when matches are found.

## Features
- Supports multiple threat intelligence feeds (AlienVault OTX, AbuseIPDB, VirusTotal)
- Elasticsearch integration for IOC storage and log correlation
- Configurable alerting via email and Slack
- Modular architecture for easy extension

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourrepo/threat_intel_processor.git
cd threat_intel_processor