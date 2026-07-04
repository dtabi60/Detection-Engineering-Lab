# Detection-Engineering-Lab
A hands-on detection engineering lab for building, testing, and tuning cybersecurity detections using Python, Sysmon, Sigma, and MITRE ATT&amp;CK.
# 🛡️ Detection Engineering Lab

> A modern Detection Engineering and Endpoint Investigation Platform built from the ground up using Python, Sysmon, Streamlit, AI, and Threat Intelligence.

---

# Overview

The Detection Engineering Lab is a portfolio project that simulates many of the core capabilities found in commercial Endpoint Detection and Response (EDR) platforms such as SentinelOne, Microsoft Defender for Endpoint, and CrowdStrike.

Instead of simply generating alerts, this platform collects live endpoint telemetry, normalizes Windows events, enriches indicators with Threat Intelligence, and provides an interactive investigation experience for security analysts.

This project is designed to demonstrate Detection Engineering, Security Operations (SOC), Threat Detection, Incident Investigation, Python automation, and security engineering skills.

---

# Current Features

### Live Endpoint Telemetry

- Live Sysmon event collection
- Windows Event Log collection
- PowerShell event collection (planned)
- Windows Security Log collection (planned)

---

### Event Processing

- Event normalization engine
- Common event schema
- Timeline generation
- Event correlation framework

---

### Detection Engine

- Modular detection rules
- Risk scoring
- MITRE ATT&CK mapping
- JSON alert generation

---

### Threat Intelligence Engine

Current Providers

- ✅ OTX (Operational)

Upcoming Providers

- AbuseIPDB
- VirusTotal
- MalwareBazaar
- URLhaus

The Threat Intelligence Engine is provider-based, allowing additional intelligence feeds to be added without modifying the dashboard.

---

### Investigation Dashboard

Interactive Streamlit dashboard featuring

- Alert summary
- Risk score
- Severity
- MITRE ATT&CK mapping
- Raw telemetry
- Investigation timeline
- Endpoint view
- Process details

Upcoming

- Process Tree
- Host Investigation
- User Investigation
- Network Investigation
- DNS Investigation
- Registry Investigation
- AI Investigation Assistant

---

# Project Architecture

```
                    Windows Endpoint
                           │
                    Sysmon / Event Logs
                           │
                    ┌──────────────┐
                    │ Collectors   │
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Parsers      │
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Normalization│
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Detection    │
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Threat Intel │
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ AI Analysis  │
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Dashboard    │
                    └──────────────┘
```

---

# Project Structure

```
Detection-Engineering-Lab/

collectors/
    Live Windows telemetry collectors

parsers/
    Event normalization
    Timeline generation

detections/
    Detection rules
    Risk scoring

enrichment/
    Threat Intelligence providers
    OTX
    AbuseIPDB
    VirusTotal
    MalwareBazaar
    URLhaus

dashboard/
    Interactive investigation interface

data/
    Raw telemetry
    Alerts
    Normalized events
    Investigation timeline

docs/
    Documentation

tests/
    Unit tests
```

---

# Detection Pipeline

```
Live Endpoint

↓

Sysmon

↓

Collector

↓

Parser

↓

Normalized Events

↓

Detection Rules

↓

Threat Intelligence

↓

AI Investigation

↓

Interactive Dashboard
```

---

# Technologies

- Python
- Streamlit
- Sysmon
- Windows Event Logs
- OpenAI API
- OTX Threat Intelligence
- Git
- GitHub
- SQLite (In Progress)

---

# Example Investigation Workflow

```
Alert Generated

↓

PowerShell Execution

↓

Timeline Reconstruction

↓

Threat Intelligence Lookup

↓

MITRE ATT&CK Mapping

↓

AI Investigation Summary

↓

Recommended Response
```

---

# Roadmap

## Phase 1 ✅

- Live Sysmon Collection
- Event Parser
- Detection Engine
- Timeline Builder
- Streamlit Dashboard

---

## Phase 2 🚧

- Threat Intelligence Engine
- OTX Integration
- AbuseIPDB
- VirusTotal
- MalwareBazaar
- URLhaus

---

## Phase 3

- Process Tree
- Host Investigation
- User Investigation
- DNS Investigation
- Network Investigation
- Registry Investigation

---

## Phase 4

- SQLite Backend
- AI Investigation Assistant
- Threat Hunting Interface
- IOC Search
- Behavioral Baselines
- Case Management

---

# Goals

This project aims to simulate the workflow of a modern Security Operations Center by combining

- Detection Engineering
- Endpoint Investigation
- Threat Intelligence
- Incident Response
- Threat Hunting
- AI-assisted Analysis

into a single platform.

---

# Screenshots

> Dashboard screenshots and investigation workflows will be added as new features are completed.

---

# Author

**Desmond Agbortabi**

Security Analyst | Detection Engineering | Incident Response | Threat Detection | Python Automation

GitHub:
https://github.com/dtabi60/Detection-Engineering-Lab

---

## License

MIT License
