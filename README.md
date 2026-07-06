# 🛡️ Detection Engineering Lab
## Enterprise EDR/XDR Investigation Platform

> A modern Endpoint Detection and Response (EDR) and Detection Engineering platform built from the ground up using Python, FastAPI, Streamlit, Sysmon, Threat Intelligence, and AI-assisted investigation.

---

![Python](https://img.shields.io/badge/Python-3.14-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red)
![SQLite](https://img.shields.io/badge/SQLite-Storage-blue)
![MITRE ATT%26CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Sysmon](https://img.shields.io/badge/Sysmon-Windows-success)
![License](https://img.shields.io/badge/License-MIT-green)

---

# Overview

The **Detection Engineering Lab** is an enterprise-style cybersecurity platform that simulates many of the investigation capabilities found in commercial EDR/XDR solutions such as:

- SentinelOne
- Microsoft Defender for Endpoint
- CrowdStrike Falcon
- Palo Alto Cortex XDR

The objective is to understand how modern detection platforms are engineered internally by building every layer from scratch, including telemetry collection, detection logic, investigation workflows, REST APIs, and interactive analyst dashboards.

This project focuses on **Detection Engineering**, **Threat Hunting**, **Incident Response**, **Backend API Development**, and **Security Operations (SOC)**.

---

# Current Platform Capabilities

## Endpoint Telemetry

- Live Sysmon collection
- Windows Event Log collection
- Windows Security Events
- PowerShell telemetry
- Process creation monitoring
- File activity
- Registry monitoring
- Network connections

---

## Detection Engine

- Modular detection rules
- MITRE ATT&CK mapping
- Behavioral detections
- Risk scoring engine
- Alert prioritization
- Timeline correlation

---

## Threat Intelligence

Current Providers

- ✅ AlienVault OTX

Upcoming Providers

- VirusTotal
- AbuseIPDB
- MalwareBazaar
- URLHaus
- GreyNoise
- Hybrid Analysis

Threat intelligence enrichment is fully modular allowing providers to be added independently.

---

## Investigation Engine

- Alert investigations
- Storylines
- Process Trees
- Timeline reconstruction
- Endpoint investigation
- AI enrichment
- MITRE ATT&CK mapping
- Evidence collection

---

## FastAPI Backend

REST API powering the investigation platform.

Current APIs

- Alerts
- Alert Details
- Storylines
- Process Trees
- Case Management
- Timeline
- Response Actions
- Entity Pivoting

Interactive Swagger documentation

```
http://127.0.0.1:8000/docs
```

---

## Investigation Dashboard

Interactive Streamlit dashboard providing

- Alert overview
- Investigation timeline
- Storyline visualization
- Process tree
- Threat Intelligence
- Risk Score
- Severity
- MITRE ATT&CK Techniques
- AI Investigation Summary

---

# Architecture

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
                    │ Normalizers  │
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Detection    │
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Risk Engine  │
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Threat Intel │
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Investigation│
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ FastAPI API  │
                    └──────────────┘
                           │
                    ┌──────────────┐
                    │ Dashboard    │
                    └──────────────┘
```

---

# Backend Architecture

The backend follows a layered enterprise architecture.

```
HTTP Request

      │

      ▼

FastAPI Router

      │

      ▼

Controller Layer

      │

      ▼

Storage Layer

      │

      ▼

SQLite / JSON
```

Each layer has a single responsibility.

### Routers

- HTTP endpoints
- Request validation
- Response models

### Controllers

- Business logic
- Investigation orchestration
- Timeline aggregation
- Response action workflows

### Storage

- SQLite
- JSON
- Data access
- Persistence

---

# Investigation Workflow

```
Alert Generated

↓

Investigation

↓

Storyline

↓

Process Tree

↓

Timeline

↓

Entity Pivot

↓

Case

↓

Response Action
```

This mirrors modern SOC investigation workflows.

---

# REST API

## Alerts

```
GET /api/v1/alerts

GET /api/v1/alerts/{alert_id}
```

---

## Storylines

```
GET /api/v1/storylines/{storyline_id}
```

---

## Process Trees

```
GET /api/v1/process-tree/{storyline_id}
```

---

## Cases

```
GET /api/v1/cases/{case_id}

PATCH /api/v1/cases/{case_id}
```

---

## Response Actions

```
POST /api/v1/response-actions

GET /api/v1/response-actions/{alert_id}
```

---

## Timeline

```
GET /api/v1/timeline
```

---

## Entity Pivoting

```
GET /api/v1/entities/{entity_id}
```

---

# Project Structure

```
Detection-Engineering-Lab/

api/
│
├── routers/
├── controllers/
├── schemas.py
├── main.py

dashboard/

detections/

enrichment/

normalizers/

sensor/

scoring/

storage/

tests/

docs/

data/
```

---

# Technologies

- Python
- FastAPI
- Streamlit
- SQLite
- Sysmon
- Windows Event Logs
- MITRE ATT&CK
- AlienVault OTX
- Git
- GitHub

---

# Current Roadmap

## ✅ Completed

- Live Sysmon Collection
- Detection Engine
- Risk Scoring
- Threat Intelligence
- Investigation Engine
- Storylines
- Process Trees
- FastAPI Backend
- REST API
- Swagger Documentation
- Case Management
- Timeline API
- Entity Pivoting

---

## 🚧 In Progress

- Interactive Timeline
- Response Actions
- AI Investigation Assistant
- Entity Graph
- Multi-endpoint Support

---

## 🔜 Planned

- ClickHouse Backend
- Elasticsearch Support
- Authentication
- Role-Based Access Control
- IOC Search
- Threat Hunting Queries
- Live Event Streaming
- Docker Deployment
- Kubernetes Deployment
- Multi-Tenant Support

---

# Screenshots

Coming Soon

- Dashboard
- Alerts
- Storylines
- Process Trees
- Timeline
- Entity Investigation
- Response Actions

---

# Why I Built This

Commercial EDR platforms provide sophisticated investigation capabilities, but most operate as closed-source products.

I built the Detection Engineering Lab to better understand how modern endpoint security platforms are engineered by implementing the core components myself. The project demonstrates detection engineering, endpoint telemetry processing, backend API development, threat intelligence enrichment, investigation workflows, and scalable software architecture while following enterprise engineering practices.

---

# Future Vision

The long-term objective is to evolve this project into a full-featured EDR/XDR investigation platform supporting:

- Multiple endpoints
- High-volume telemetry ingestion
- Behavioral analytics
- IOC hunting
- AI-assisted investigations
- Threat Intelligence correlation
- Automated response actions
- Interactive investigation graphs

---

# Author

**Desmond Agbortabi**

Security Analyst | Detection Engineering | Incident Response | Threat Hunting | Python | FastAPI | SOC Operations

GitHub:

https://github.com/dtabi60/Detection-Engineering-Lab

---

# License

MIT License
