# Detection Engineering Lab - Product Design

## Purpose

Detection Engineering Lab is a portfolio-grade detection engineering platform built to collect logs, run detection rules, calculate risk scores, map alerts to MITRE ATT&CK, and display results in a GUI.

## Main Pages

### 1. Dashboard
Shows alert counts, severity breakdown, detection rule count, and MITRE coverage.

### 2. Alerts
Displays generated alerts with severity, risk score, rule name, MITRE technique, and source log.

### 3. Detection Rules
Shows all YAML detection rules and their metadata.

### 4. Rule Wizard
Allows a user to create new detection rules without manually writing YAML.

### 5. Test Lab
Runs sample logs against detection rules to validate detections.

### 6. MITRE ATT&CK
Shows which techniques are covered by the detection library.

## Current Engine Flow

Sample Logs
→ Collector
→ Parser
→ YAML Detection Rules
→ Risk Scoring
→ Alert Generation
→ Dashboard

## Portfolio Goals

- Polished README
- Screenshots
- MITRE mappings
- Sample logs
- Test cases
- Clear Git commit history
- Streamlit GUI
- Docker support later