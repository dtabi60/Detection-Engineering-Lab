# Suspicious PowerShell Execution Flags

## Overview

This detection identifies PowerShell executions using suspicious command-line flags commonly associated with defense evasion, script execution, and payload staging.

## MITRE ATT&CK Mapping

- Technique: T1059.001
- Name: Command and Scripting Interpreter: PowerShell
- Tactic: Execution

## Detection Logic

The detection looks for PowerShell command lines containing:

- `-NoProfile`
- `-nop`
- `-ExecutionPolicy Bypass`
- `-EncodedCommand`
- `-enc`
- `-WindowStyle Hidden`

## Risk Scoring

| Indicator | Score |
|---|---:|
| `-EncodedCommand` | 40 |
| `-enc` | 40 |
| `-ExecutionPolicy Bypass` | 30 |
| `-WindowStyle Hidden` | 25 |
| `-NoProfile` | 10 |
| `-nop` | 10 |

## False Positives

Possible legitimate activity may include:

- IT administration scripts
- Software deployment tools
- Security testing
- Automation scripts

## SOC Value

This detection helps identify suspicious PowerShell execution patterns that may indicate script-based execution, defense evasion, or malware staging.