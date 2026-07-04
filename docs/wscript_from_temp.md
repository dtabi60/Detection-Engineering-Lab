# Wscript From Temp

## Overview

Detects WScript executing Visual Basic scripts from temporary directories.

## MITRE ATT&CK Mapping

- Technique: T1059.005
- Name: Visual Basic
- Tactic: Execution

## Detection Logic

- `wscript.exe` — Score: 25
- `Temp` — Score: 25
- `.vbs` — Score: 20

## False Positives

- Administrative activity
- Security testing
