import os
import requests

from enrichment.base import ThreatIntelProvider
from enrichment.models import TIResult, error_result, unknown_result


class OTXProvider(ThreatIntelProvider):
    name = "OTX"

    def __init__(self):
        self.api_key = os.getenv("OTX_API_KEY")

    def lookup_ip(self, ip: str) -> dict:
        if not self.api_key:
            return unknown_result(self.name, "OTX_API_KEY is not configured.")

        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.api_key}

        try:
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code != 200:
                return error_result(self.name, f"HTTP {response.status_code}: {response.text}")

            data = response.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)

            if pulse_count > 0:
                verdict = "suspicious"
                confidence = min(100, pulse_count * 10)
                summary = f"OTX found this IP in {pulse_count} pulse(s)."
            else:
                verdict = "unknown"
                confidence = 0
                summary = "OTX did not find pulses for this IP."

            return TIResult(
                source=self.name,
                status="success",
                verdict=verdict,
                confidence=confidence,
                summary=summary,
                details={
                    "pulse_count": pulse_count,
                    "indicator": data.get("indicator"),
                    "type": data.get("type"),
                    "country_code": data.get("country_code"),
                    "asn": data.get("asn"),
                }
            ).to_dict()

        except Exception as e:
            return error_result(self.name, str(e))