from abc import ABC, abstractmethod


class ThreatIntelProvider(ABC):
    name = "BaseProvider"

    def lookup_ip(self, ip: str) -> dict:
        return {
            "source": self.name,
            "status": "unsupported",
            "verdict": "unknown",
            "confidence": 0,
            "summary": f"{self.name} does not support IP lookup.",
            "details": {}
        }

    def lookup_hash(self, file_hash: str) -> dict:
        return {
            "source": self.name,
            "status": "unsupported",
            "verdict": "unknown",
            "confidence": 0,
            "summary": f"{self.name} does not support hash lookup.",
            "details": {}
        }

    def lookup_domain(self, domain: str) -> dict:
        return {
            "source": self.name,
            "status": "unsupported",
            "verdict": "unknown",
            "confidence": 0,
            "summary": f"{self.name} does not support domain lookup.",
            "details": {}
        }

    def lookup_url(self, url: str) -> dict:
        return {
            "source": self.name,
            "status": "unsupported",
            "verdict": "unknown",
            "confidence": 0,
            "summary": f"{self.name} does not support URL lookup.",
            "details": {}
        }