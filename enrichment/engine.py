import json
from pathlib import Path

from enrichment.otx import OTXProvider

OUTPUT_FILE = Path("data/threat_intel_results.json")


def get_enabled_providers():
    return [
        OTXProvider(),
    ]


def summarize_sources(sources: list) -> dict:
    summary = {
        "malicious_sources": 0,
        "suspicious_sources": 0,
        "benign_sources": 0,
        "unknown_sources": 0,
        "unsupported_sources": 0,
        "error_sources": 0,
        "max_confidence": 0,
    }

    for source in sources:
        status = source.get("status", "unknown")
        verdict = source.get("verdict", "unknown")
        confidence = source.get("confidence", 0)

        summary["max_confidence"] = max(summary["max_confidence"], confidence)

        if status == "unsupported":
            summary["unsupported_sources"] += 1
        elif status == "error":
            summary["error_sources"] += 1
        elif verdict == "malicious":
            summary["malicious_sources"] += 1
        elif verdict == "suspicious":
            summary["suspicious_sources"] += 1
        elif verdict == "benign":
            summary["benign_sources"] += 1
        else:
            summary["unknown_sources"] += 1

    return summary


def enrich_observable(value: str, observable_type: str = "ip") -> dict:
    providers = get_enabled_providers()
    sources = []

    for provider in providers:
        if observable_type == "ip":
            sources.append(provider.lookup_ip(value))
        elif observable_type == "hash":
            sources.append(provider.lookup_hash(value))
        elif observable_type == "domain":
            sources.append(provider.lookup_domain(value))
        elif observable_type == "url":
            sources.append(provider.lookup_url(value))
        else:
            sources.append({
                "source": provider.name,
                "status": "unsupported",
                "verdict": "unknown",
                "confidence": 0,
                "summary": f"Unsupported observable type: {observable_type}",
                "details": {}
            })

    result = {
        "observable": value,
        "observable_type": observable_type,
        "sources": sources,
        "summary": summarize_sources(sources)
    }

    OUTPUT_FILE.write_text(json.dumps(result, indent=4, default=str))
    return result


if __name__ == "__main__":
    output = enrich_observable("8.8.8.8", "ip")
    print(json.dumps(output, indent=4))