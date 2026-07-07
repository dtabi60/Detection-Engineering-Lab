import requests

API_BASE_URL = "http://127.0.0.1:8000"


def get_alerts():
    response = requests.get(f"{API_BASE_URL}/api/v1/alerts/")
    response.raise_for_status()
    return response.json()


def get_alert_details(alert_id: str):
    response = requests.get(f"{API_BASE_URL}/api/v1/alerts/{alert_id}")
    response.raise_for_status()
    return response.json()


def get_storyline(storyline_id: str):
    response = requests.get(f"{API_BASE_URL}/api/v1/storylines/{storyline_id}")
    response.raise_for_status()
    return response.json()


def get_process_tree(process_guid: str):
    response = requests.get(f"{API_BASE_URL}/api/v1/process-tree/{process_guid}")
    response.raise_for_status()
    return response.json()


def get_response_actions(alert_id: str):
    response = requests.get(f"{API_BASE_URL}/api/v1/response-actions/{alert_id}")
    response.raise_for_status()
    return response.json()


def create_response_action(host_id: str, alert_id: str, action_type: str, target_identifier: str):
    payload = {
        "host_id": host_id,
        "alert_id": alert_id,
        "action_type": action_type,
        "target_identifier": target_identifier,
    }

    response = requests.post(
        f"{API_BASE_URL}/api/v1/response-actions/",
        json=payload,
    )
    response.raise_for_status()
    return response.json()