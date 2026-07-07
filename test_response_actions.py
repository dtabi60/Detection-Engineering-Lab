from storage.response_actions import log_response_action, get_response_actions

alert_id = input("Enter alert ID: ")

log_response_action(
    alert_id=alert_id,
    action_type="Isolate Host",
    target="local_endpoint",
    notes="Simulated isolation for testing."
)

actions = get_response_actions(alert_id)

for action in actions:
    print(action)