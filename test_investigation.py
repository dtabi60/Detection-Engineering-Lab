from storage.investigation import get_all_alerts, get_alert_investigation

alerts = get_all_alerts()

for alert in alerts:
    print(f"{alert['id']} | {alert['hostname']} | {alert['alert_name']} | {alert['severity']}")

alert_id = input("\nEnter alert ID to investigate: ")

investigation = get_alert_investigation(alert_id)

print(investigation)