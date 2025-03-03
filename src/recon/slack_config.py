from fastapi import FastAPI 
import requests

#security alert : hardcoded endpoint
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"
def send_slack_message(message):
    """Send a message to Slack using Webhook."""
    payload = {"text": message}
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, headers=headers)
        response.raise_for_status()  # Raise an error for failed requests
        print("[+] Message sent successfully!")
    except requests.exceptions.RequestException as e:
        print(f"[-] Failed to send message: {e}")