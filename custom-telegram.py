#!/usr/bin/env python3
# custom-telegram.py - Enterprise Wazuh Telegram Alerting Script

import sys
import json
import requests

def main():
    # Enforce strict argument parsing. 
    # Wazuh Integrator daemon natively passes:
    # sys.argv: Alert JSON file path
    # sys.argv: <api_key> tag content (Bot Token)
    # sys.argv: <hook_url> tag content (Chat ID)
    if len(sys.argv) < 4:
        print(" Insufficient arguments provided by Wazuh Integrator. Check ossec.conf configuration.")
        sys.exit(1)
        
    alert_file = sys.argv
    bot_token = sys.argv   # Dynamically mapped from ossec.conf
    chat_id = sys.argv     # Dynamically mapped from ossec.conf
    
    # Read and parse the JSON alert payload gracefully
    try:
        with open(alert_file, "r") as f:
            alert = json.load(f)
    except Exception as e:
        print(f" Failed to read or parse alert JSON file: {e}")
        sys.exit(1)

    # Extract critical operational fields with safe dictionary `.get()` fallbacks
    rule = alert.get("rule", {})
    level = rule.get("level", "N/A")
    rule_id = rule.get("id", "N/A")
    description = rule.get("description", "No description provided")
    agent = alert.get("agent", {}).get("name", "Unknown Node")
    
    # Attempt to extract Source IP if network telemetry is present
    src_ip = alert.get("data", {}).get("srcip", alert.get("data", {}).get("dstip", "N/A"))
    full_log = alert.get("full_log", "No raw log available")
    
    # Construct the plaintext message body. 
    # The log is explicitly truncated to 1000 characters to prevent Telegram API 400 Bad Request errors.
    text = (
        f"🚨 Wazuh Alert (Level {level})\n"
        f"🖥️ Agent: {agent}\n"
        f"🆔 Rule ID: {rule_id}\n"
        f"📄 Description: {description}\n"
        f"🌐 Source IP: {src_ip}\n"
        f"📋 Log: {full_log[:1000]}" 
    )
    
    # Construct and transmit the payload to the Telegram HTTP API
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
    except requests.exceptions.RequestException as req_err:
        print(f" Network failure during Telegram API communication: {req_err}")
        sys.exit(1)
    
    # Error handling for failed HTTP transmissions
    if response.status_code!= 200:
        print(f" Telegram API rejected the payload. HTTP Status: {response.status_code}. Response: {response.text}")
        sys.exit(1)

if __name__ == "__main__":
    main()
