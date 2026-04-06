Overview
This repository provides an enterprise-grade, highly secure custom integration for the Wazuh SIEM platform (v4.14 and above). Designed for modern Security Operations Centers (SOCs), this integration bridges the gap between Wazuh's robust correlation engine (wazuh-analysisd) and rapid incident response teams by forwarding critical security alerts in real-time to any specified Telegram Chat or Group.

Unlike simplistic implementations, this integration is engineered to prioritize host operating system stability and data security. By isolating its dependencies within a dedicated Python Virtual Environment (venv) and dynamically ingesting API credentials directly from the Wazuh configuration interface (ossec.conf), the integration ensures that no sensitive secrets are hardcoded in the executable logic.

Architectural Highlights
Real-Time Out-of-Band Alerting: Immediate push notifications to mobile or desktop devices, significantly reducing the Mean Time to Respond (MTTR).
Dependency Compartmentalization: Operates entirely within a dedicated /var/ossec/venv environment, safeguarding the host OS's native Python interpreter from third-party library conflicts.
Dynamic Secrets Ingestion: Avoids hardcoded credentials. Telegram BOT_TOKEN and CHAT_ID are securely passed as arguments by the wazuh-integratord daemon.
Context-Rich Output: Intelligently extracts actionable intelligence from complex JSON payloads, including Rule IDs, severity levels, contextual descriptions, agent identifiers, network IoCs (Source IPs), and truncated raw logs to comply with Telegram's payload limits.
Strict Access Controls: Enforces rigid permission boundaries (root:wazuh, chmod 750) to eliminate local privilege escalation vectors.
Prerequisites and Requirements
Before deploying the integration into a production environment, ensure the following preconditions are met on the host running the Wazuh Manager:

System Requirements:
Wazuh Manager installed and operational (v4.14 or newer).
Administrative (root) privileges on the host server.
Python 3 installed natively on the system.
Network Requirements:
The Wazuh Manager must have outbound internet connectivity (HTTPS over port 443) to reach https://api.telegram.org.
Telegram Bot Credentials:
A valid Bot Token (provisioned via the @BotFather interface on Telegram).
A valid Chat ID (the unique numeric identifier for the target user or channel).
How to obtain your Telegram Credentials
Provision the Bot: Open the Telegram application, search for the official @BotFather account, and initiate a chat. Send the /newbot command and follow the interactive prompts to define a display name and username. @BotFather will generate an HTTP API Token (e.g., 123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11). Store this token in a secure password manager.
Acquire the Chat ID: Add the newly provisioned bot to the target Telegram group (or send it a direct message). To retrieve the exact Chat ID, query the Telegram API by visiting the following URL in your browser: https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates Search the resulting JSON response for the "chat":{"id":-100123456789} field. (Note: Group IDs typically start with a minus sign -).
Installation and Deployment Guide
The deployment process follows strict security conventions. All commands provided below must be executed in a terminal session with root privileges.

Step 1: Initialize the Python Virtual Environment
To prevent library conflicts, initialize a dedicated virtual environment for Wazuh integrations and install the external requests library.

# Provision the virtual environment directory
mkdir -p /var/ossec/venv

# Initialize the virtual environment natively
python3 -m venv /var/ossec/venv

# Activate the environment context and install dependencies
source /var/ossec/venv/bin/activate
pip install requests

# Deactivate the context to return to the system shell
deactivate

Step 2: Deploy the Executable Logic and Wrapper
The integration requires two distinct components: the primary Python logic script and a Bash wrapper to facilitate execution by the Wazuh Integrator daemon.

1. Provision the Python Script:

Create the primary Python executable file:

nano /var/ossec/integrations/custom-telegram.py

Insert the refactored code below. Note that unlike legacy implementations, you do not need to hardcode your tokens here. The script is designed to dynamically accept credentials from the Wazuh manager.

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

2. Provision the Bash Wrapper:

Wazuh natively demands that the executable matches the exact string defined in the XML configuration. Create the Bash wrapper to route execution through the virtual environment:

nano /var/ossec/integrations/custom-telegram

Insert the following bridge logic:

#!/bin/bash
# Passes all received arguments ($@) directly into the isolated Python environment
/var/ossec/venv/bin/python3 /var/ossec/integrations/custom-telegram.py "$@"

Step 3: Enforce Cryptographic and Access Permissions
To mitigate Local Privilege Escalation (LPE) vulnerabilities, the scripts must be locked down to the wazuh execution group.

Execute the following hardening commands:

chown root:wazuh /var/ossec/integrations/custom-telegram*
chmod 750 /var/ossec/integrations/custom-telegram*

Step 4: Configure Wazuh (ossec.conf)
Instruct the Wazuh Manager to utilize the deployed integration. Edit the global configuration:

nano /var/ossec/etc/ossec.conf

1. Enable JSON Telemetry Output: Verify that JSON output and alert logging are activated within the <global> block:

<global>
...
 <jsonout_output>yes</jsonout_output>
 <alerts_log>yes</alerts_log>
 <logall>yes</logall>
 <logall_json>yes</logall_json>
...
</global>

2. Inject the Integration Block: Append the following configuration block into the file (typically before the closing </ossec_config> tag). This is where you define your secrets.

Replace YOUR_BOT_TOKEN_HERE and YOUR_CHAT_ID_HERE with your actual Telegram parameters.

<integration>
 <name>custom-telegram</name>
 <level>10</level>
 <hook_url>YOUR_CHAT_ID_HERE</hook_url>
 <api_key>YOUR_BOT_TOKEN_HERE</api_key>
 <alert_format>json</alert_format>
</integration>

Architecture Warning: Filtering alerts via <level>10</level> or filtering by specific <group> tags is strongly advised. Setting a low threshold (e.g., Level 1 or 3) will result in alert flooding, rapidly exhausting Telegram's API rate limits (HTTP 429 errors).

Step 5: Service Initialization
To instantiate the configuration changes, restart the Wazuh management daemon:

systemctl restart wazuh-manager

Auditing and Troubleshooting
Log Analysis
If integration events are failing to populate in the Telegram interface, monitor the primary integration log stream for stack traces or HTTP errors:

tail -f /var/ossec/logs/integrations.log

To verify the internal state of the wazuh-integratord subsystem:

grep -i "integratord" /var/ossec/logs/ossec.log

Uninstallation Routine
To completely purge the integration from the infrastructure:

Strip the <integration> block from /var/ossec/etc/ossec.conf.
Cycle the daemon: systemctl restart wazuh-manager.
Destroy the executables: rm -f /var/ossec/integrations/custom-telegram*
(Optional) Purge the virtual environment if no other custom modules depend on it: rm -rf /var/ossec/venv
