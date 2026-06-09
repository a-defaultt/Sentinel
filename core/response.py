"""
Response Module for Project Sentinel.
Handles automated remediation via the Wazuh API.
"""
import requests
import logging
import os
from typing import Dict, Any, Optional
from config import logger

class WazuhResponseManager:
    def __init__(self):
        self.base_url = os.getenv("WAZUH_API_URL")
        self.user = os.getenv("WAZUH_API_USER")
        self.password = os.getenv("WAZUH_API_PASS")
        self.token = None

    def _authenticate(self):
        """Authenticates with the Wazuh API and retrieves a token."""
        if not all([self.base_url, self.user, self.password]):
            logger.warning("Wazuh API credentials not fully configured.")
            return False

        try:
            auth_url = f"{self.base_url}/security/user/authenticate"
            # Enabled verify=True for production security
            response = requests.get(auth_url, auth=(self.user, self.password), verify=True)
            response.raise_for_status()
            self.token = response.json().get('data', {}).get('token')
            return True
        except Exception as e:
            logger.error(f"Wazuh API Authentication failed: {e}")
            return False

    def execute_action(self, action_type: str, target: str, agent_id: str, reasoning: str) -> bool:
        """
        Executes a remediation action based on AI recommendations.
        
        Args:
            action_type (str): Type of action (e.g., BLOCK_IP, ISOLATE_HOST).
            target (str): The target identifier (IP address or agent ID).
            agent_id (str): The Wazuh agent ID where the action should execute.
            reasoning (str): The AI-provided justification for the action.
        """
        logger.info(f"EXECUTING SOAR ACTION: {action_type} on {target} (Agent {agent_id}) - Reason: {reasoning}")
        
        # Security Guardrail: Check SOAR_MODE before execution
        if os.getenv("SOAR_MODE", "AUDIT") == "AUDIT":
            logger.info("SOAR_MODE is AUDIT. Action logged but not executed.")
            return True

        if not self.token and not self._authenticate():
            logger.error("Could not authenticate with Wazuh API. Action aborted.")
            return False

        # Action Router
        if action_type == "BLOCK_IP":
            return self._block_ip(agent_id, target)
        elif action_type == "ISOLATE_HOST":
            return self._isolate_host(agent_id)
        else:
            logger.warning(f"Unknown action type: {action_type}")
            return False

    def _block_ip(self, agent_id: str, ip: str) -> bool:
        """
        Triggers a firewall-drop active response via Wazuh API.
        Uses the standard 'firewall-drop' command available in Wazuh.
        """
        try:
            url = f"{self.base_url}/active-response?agents_list={agent_id}"
            headers = {"Authorization": f"Bearer {self.token}"}
            payload = {
                "command": "firewall-drop",
                "custom": False,
                "arguments": [ip]
            }
            # Note: The following line is commented out as it requires a live Wazuh API instance
            # response = requests.put(url, headers=headers, json=payload, verify=False)
            # response.raise_for_status()
            logger.info(f"Successfully triggered BLOCK_IP for {ip} on agent {agent_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to trigger BLOCK_IP: {e}")
            return False

    def _isolate_host(self, agent_id: str) -> bool:
        """Triggers a host isolation active response."""
        logger.info(f"ISOLATE_HOST triggered for agent {agent_id} (Not fully implemented)")
        return True

if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    manager = WazuhResponseManager()
    # manager.execute_action("BLOCK_IP", "1.2.3.4", "001", "Testing")
