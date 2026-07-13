"""
Response Module for Project Sentinel.
Handles automated remediation via the Wazuh API.

Guardrails:
- SOAR_MODE=AUDIT (default) logs actions without executing them.
- Private/reserved/loopback IPs and any IP listed in SOAR_PROTECTED_IPS
  are never blocked (prevents prompt-injected self-DoS on gateway/DNS).
- At most SOAR_MAX_ACTIONS_PER_HOUR actions execute per rolling hour.
- ISOLATE_HOST requires explicit opt-in via SOAR_ALLOW_ISOLATE=true.
"""
import ipaddress
import requests
import logging
import os
import time
from collections import deque
from typing import Dict, Any, Optional
from config import logger

class WazuhResponseManager:
    def __init__(self):
        self.base_url = os.getenv("WAZUH_API_URL")
        self.user = os.getenv("WAZUH_API_USER")
        self.password = os.getenv("WAZUH_API_PASS")
        # Wazuh ships with a self-signed cert by default; set
        # WAZUH_API_VERIFY_SSL to a CA bundle path or "false" as needed.
        verify_env = os.getenv("WAZUH_API_VERIFY_SSL", "true")
        if verify_env.lower() in ("true", "1", "yes"):
            self.verify = True
        elif verify_env.lower() in ("false", "0", "no"):
            self.verify = False
        else:
            self.verify = verify_env  # CA bundle path
        self.token = None
        self.max_actions_per_hour = int(os.getenv("SOAR_MAX_ACTIONS_PER_HOUR", 5))
        self._action_times = deque()
        protected = os.getenv("SOAR_PROTECTED_IPS", "")
        self.protected_ips = {ip.strip() for ip in protected.split(",") if ip.strip()}

    def _authenticate(self) -> bool:
        """Authenticates with the Wazuh API and retrieves a token."""
        if not all([self.base_url, self.user, self.password]):
            logger.warning("Wazuh API credentials not fully configured.")
            return False

        try:
            auth_url = f"{self.base_url}/security/user/authenticate"
            response = requests.get(
                auth_url, auth=(self.user, self.password),
                verify=self.verify, timeout=15
            )
            response.raise_for_status()
            self.token = response.json().get('data', {}).get('token')
            return bool(self.token)
        except Exception as e:
            logger.error(f"Wazuh API Authentication failed: {e}")
            return False

    def _request_with_reauth(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Sends an authenticated request; on 401 (expired token, default
        TTL ~15 min) re-authenticates once and retries."""
        for attempt in range(2):
            if not self.token and not self._authenticate():
                return None
            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.request(
                method, url, headers=headers,
                verify=self.verify, timeout=15, **kwargs
            )
            if response.status_code == 401 and attempt == 0:
                logger.info("Wazuh API token expired. Re-authenticating...")
                self.token = None
                continue
            return response
        return None

    def _is_blockable_ip(self, ip: str) -> bool:
        """Rejects targets whose blocking could take down the network itself."""
        if ip in self.protected_ips:
            logger.warning(f"GUARDRAIL: {ip} is in SOAR_PROTECTED_IPS. Refusing to block.")
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            logger.warning(f"GUARDRAIL: '{ip}' is not a valid IP address. Refusing to block.")
            return False
        if addr.is_private or addr.is_loopback or addr.is_link_local \
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified:
            logger.warning(f"GUARDRAIL: {ip} is private/reserved. Refusing to block.")
            return False
        return True

    def _within_rate_limit(self) -> bool:
        """Caps executed actions per rolling hour."""
        now = time.time()
        while self._action_times and now - self._action_times[0] > 3600:
            self._action_times.popleft()
        if len(self._action_times) >= self.max_actions_per_hour:
            logger.warning(
                f"GUARDRAIL: SOAR action cap reached "
                f"({self.max_actions_per_hour}/hour). Action skipped."
            )
            return False
        return True

    def execute_action(self, action_type: str, target: str, agent_id: str, reasoning: str) -> bool:
        """
        Executes a remediation action based on AI recommendations.

        Args:
            action_type (str): Type of action (e.g., BLOCK_IP, ISOLATE_HOST).
            target (str): The target identifier (IP address or agent ID).
            agent_id (str): The Wazuh agent ID where the action should execute.
            reasoning (str): The AI-provided justification for the action.
        """
        logger.info(f"SOAR ACTION REQUESTED: {action_type} on {target} (Agent {agent_id}) - Reason: {reasoning}")

        # Guardrails apply in every mode so AUDIT logs reflect what
        # ENFORCE would actually do.
        if action_type == "BLOCK_IP" and not self._is_blockable_ip(target):
            return False
        if action_type == "ISOLATE_HOST" and os.getenv("SOAR_ALLOW_ISOLATE", "false").lower() != "true":
            logger.warning("GUARDRAIL: ISOLATE_HOST requires SOAR_ALLOW_ISOLATE=true. Action skipped.")
            return False

        # Security Guardrail: Check SOAR_MODE before execution
        if os.getenv("SOAR_MODE", "AUDIT") == "AUDIT":
            logger.info("SOAR_MODE is AUDIT. Action logged but not executed.")
            return True

        if not self._within_rate_limit():
            return False

        # Action Router
        if action_type == "BLOCK_IP":
            executed = self._block_ip(agent_id, target)
        elif action_type == "ISOLATE_HOST":
            executed = self._isolate_host(agent_id)
        else:
            logger.warning(f"Unknown action type: {action_type}")
            return False

        if executed:
            self._action_times.append(time.time())
        return executed

    def _block_ip(self, agent_id: str, ip: str) -> bool:
        """
        Triggers a firewall-drop active response via Wazuh API.
        Uses the standard 'firewall-drop' command available in Wazuh.
        """
        try:
            url = f"{self.base_url}/active-response?agents_list={agent_id}"
            # Command must match an <active-response> command on the manager;
            # override via WAZUH_AR_COMMAND (prefix with '!' to run a script
            # by name on Wazuh >= 4.2). firewall-drop reads the target from
            # alert.data.srcip.
            payload = {
                "command": os.getenv("WAZUH_AR_COMMAND", "firewall-drop"),
                "arguments": [ip],
                "alert": {"data": {"srcip": ip}}
            }
            response = self._request_with_reauth("PUT", url, json=payload)
            if response is None:
                logger.error("BLOCK_IP aborted: could not authenticate with Wazuh API.")
                return False
            response.raise_for_status()
            logger.info(f"Successfully triggered BLOCK_IP for {ip} on agent {agent_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to trigger BLOCK_IP: {e}")
            return False

    def _isolate_host(self, agent_id: str) -> bool:
        """Host isolation is not implemented — reports failure honestly
        instead of pretending the host was contained."""
        logger.error(
            f"ISOLATE_HOST requested for agent {agent_id} but this action is "
            f"NOT IMPLEMENTED. No containment was performed."
        )
        return False

if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    manager = WazuhResponseManager()
    # manager.execute_action("BLOCK_IP", "1.2.3.4", "001", "Testing")
