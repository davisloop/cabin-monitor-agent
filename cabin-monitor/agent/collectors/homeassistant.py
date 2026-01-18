"""
Home Assistant data collector.

Collects telemetry data from Home Assistant via WebSocket API:
- Entity states
- Events
- System metrics
"""
import asyncio
import aiohttp
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import psutil

logger = logging.getLogger(__name__)


class HomeAssistantCollectorError(Exception):
    """Home Assistant collector error."""
    pass


class HomeAssistantCollector:
    """
    Collects telemetry data from Home Assistant.

    Uses the Home Assistant WebSocket API for real-time data collection.
    """

    def __init__(
        self,
        ha_url: str,
        ha_token: str,
        verify_ssl: bool = True
    ):
        """
        Initialize Home Assistant collector.

        Args:
            ha_url: Home Assistant URL (e.g., http://homeassistant.local:8123)
            ha_token: Long-lived access token
            verify_ssl: Whether to verify SSL certificates (default True)
        """
        self.ha_url = ha_url.rstrip('/')
        self.ha_token = ha_token
        self.verify_ssl = verify_ssl

    async def get_all_states(self) -> Dict[str, Any]:
        """
        Get current states of all entities.

        Returns:
            Dict mapping entity_id to state info:
                {
                    "entity_id": {
                        "state": str,
                        "attributes": dict,
                        "last_changed": str,
                        "last_updated": str
                    }
                }

        Raises:
            HomeAssistantCollectorError: If data collection fails
        """
        url = f"{self.ha_url}/api/states"
        headers = {
            "Authorization": f"Bearer {self.ha_token}",
            "Content-Type": "application/json"
        }

        try:
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        states_list = await response.json()

                        # Convert list to dict keyed by entity_id
                        states_dict = {}
                        for state in states_list:
                            entity_id = state.get("entity_id")
                            if entity_id:
                                states_dict[entity_id] = {
                                    "state": state.get("state"),
                                    "attributes": state.get("attributes", {}),
                                    "last_changed": state.get("last_changed"),
                                    "last_updated": state.get("last_updated")
                                }

                        logger.debug(f"Collected {len(states_dict)} entity states")
                        return states_dict

                    else:
                        text = await response.text()
                        raise HomeAssistantCollectorError(
                            f"Failed to get states: HTTP {response.status}: {text}"
                        )

        except aiohttp.ClientError as e:
            raise HomeAssistantCollectorError(f"Network error collecting states: {e}")

    async def get_events(self, event_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Get recent events from Home Assistant.

        Note: This is a placeholder. The Home Assistant API doesn't provide
        a simple "get recent events" endpoint. In practice, you would either:
        1. Subscribe to events via WebSocket and buffer them
        2. Query the recorder database
        3. Use a custom integration

        For now, this returns an empty list.

        Args:
            event_types: Optional list of event types to filter

        Returns:
            List of event dicts
        """
        # TODO: Implement event collection via WebSocket subscription
        # For Phase 6, we'll focus on state collection
        logger.debug("Event collection not yet implemented")
        return []

    def get_system_metrics(self) -> Dict[str, float]:
        """
        Get system metrics from the host running the agent.

        Returns:
            Dict with system metrics:
                {
                    "cpu_percent": float,
                    "memory_percent": float,
                    "disk_percent": float,
                    "uptime_seconds": float
                }
        """
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)

            # Memory usage
            mem = psutil.virtual_memory()
            memory_percent = mem.percent

            # Disk usage (root partition)
            disk = psutil.disk_usage('/')
            disk_percent = disk.percent

            # System uptime
            uptime_seconds = datetime.now().timestamp() - psutil.boot_time()

            metrics = {
                "cpu_percent": round(cpu_percent, 2),
                "memory_percent": round(memory_percent, 2),
                "disk_percent": round(disk_percent, 2),
                "uptime_seconds": round(uptime_seconds, 2)
            }

            logger.debug(f"Collected system metrics: {metrics}")
            return metrics

        except Exception as e:
            logger.warning(f"Failed to collect system metrics: {e}")
            return {}

    async def collect_telemetry(
        self,
        include_system_metrics: bool = True
    ) -> Dict[str, Any]:
        """
        Collect complete telemetry payload.

        Args:
            include_system_metrics: Whether to include system metrics (default True)

        Returns:
            Telemetry dict ready for server submission:
                {
                    "states": dict,
                    "events": list,
                    "system_metrics": dict
                }

        Raises:
            HomeAssistantCollectorError: If collection fails
        """
        # Collect states
        states = await self.get_all_states()

        # Collect events (placeholder for now)
        events = await self.get_events()

        # Collect system metrics
        system_metrics = {}
        if include_system_metrics:
            system_metrics = self.get_system_metrics()

        return {
            "states": states,
            "events": events,
            "system_metrics": system_metrics
        }


def create_device_info(
    hostname: Optional[str] = None,
    ha_version: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create device info dict for enrollment.

    Args:
        hostname: Device hostname (optional, auto-detected if not provided)
        ha_version: Home Assistant version (optional)

    Returns:
        Device info dict:
            {
                "hostname": str,
                "arch": str,
                "ha_version": str,
                "additional_info": dict
            }
    """
    import platform
    import socket

    if hostname is None:
        hostname = socket.gethostname()

    # Get architecture
    arch = platform.machine()

    # Platform info
    additional_info = {
        "platform": platform.system(),
        "platform_version": platform.version(),
        "python_version": platform.python_version()
    }

    return {
        "hostname": hostname,
        "arch": arch,
        "ha_version": ha_version or "unknown",
        "additional_info": additional_info
    }
