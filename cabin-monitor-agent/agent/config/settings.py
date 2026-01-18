"""
Agent configuration management.

Loads configuration from:
1. Environment variables
2. Configuration file (YAML/TOML)
3. Defaults
"""
import os
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)


@dataclass
class ServerConfig:
    """Server connection configuration."""
    url: str
    verify_ssl: bool = True
    timeout: int = 30


@dataclass
class HomeAssistantConfig:
    """Home Assistant configuration."""
    url: str
    token: str
    verify_ssl: bool = True


@dataclass
class CertificateConfig:
    """Certificate configuration."""
    cert_dir: Path
    renew_days: int = 30
    key_password: Optional[str] = None


@dataclass
class TelemetryConfig:
    """Telemetry collection configuration."""
    upload_interval_sec: int = 60
    include_system_metrics: bool = True
    retry_attempts: int = 3
    retry_delay_sec: int = 5


@dataclass
class AgentConfig:
    """Complete agent configuration."""
    # Identity
    site_id: str
    device_id: Optional[str] = None

    # Server
    server: ServerConfig = field(default_factory=lambda: ServerConfig(url=""))

    # Home Assistant
    homeassistant: Optional[HomeAssistantConfig] = None

    # Certificates
    certificate: CertificateConfig = field(
        default_factory=lambda: CertificateConfig(cert_dir=Path("./certs"))
    )

    # Telemetry
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)

    # Enrollment
    enrollment_token: Optional[str] = None

    # Logging
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """
        Load configuration from environment variables.

        Environment variables:
            CABINMONITOR_SITE_ID: Site identifier (required)
            CABINMONITOR_DEVICE_ID: Device identifier (optional, set after enrollment)
            CABINMONITOR_SERVER_URL: Server URL (required)
            CABINMONITOR_SERVER_VERIFY_SSL: Verify SSL (default: true)
            CABINMONITOR_HA_URL: Home Assistant URL (required)
            CABINMONITOR_HA_TOKEN: Home Assistant long-lived token (required)
            CABINMONITOR_HA_VERIFY_SSL: Verify HA SSL (default: true)
            CABINMONITOR_CERT_DIR: Certificate directory (default: ./certs)
            CABINMONITOR_CERT_RENEW_DAYS: Days before expiry to renew (default: 30)
            CABINMONITOR_UPLOAD_INTERVAL: Upload interval in seconds (default: 60)
            CABINMONITOR_ENROLLMENT_TOKEN: One-time enrollment token (optional)
            CABINMONITOR_LOG_LEVEL: Log level (default: INFO)

        Returns:
            AgentConfig instance

        Raises:
            ValueError: If required config is missing
        """
        # Required fields
        site_id = os.getenv("CABINMONITOR_SITE_ID")
        if not site_id:
            raise ValueError("CABINMONITOR_SITE_ID environment variable is required")

        server_url = os.getenv("CABINMONITOR_SERVER_URL")
        if not server_url:
            raise ValueError("CABINMONITOR_SERVER_URL environment variable is required")

        ha_url = os.getenv("CABINMONITOR_HA_URL")
        ha_token = os.getenv("CABINMONITOR_HA_TOKEN")

        # Optional fields with defaults
        device_id = os.getenv("CABINMONITOR_DEVICE_ID")
        server_verify_ssl = os.getenv("CABINMONITOR_SERVER_VERIFY_SSL", "true").lower() == "true"
        ha_verify_ssl = os.getenv("CABINMONITOR_HA_VERIFY_SSL", "true").lower() == "true"
        cert_dir = Path(os.getenv("CABINMONITOR_CERT_DIR", "./certs"))
        cert_renew_days = int(os.getenv("CABINMONITOR_CERT_RENEW_DAYS", "30"))
        upload_interval = int(os.getenv("CABINMONITOR_UPLOAD_INTERVAL", "60"))
        enrollment_token = os.getenv("CABINMONITOR_ENROLLMENT_TOKEN")
        log_level = os.getenv("CABINMONITOR_LOG_LEVEL", "INFO")

        # Build configuration
        config = cls(
            site_id=site_id,
            device_id=device_id,
            server=ServerConfig(
                url=server_url,
                verify_ssl=server_verify_ssl
            ),
            certificate=CertificateConfig(
                cert_dir=cert_dir,
                renew_days=cert_renew_days
            ),
            telemetry=TelemetryConfig(
                upload_interval_sec=upload_interval
            ),
            enrollment_token=enrollment_token,
            log_level=log_level
        )

        # Add Home Assistant config if provided
        if ha_url and ha_token:
            config.homeassistant = HomeAssistantConfig(
                url=ha_url,
                token=ha_token,
                verify_ssl=ha_verify_ssl
            )

        return config

    def validate(self) -> None:
        """
        Validate configuration.

        Raises:
            ValueError: If configuration is invalid
        """
        if not self.site_id:
            raise ValueError("site_id is required")

        if not self.server.url:
            raise ValueError("server.url is required")

        if self.telemetry.upload_interval_sec < 10:
            raise ValueError("telemetry.upload_interval_sec must be at least 10 seconds")

        if self.certificate.renew_days < 1:
            raise ValueError("certificate.renew_days must be at least 1")

    def save_device_id(self, device_id: str) -> None:
        """
        Save device_id to environment for persistence.

        Note: This saves to a .env file in the current directory.
        For production, use proper secret management.

        Args:
            device_id: Device identifier from enrollment
        """
        self.device_id = device_id

        env_file = Path(".env")
        lines = []

        # Read existing .env if present
        if env_file.exists():
            with open(env_file, 'r') as f:
                lines = f.readlines()

        # Update or add DEVICE_ID
        updated = False
        for i, line in enumerate(lines):
            if line.startswith("CABINMONITOR_DEVICE_ID="):
                lines[i] = f"CABINMONITOR_DEVICE_ID={device_id}\n"
                updated = True
                break

        if not updated:
            lines.append(f"CABINMONITOR_DEVICE_ID={device_id}\n")

        # Write back
        with open(env_file, 'w') as f:
            f.writelines(lines)

        logger.info(f"Saved device_id to {env_file}")


def setup_logging(log_level: str = "INFO") -> None:
    """
    Setup logging configuration.

    Args:
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
