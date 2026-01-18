"""
API client for CabinMonitor server.

Handles all HTTP communication with the server:
- Enrollment
- Telemetry submission
- Certificate renewal
"""
import requests
from typing import Dict, Any, Optional, Tuple
from datetime import datetime
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class APIError(Exception):
    """API communication error."""
    def __init__(self, message: str, status_code: Optional[int] = None, details: Optional[Dict] = None):
        super().__init__(message)
        self.status_code = status_code
        self.details = details or {}


class CabinMonitorClient:
    """
    Client for CabinMonitor server API.

    Handles enrollment, telemetry, and renewal operations.
    """

    def __init__(
        self,
        server_url: str,
        verify_ssl: bool = True,
        timeout: int = 30
    ):
        """
        Initialize API client.

        Args:
            server_url: Base URL of CabinMonitor server (e.g., https://server.example.com)
            verify_ssl: Whether to verify SSL certificates (default True)
            timeout: Request timeout in seconds (default 30)
        """
        self.server_url = server_url.rstrip('/')
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        # Session for connection pooling
        self.session = requests.Session()

    def enroll_device(
        self,
        site_id: str,
        csr_pem: str,
        enrollment_token: str,
        agent_version: str,
        device_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enroll a new device.

        Args:
            site_id: Site identifier
            csr_pem: Certificate Signing Request (PEM format)
            enrollment_token: One-time enrollment token
            agent_version: Agent version string
            device_info: Device information dict with:
                - hostname: str
                - arch: str
                - ha_version: str
                - additional_info: dict (optional)

        Returns:
            Enrollment response dict with:
                - device_id: str
                - device_cert_pem: str
                - ca_chain_pem: str
                - cert_not_after: str (ISO timestamp)
                - policy: dict

        Raises:
            APIError: If enrollment fails
        """
        url = f"{self.server_url}/v1/enroll"

        payload = {
            "site_id": site_id,
            "csr_pem": csr_pem,
            "agent_version": agent_version,
            "schema_version": 1,
            "device_info": device_info
        }

        headers = {
            "Authorization": f"Bearer {enrollment_token}",
            "Content-Type": "application/json"
        }

        try:
            logger.info(f"Enrolling device at site {site_id}")
            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Enrollment successful: device_id={data['device_id']}")
                return data
            else:
                error_detail = response.text
                try:
                    error_detail = response.json().get("detail", response.text)
                except:
                    pass

                raise APIError(
                    f"Enrollment failed: {error_detail}",
                    status_code=response.status_code,
                    details={"response": response.text}
                )

        except requests.exceptions.RequestException as e:
            raise APIError(f"Network error during enrollment: {e}")

    def send_telemetry(
        self,
        payload: Dict[str, Any],
        cert_path: Path,
        key_path: Path
    ) -> Dict[str, Any]:
        """
        Send telemetry data with mTLS authentication.

        Args:
            payload: Telemetry payload dict with:
                - ts: str (ISO timestamp)
                - agent_version: str
                - schema_version: int
                - payload_id: str (UUID)
                - states: dict (optional)
                - events: list (optional)
                - system_metrics: dict (optional)
            cert_path: Path to device certificate
            key_path: Path to device private key

        Returns:
            Telemetry response dict with:
                - status: str ("ok", "partial", "error")
                - server_time: str (ISO timestamp)
                - policy: dict
                - errors: list (optional)

        Raises:
            APIError: If telemetry submission fails
        """
        url = f"{self.server_url}/v1/telemetry"

        try:
            logger.debug(f"Sending telemetry: payload_id={payload.get('payload_id')}")

            response = self.session.post(
                url,
                json=payload,
                cert=(str(cert_path), str(key_path)),
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                logger.debug(f"Telemetry sent successfully: status={data['status']}")
                return data
            else:
                error_detail = response.text
                try:
                    error_detail = response.json().get("detail", response.text)
                except:
                    pass

                raise APIError(
                    f"Telemetry submission failed: {error_detail}",
                    status_code=response.status_code,
                    details={"response": response.text}
                )

        except requests.exceptions.SSLError as e:
            raise APIError(f"SSL error during telemetry (check certificates): {e}")
        except requests.exceptions.RequestException as e:
            raise APIError(f"Network error during telemetry: {e}")

    def renew_certificate(
        self,
        csr_pem: str,
        cert_path: Path,
        key_path: Path
    ) -> Dict[str, Any]:
        """
        Renew device certificate with mTLS authentication.

        Args:
            csr_pem: New Certificate Signing Request (PEM format)
            cert_path: Path to current device certificate
            key_path: Path to current device private key

        Returns:
            Renewal response dict with:
                - device_cert_pem: str
                - cert_not_after: str (ISO timestamp)
                - ca_chain_pem: str

        Raises:
            APIError: If renewal fails
        """
        url = f"{self.server_url}/v1/renew"

        payload = {
            "csr_pem": csr_pem
        }

        try:
            logger.info("Requesting certificate renewal")

            response = self.session.post(
                url,
                json=payload,
                cert=(str(cert_path), str(key_path)),
                verify=self.verify_ssl,
                timeout=self.timeout
            )

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Certificate renewed successfully: expires={data['cert_not_after']}")
                return data
            else:
                error_detail = response.text
                try:
                    error_detail = response.json().get("detail", response.text)
                except:
                    pass

                raise APIError(
                    f"Certificate renewal failed: {error_detail}",
                    status_code=response.status_code,
                    details={"response": response.text}
                )

        except requests.exceptions.SSLError as e:
            raise APIError(f"SSL error during renewal (check certificates): {e}")
        except requests.exceptions.RequestException as e:
            raise APIError(f"Network error during renewal: {e}")

    def close(self):
        """Close the HTTP session."""
        self.session.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
