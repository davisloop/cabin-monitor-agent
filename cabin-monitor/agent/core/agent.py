"""
Main CabinMonitor agent implementation.

Orchestrates enrollment, telemetry collection, and certificate renewal.
"""
import asyncio
import time
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from pathlib import Path

from agent.config.settings import AgentConfig
from agent.core.certs import CertificateManager
from agent.core.client import CabinMonitorClient, APIError
from agent.collectors.homeassistant import HomeAssistantCollector, create_device_info

logger = logging.getLogger(__name__)


class Agent:
    """
    CabinMonitor telemetry agent.

    Handles the complete lifecycle:
    - Enrollment (if not enrolled)
    - Telemetry collection and submission
    - Certificate renewal
    """

    def __init__(self, config: AgentConfig):
        """
        Initialize agent.

        Args:
            config: Agent configuration
        """
        self.config = config
        self.running = False
        self.current_policy: Optional[Dict[str, Any]] = None

        # Initialize certificate manager
        self.cert_manager = CertificateManager(
            cert_dir=config.certificate.cert_dir,
            device_id=config.device_id or "pending",
            key_password=config.certificate.key_password
        )

        # Initialize API client
        self.client = CabinMonitorClient(
            server_url=config.server.url,
            verify_ssl=config.server.verify_ssl,
            timeout=config.server.timeout
        )

        # Initialize Home Assistant collector (if configured)
        self.ha_collector: Optional[HomeAssistantCollector] = None
        if config.homeassistant:
            self.ha_collector = HomeAssistantCollector(
                ha_url=config.homeassistant.url,
                ha_token=config.homeassistant.token,
                verify_ssl=config.homeassistant.verify_ssl
            )

    async def enroll(self) -> None:
        """
        Enroll the device with the server.

        Generates a CSR, submits to server, and stores the issued certificate.

        Raises:
            RuntimeError: If enrollment fails or enrollment_token not configured
        """
        if not self.config.enrollment_token:
            raise RuntimeError(
                "Enrollment token not configured. "
                "Set CABINMONITOR_ENROLLMENT_TOKEN environment variable."
            )

        logger.info("Starting device enrollment...")

        # Generate temporary device ID for CSR
        temp_device_id = f"temp_{uuid.uuid4().hex[:8]}"
        self.cert_manager.device_id = temp_device_id

        # Generate key and CSR
        private_key, csr_pem = self.cert_manager.generate_key_and_csr()

        # Create device info
        device_info = create_device_info()

        # Enroll with server
        try:
            response = self.client.enroll_device(
                site_id=self.config.site_id,
                csr_pem=csr_pem,
                enrollment_token=self.config.enrollment_token,
                agent_version=self._get_agent_version(),
                device_info=device_info
            )

            # Extract enrollment data
            device_id = response["device_id"]
            device_cert_pem = response["device_cert_pem"]
            ca_chain_pem = response["ca_chain_pem"]
            policy = response["policy"]

            # Update device ID
            self.config.device_id = device_id
            self.cert_manager.device_id = device_id
            self.current_policy = policy

            # Save certificate materials
            self.cert_manager.save_enrollment_materials(
                private_key=private_key,
                device_cert_pem=device_cert_pem,
                ca_chain_pem=ca_chain_pem
            )

            # Persist device ID
            self.config.save_device_id(device_id)

            logger.info(f"Enrollment successful: device_id={device_id}")
            logger.info(f"Certificate expires: {response['cert_not_after']}")
            logger.info(f"Policy: {policy}")

        except APIError as e:
            logger.error(f"Enrollment failed: {e}")
            raise RuntimeError(f"Enrollment failed: {e}")

    async def renew_certificate(self) -> None:
        """
        Renew the device certificate.

        Generates a new CSR and requests certificate renewal from the server.

        Raises:
            RuntimeError: If renewal fails
        """
        logger.info("Renewing device certificate...")

        # Generate new key and CSR
        private_key, csr_pem = self.cert_manager.generate_key_and_csr()

        # Get current certificate paths for mTLS
        cert_path, key_path, _ = self.cert_manager.get_cert_paths()

        try:
            response = self.client.renew_certificate(
                csr_pem=csr_pem,
                cert_path=cert_path,
                key_path=key_path
            )

            # Extract renewal data
            device_cert_pem = response["device_cert_pem"]
            ca_chain_pem = response["ca_chain_pem"]

            # Save new certificate materials
            self.cert_manager.save_enrollment_materials(
                private_key=private_key,
                device_cert_pem=device_cert_pem,
                ca_chain_pem=ca_chain_pem
            )

            logger.info(f"Certificate renewed successfully: expires={response['cert_not_after']}")

        except APIError as e:
            logger.error(f"Certificate renewal failed: {e}")
            raise RuntimeError(f"Certificate renewal failed: {e}")

    async def collect_and_send_telemetry(self) -> None:
        """
        Collect telemetry data and send to server.

        Raises:
            RuntimeError: If telemetry submission fails
        """
        logger.debug("Collecting telemetry...")

        # Collect data from Home Assistant (if configured)
        if self.ha_collector:
            try:
                telemetry_data = await self.ha_collector.collect_telemetry(
                    include_system_metrics=self.config.telemetry.include_system_metrics
                )
            except Exception as e:
                logger.error(f"Failed to collect telemetry: {e}")
                raise RuntimeError(f"Telemetry collection failed: {e}")
        else:
            # No collector configured - send basic system metrics
            telemetry_data = {
                "states": {},
                "events": [],
                "system_metrics": {}
            }

        # Build payload
        payload = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_version": self._get_agent_version(),
            "schema_version": 1,
            "payload_id": str(uuid.uuid4()),
            **telemetry_data
        }

        # Send to server
        cert_path, key_path, _ = self.cert_manager.get_cert_paths()

        try:
            response = self.client.send_telemetry(
                payload=payload,
                cert_path=cert_path,
                key_path=key_path
            )

            # Update policy from response
            if "policy" in response:
                old_interval = self.current_policy.get("upload_interval_sec") if self.current_policy else None
                self.current_policy = response["policy"]
                new_interval = self.current_policy.get("upload_interval_sec")

                if old_interval != new_interval:
                    logger.info(f"Upload interval updated: {old_interval} -> {new_interval} seconds")

            logger.debug(f"Telemetry sent successfully: status={response['status']}")

        except APIError as e:
            logger.error(f"Telemetry submission failed: {e}")
            raise RuntimeError(f"Telemetry submission failed: {e}")

    def _get_agent_version(self) -> str:
        """Get agent version string."""
        from agent import __version__
        return __version__

    def _get_upload_interval(self) -> int:
        """
        Get current upload interval.

        Uses policy from server if available, otherwise uses config default.

        Returns:
            Upload interval in seconds
        """
        if self.current_policy and "upload_interval_sec" in self.current_policy:
            return self.current_policy["upload_interval_sec"]
        return self.config.telemetry.upload_interval_sec

    async def run_once(self) -> None:
        """
        Run one iteration: check enrollment, check renewal, send telemetry.

        Raises:
            RuntimeError: If critical operations fail
        """
        # Check if enrolled
        if not self.cert_manager.has_valid_certificate():
            logger.info("Device not enrolled, starting enrollment...")
            await self.enroll()

        # Check if certificate needs renewal
        if self.cert_manager.needs_renewal(self.config.certificate.renew_days):
            logger.info("Certificate needs renewal...")
            await self.renew_certificate()

        # Collect and send telemetry
        await self.collect_and_send_telemetry()

    async def run(self) -> None:
        """
        Run the agent main loop.

        Continuously collects and sends telemetry based on the upload interval.
        """
        self.running = True
        logger.info("Starting CabinMonitor agent...")

        # Perform initial enrollment/renewal if needed
        try:
            if not self.cert_manager.has_valid_certificate():
                await self.enroll()

            if self.cert_manager.needs_renewal(self.config.certificate.renew_days):
                await self.renew_certificate()

        except Exception as e:
            logger.error(f"Initial setup failed: {e}")
            self.running = False
            raise

        # Main telemetry loop
        iteration = 0
        while self.running:
            iteration += 1
            logger.debug(f"Starting iteration {iteration}")

            try:
                # Send telemetry
                await self.collect_and_send_telemetry()

                # Check for renewal (periodic check)
                if self.cert_manager.needs_renewal(self.config.certificate.renew_days):
                    await self.renew_certificate()

            except Exception as e:
                logger.error(f"Error in iteration {iteration}: {e}")

                # Retry logic
                for attempt in range(self.config.telemetry.retry_attempts):
                    logger.info(f"Retry attempt {attempt + 1}/{self.config.telemetry.retry_attempts}")
                    await asyncio.sleep(self.config.telemetry.retry_delay_sec)

                    try:
                        await self.collect_and_send_telemetry()
                        logger.info("Retry successful")
                        break
                    except Exception as retry_error:
                        logger.error(f"Retry failed: {retry_error}")
                        if attempt == self.config.telemetry.retry_attempts - 1:
                            logger.error("All retries exhausted, continuing to next interval")

            # Sleep until next upload
            upload_interval = self._get_upload_interval()
            logger.debug(f"Sleeping for {upload_interval} seconds...")
            await asyncio.sleep(upload_interval)

    def stop(self) -> None:
        """Stop the agent."""
        logger.info("Stopping agent...")
        self.running = False
        self.client.close()
