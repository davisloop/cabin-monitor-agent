"""
CabinMonitor Agent CLI entry point.

Runs the telemetry agent as a daemon.
"""
import asyncio
import signal
import sys
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.config.settings import AgentConfig, setup_logging
from agent.core.agent import Agent

logger = logging.getLogger(__name__)


def signal_handler(signum, frame, agent: Agent):
    """
    Handle termination signals.

    Args:
        signum: Signal number
        frame: Stack frame
        agent: Agent instance to stop
    """
    logger.info(f"Received signal {signum}, shutting down...")
    agent.stop()


async def main():
    """Main entry point."""
    # Load configuration from environment
    try:
        config = AgentConfig.from_env()
        config.validate()
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        print("\nRequired environment variables:", file=sys.stderr)
        print("  CABINMONITOR_SITE_ID", file=sys.stderr)
        print("  CABINMONITOR_SERVER_URL", file=sys.stderr)
        print("  CABINMONITOR_HA_URL (optional)", file=sys.stderr)
        print("  CABINMONITOR_HA_TOKEN (optional)", file=sys.stderr)
        print("\nFor enrollment, also set:", file=sys.stderr)
        print("  CABINMONITOR_ENROLLMENT_TOKEN", file=sys.stderr)
        return 1

    # Setup logging
    setup_logging(config.log_level)

    logger.info("=" * 60)
    logger.info("CabinMonitor Telemetry Agent")
    logger.info("=" * 60)
    logger.info(f"Site ID: {config.site_id}")
    logger.info(f"Device ID: {config.device_id or '(not enrolled)'}")
    logger.info(f"Server URL: {config.server.url}")
    logger.info(f"Certificate directory: {config.certificate.cert_dir}")
    logger.info("=" * 60)

    # Create agent
    agent = Agent(config)

    # Register signal handlers
    signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, agent))
    signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, agent))

    # Run agent
    try:
        await agent.run()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        agent.stop()
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1

    logger.info("Agent stopped")
    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
