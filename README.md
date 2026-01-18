# CabinMonitor Home Assistant Add-ons

Home Assistant add-on repository for CabinMonitor.

## Add-ons

### CabinMonitor Agent

Telemetry agent that collects Home Assistant states and system metrics, sending them securely to your CabinMonitor server.

## Installation

1. Open Home Assistant
2. Go to **Settings → Add-ons → Add-on Store**
3. Click ⋮ (three dots) → **Repositories**
4. Add this URL:
   ```
   https://github.com/davisloop/CabinMonitor-server
   ```
5. Find "CabinMonitor Agent" and install

## Quick Start

1. Generate an enrollment token in the CabinMonitor admin UI
2. Configure the add-on with your site ID, server URL, and token
3. Start the add-on
4. Check logs to verify enrollment succeeded

## Support

See the [main documentation](../docs/) for detailed guides.
