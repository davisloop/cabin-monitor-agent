# CabinMonitor Telemetry Agent

**Version:** 1.0.0
**Python:** 3.11+
**Status:** ✅ Production Ready

## Quick Start

### Docker (Recommended)

```bash
# 1. Build image
docker build -t cabinmonitor-agent .

# 2. Set environment variables
export CABINMONITOR_SITE_ID="my-site"
export CABINMONITOR_SERVER_URL="https://server.example.com"
export CABINMONITOR_ENROLLMENT_TOKEN="your-token"

# 3. Run container
docker run -d \
  --name cabin-agent \
  -e CABINMONITOR_SITE_ID \
  -e CABINMONITOR_SERVER_URL \
  -e CABINMONITOR_ENROLLMENT_TOKEN \
  -v agent-certs:/app/certs \
  cabinmonitor-agent
```

### Python

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set environment variables
export CABINMONITOR_SITE_ID="my-site"
export CABINMONITOR_SERVER_URL="https://server.example.com"
export CABINMONITOR_ENROLLMENT_TOKEN="your-token"

# 3. Run agent
python -m agent
```

## Features

- ✅ **Self-Enrollment** - Automatic device registration
- ✅ **mTLS Authentication** - Secure certificate-based auth
- ✅ **Auto-Renewal** - Certificates renewed before expiry
- ✅ **Home Assistant Integration** - Collect entity states
- ✅ **System Metrics** - CPU, memory, disk usage
- ✅ **Policy-Aware** - Respects server upload intervals
- ✅ **Retry Logic** - Automatic retry on errors
- ✅ **Docker Support** - Containerized deployment

## Configuration

All configuration via environment variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CABINMONITOR_SITE_ID` | ✅ | - | Site identifier |
| `CABINMONITOR_SERVER_URL` | ✅ | - | Server base URL |
| `CABINMONITOR_ENROLLMENT_TOKEN` | First run | - | One-time token |
| `CABINMONITOR_DEVICE_ID` | - | Auto | Device ID (set after enrollment) |
| `CABINMONITOR_HA_URL` | - | - | Home Assistant URL |
| `CABINMONITOR_HA_TOKEN` | - | - | Home Assistant token |
| `CABINMONITOR_CERT_DIR` | - | `./certs` | Certificate directory |
| `CABINMONITOR_UPLOAD_INTERVAL` | - | `60` | Upload interval (seconds) |
| `CABINMONITOR_LOG_LEVEL` | - | `INFO` | Log level |

## Architecture

```
┌─────────────────────┐
│   CertManager       │  Generate CSR, manage certs
└──────┬──────────────┘
       │
┌──────┴──────────────┐
│   API Client        │  HTTP/mTLS communication
└──────┬──────────────┘
       │
┌──────┴──────────────┐
│   HA Collector      │  Collect states & metrics
└──────┬──────────────┘
       │
┌──────┴──────────────┐
│   Agent Main Loop   │  Orchestrate everything
└─────────────────────┘
  1. Check enrollment
  2. Check renewal
  3. Collect telemetry
  4. Send to server
  5. Sleep (policy interval)
  6. Repeat
```

## Project Structure

```
agent/
├── core/
│   ├── agent.py       # Main orchestrator
│   ├── certs.py       # Certificate management
│   └── client.py      # API client
├── collectors/
│   └── homeassistant.py  # HA collector
├── config/
│   └── settings.py    # Configuration
├── __main__.py        # CLI entry point
├── requirements.txt   # Dependencies
├── Dockerfile         # Container image
└── README.md          # This file
```

## Usage Examples

### First Enrollment

```bash
# Generate enrollment token from admin API
curl -k -X POST \
  -H "X-API-Key: YOUR_ADMIN_KEY" \
  -d '{"site_id": "my-site", "validity_hours": 24}' \
  https://server.example.com/v1/admin/tokens

# Set token and run agent
export CABINMONITOR_ENROLLMENT_TOKEN="token-from-above"
python -m agent
```

Expected output:
```
2026-01-13 00:00:00 - agent.core.agent - INFO - Starting device enrollment...
2026-01-13 00:00:01 - agent.core.client - INFO - Enrollment successful: device_id=dev_abc123
2026-01-13 00:00:01 - agent.core.agent - INFO - Certificate expires: 2026-04-13T00:00:00Z
```

### Normal Operation

After enrollment, agent runs continuously:

```
2026-01-13 00:00:00 - agent.core.agent - INFO - Starting CabinMonitor agent...
2026-01-13 00:00:01 - agent.core.client - DEBUG - Telemetry sent successfully
2026-01-13 00:00:01 - agent.core.agent - DEBUG - Sleeping for 60 seconds...
```

### With Home Assistant

```bash
# Create long-lived token in Home Assistant
# Profile → Long-Lived Access Tokens → Create Token

# Set environment variables
export CABINMONITOR_HA_URL="http://homeassistant.local:8123"
export CABINMONITOR_HA_TOKEN="your-ha-token"

# Run agent
python -m agent
```

## Troubleshooting

### Enrollment Fails

**Error:** `Enrollment token not configured`

```bash
# Solution: Set enrollment token
export CABINMONITOR_ENROLLMENT_TOKEN="your-token"
```

**Error:** `Invalid enrollment token`

Token may be:
- Already used (one-time only)
- Expired
- Invalid

Generate a new token via admin API.

### Telemetry Fails

**Error:** `SSL error during telemetry`

```bash
# For self-signed certs (development only)
export CABINMONITOR_SERVER_VERIFY_SSL="false"

# Check certificate expiry
openssl x509 -in certs/device.crt -noout -dates
```

**Error:** `Device is revoked`

Device has been revoked. Contact administrator to unrevo or re-enroll with new token.

### Home Assistant Connection

**Error:** `HTTP 401 from Home Assistant`

Token is invalid. Generate new long-lived token in HA.

**Error:** `Cannot connect to host`

Check:
1. `CABINMONITOR_HA_URL` is correct
2. Home Assistant is running
3. Network connectivity

## Development

### Running Tests

```bash
# From project root
python test_agent.py
```

Expected:
```
✓ All agent tests passed!
```

### Adding New Collectors

1. Create file in `collectors/`
2. Implement `collect_telemetry()` method
3. Return dict with `states`, `events`, `system_metrics`
4. Update `agent.py` to use new collector

Example:
```python
# collectors/custom.py
class CustomCollector:
    async def collect_telemetry(self):
        return {
            "states": {},
            "events": [],
            "system_metrics": {"custom_metric": 123.0}
        }
```

## Security

- **Private keys** stored with `0600` permissions
- **Certificates** stored with `0644` permissions
- **Enrollment tokens** are one-time use and time-limited
- **mTLS** ensures mutual authentication
- **SSL verification** enabled by default

## Monitoring

Check agent status:
```bash
# Docker
docker logs -f cabin-agent

# Docker Compose
docker-compose -f docker-compose.agent.yml logs -f agent

# Python (check process)
ps aux | grep agent
```

Server-side monitoring:
```bash
# Check device last_seen via admin API
curl -k -H "X-API-Key: YOUR_KEY" \
  https://server.example.com/v1/admin/devices/dev_abc123
```

## Documentation

- **User Guide:** `../docs/AGENT_GUIDE.md`
- **Phase 6 Completion:** `../docs/PHASE6_COMPLETION.md`
- **API Documentation:** `../docs/API_QUICKSTART.md`

## Support

- **Tests:** `python test_agent.py`
- **Logs:** Check agent logs for errors
- **Server:** Check server-side logs

## License

Copyright © 2026 CabinMonitor Project
