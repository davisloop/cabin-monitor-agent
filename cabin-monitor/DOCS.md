# CabinMonitor Agent Add-on

This add-on runs the CabinMonitor telemetry agent on your Home Assistant OS installation.

## Installation

1. Add this repository to your Home Assistant add-on store:
   - Go to **Settings → Add-ons → Add-on Store**
   - Click the three dots (⋮) in the top right
   - Select **Repositories**
   - Add: `https://github.com/davisloop/CabinMonitor-server`

2. Find "CabinMonitor Agent" in the add-on store and click **Install**

3. Configure the add-on (see Configuration below)

4. Start the add-on

## Configuration

### Required Settings

| Option | Description |
|--------|-------------|
| `site_id` | Your site identifier (from CabinMonitor admin) |
| `server_url` | CabinMonitor server URL (e.g., `https://monitor.example.com`) |

### First-Time Enrollment

For first-time setup, you also need:

| Option | Description |
|--------|-------------|
| `enrollment_token` | One-time enrollment token (from CabinMonitor admin) |

After successful enrollment, the token is no longer needed and can be removed.

### Optional Settings

| Option | Default | Description |
|--------|---------|-------------|
| `upload_interval` | 60 | Seconds between telemetry uploads |
| `log_level` | INFO | Log verbosity (DEBUG, INFO, WARNING, ERROR) |
| `verify_ssl` | true | Verify server SSL certificate |

## Example Configuration

```yaml
site_id: "advi-office"
server_url: "https://monitor.example.com"
enrollment_token: "your-token-here"
upload_interval: 60
log_level: "INFO"
verify_ssl: true
```

## How It Works

1. **Enrollment**: On first run, the agent uses the enrollment token to register with the server and receive a client certificate.

2. **Data Collection**: The agent collects:
   - Home Assistant entity states
   - System metrics (CPU, memory, disk)

3. **Secure Upload**: Data is sent to the server using mTLS (mutual TLS) authentication.

4. **Auto-Renewal**: Certificates are automatically renewed before expiry.

## Troubleshooting

### Check Logs

Go to the add-on page and click **Log** to view agent output.

### Enrollment Failed

- Verify the enrollment token is correct and hasn't expired
- Tokens are one-time use - generate a new one if needed
- Check that `server_url` is correct and accessible

### Connection Errors

- Verify `server_url` is reachable from your network
- If using self-signed certificates, set `verify_ssl: false`
- Check firewall rules allow outbound HTTPS

### Certificate Issues

Certificates are stored in `/data/certs`. If you need to re-enroll:

1. Stop the add-on
2. Remove certificate files via SSH/Terminal add-on:
   ```bash
   rm -rf /addon_configs/*/certs/*
   ```
3. Configure a new enrollment token
4. Start the add-on

## Support

- **Documentation**: See the main CabinMonitor documentation
- **Issues**: Report issues on GitHub
