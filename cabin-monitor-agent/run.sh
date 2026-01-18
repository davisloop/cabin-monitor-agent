#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
set -e

# Read configuration from Home Assistant add-on options
CONFIG_PATH=/data/options.json

# Required settings
export CABINMONITOR_SITE_ID=$(bashio::config 'site_id')
export CABINMONITOR_SERVER_URL=$(bashio::config 'server_url')

# Optional settings
if bashio::config.has_value 'enrollment_token'; then
    export CABINMONITOR_ENROLLMENT_TOKEN=$(bashio::config 'enrollment_token')
fi

if bashio::config.has_value 'upload_interval'; then
    export CABINMONITOR_UPLOAD_INTERVAL=$(bashio::config 'upload_interval')
fi

if bashio::config.has_value 'log_level'; then
    export CABINMONITOR_LOG_LEVEL=$(bashio::config 'log_level')
fi

if bashio::config.has_value 'verify_ssl'; then
    VERIFY_SSL=$(bashio::config 'verify_ssl')
    if [ "$VERIFY_SSL" = "false" ]; then
        export CABINMONITOR_SERVER_VERIFY_SSL="false"
    fi
fi

# Certificate directory (persistent storage)
export CABINMONITOR_CERT_DIR="/data/certs"

# Home Assistant API integration
# The Supervisor provides these automatically when homeassistant_api is enabled
if [ -n "${SUPERVISOR_TOKEN:-}" ]; then
    export CABINMONITOR_HA_URL="http://supervisor/core"
    export CABINMONITOR_HA_TOKEN="${SUPERVISOR_TOKEN}"
    bashio::log.info "Home Assistant API integration enabled"
fi

# Log startup info
bashio::log.info "Starting CabinMonitor Agent..."
bashio::log.info "Site ID: ${CABINMONITOR_SITE_ID}"
bashio::log.info "Server URL: ${CABINMONITOR_SERVER_URL}"
bashio::log.info "Certificate directory: ${CABINMONITOR_CERT_DIR}"

# Check if already enrolled
if [ -f "${CABINMONITOR_CERT_DIR}/device.crt" ]; then
    bashio::log.info "Device certificate found - already enrolled"
else
    bashio::log.info "No certificate found - will attempt enrollment"
    if [ -z "${CABINMONITOR_ENROLLMENT_TOKEN:-}" ]; then
        bashio::log.warning "No enrollment token configured - enrollment will fail"
    fi
fi

# Run the agent
cd /app
exec python3 -m agent
