ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install Python and dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    py3-cryptography \
    py3-aiohttp \
    py3-requests \
    py3-psutil \
    curl \
    jq

# Set working directory
WORKDIR /app

# Copy agent code
COPY agent/ ./agent/

# Copy run script
COPY run.sh /run.sh
RUN chmod +x /run.sh

# Create certificate directory
RUN mkdir -p /data/certs

CMD [ "/run.sh" ]
