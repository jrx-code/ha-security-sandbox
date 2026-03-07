ARG BUILD_FROM
FROM ${BUILD_FROM}

# Install git (needed for cloning repos to scan)
RUN apk add --no-cache git

# Install Python dependencies
COPY requirements.txt /tmp/
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

# Copy application
COPY app/ /app/
COPY config.yaml /config.yaml

# Copy run script
COPY run.sh /
RUN chmod a+x /run.sh

# Data directories
RUN mkdir -p /data/repos /data/reports

EXPOSE 8099
CMD ["/run.sh"]
