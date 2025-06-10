# Use Debian to ensure compatibility with glibc instead of musl, preventing crashes during aardwolf compilation (required by NetExec).
FROM python:3.13-slim

ENV NETEXEC_URL=git+https://github.com/Pennyw0rth/NetExec.git

WORKDIR /opt/openbas-injector-netexec

# Install Python modules
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# NetExec Installation
RUN pip install --no-cache-dir "$NETEXEC_URL" \
    netexec --version

# Copy the injector
COPY . .

# Installation Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose and entrypoint
CMD ["python3", "-m", "netexec.openbas_netexec"]

