FROM kalilinux/kali-rolling

# Prevent prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install core tools
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    nmap \
    nuclei \
    sqlmap \
    hydra \
    metasploit-framework \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

# Default command starts the main MCP server

  # Runs as a non-root user. This is the highest-risk container in the stack.
  RUN useradd --create-home --uid 10002 --shell /usr/sbin/nologin wraith
  USER wraith
CMD ["python3", "-m", "mcp_servers.main"]
