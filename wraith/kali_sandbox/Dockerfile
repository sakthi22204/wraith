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
    git \
    # Phase 1.9 scanner toolkit. All five ship in Kali; the other three
    # (jwt_tool, Corsy, ghauri) are not packaged there and are cloned below.
    nikto \
    commix \
    xsstrike \
    arjun \
    dalfox \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Phase 1.9 tools that Kali does not package. Each is cloned to /opt and its
# script or console entrypoint is referenced by the web tools server. The
# clones are depth-1 (build-time freeze), which is deterministic enough for a
# throwaway scanner image: the scanners report a missing binary as
# "inconclusive", so a changed upstream is a verdict that says "nothing", never
# a verdict that says "clean".
#
# jwt_tool: ticarpi/jwt_tool. Python 3, stdlib + termcolor.
RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && pip3 install --no-cache-dir --break-system-packages termcolor requests

# Corsy: s0md3v/Corsy. Python 3 port needs requests and urllib3.
RUN git clone --depth 1 https://github.com/s0md3v/Corsy.git /opt/Corsy \
    && pip3 install --no-cache-dir --break-system-packages requests urllib3

# ghauri: r0oth3x49/ghauri (SQLi testing). Pip-installed from the checkout so
# the `ghauri` console entrypoint lands on PATH.
RUN git clone --depth 1 https://github.com/r0oth3x49/ghauri.git /opt/ghauri \
    && (test ! -f /opt/ghauri/requirements.txt \
        || pip3 install --no-cache-dir --break-system-packages -r /opt/ghauri/requirements.txt) \
    && pip3 install --no-cache-dir --break-system-packages /opt/ghauri

# Grant nmap the file capabilities it needs for SYN (raw-socket) scans. The
# sandbox runs as the unprivileged `wraith` user, and Docker drops
# NET_RAW/NET_ADMIN from the default capability set, so a plain `cap_add` is not
# enough on its own: a non-root process only gets a capability into its
# *effective* set via file capabilities on the binary. The caps go on
# /usr/lib/nmap/nmap (the real binary), not the /usr/bin/nmap wrapper script —
# file capabilities do not carry across the wrapper's `exec`, so capping the
# script would grant them to the sh interpreter and drop them again on exec.
# This is its own layer, placed before `COPY . .`, so it reuses the cached
# heavy toolchain layers above and is not invalidated by source edits below.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw,cap_net_admin+ep /usr/lib/nmap/nmap

COPY . .

# Default command starts the main MCP server

  # Runs as a non-root user. This is the highest-risk container in the stack.
  RUN useradd --create-home --uid 10002 --shell /usr/sbin/nologin wraith

  USER wraith
CMD ["python3", "-m", "mcp_servers.main"]
