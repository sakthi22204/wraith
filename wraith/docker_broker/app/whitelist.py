ALLOWED_IMAGES = [
    "projectdiscovery/subfinder:latest",
    "projectdiscovery/httpx:latest",
    "projectdiscovery/katana:latest",
    "projectdiscovery/naabu:latest",
    "kalilinux/kali-rolling:latest",
    "projectdiscovery/dnsx:latest",
    "instrumentisto/nmap:latest",
    "projectdiscovery/tlsx:latest",
    # Vulnerability template checks. Scheduled for Docker-local targets only
    # (recon_orchestrator AGGRESSIVE_TOOLS / not PASSIVE_REMOTE_TOOLS).
    # Built locally from recon_orchestrator/tool_images/nuclei: the upstream
    # ProjectDiscovery image ships no templates, so it scans nothing and exits 0.
    "nuclei:latest",
    "lc/gau:latest",
    "gau:latest",
    "tomnomnom/waybackurls:latest",
    "waybackurls:latest",
    "ffuf/ffuf:latest",
    "kiterunner:latest",
    "linkfinder:latest",
    "secretfinder:latest",
    "trufflesecurity/trufflehog:latest",
    "gittools:latest",
    "wpscanteam/wpscan:latest",
    "cloud_enum:latest"
]

ALLOWED_COMMANDS_PER_IMAGE = {
    "projectdiscovery/subfinder:latest": ["-d", "-json"],
    "projectdiscovery/httpx:latest": ["-u", "-list", "-json", "-silent"],
    "projectdiscovery/katana:latest": ["-u", "-json", "-silent"],
    "projectdiscovery/naabu:latest": ["-host", "-json", "-silent"],
    "kalilinux/kali-rolling:latest": ["nmap", "nikto"],
    "projectdiscovery/dnsx:latest": ["-d"],
    "instrumentisto/nmap:latest": ["-T4"],
    "projectdiscovery/tlsx:latest": ["-u"],
    "nuclei:latest": ["-u"],
    "lc/gau:latest": None,
    "gau:latest": None,
    "tomnomnom/waybackurls:latest": None,
    "waybackurls:latest": None,
    "ffuf/ffuf:latest": ["-u"],
    "kiterunner:latest": ["kb"],
    "linkfinder:latest": ["-i"],
    "secretfinder:latest": ["-i", "-e"],
    "trufflesecurity/trufflehog:latest": ["git"],
    "gittools:latest": ["-u"],
    "wpscanteam/wpscan:latest": ["--url"],
    "cloud_enum:latest": ["-k"]
}

ALLOWED_OPERATIONS = {
    "create",
    "start",
    "stop",
    "remove",
    "logs",
    "wait"
}

# The only named volumes a tool container may mount, and always read-only.
#
# Volumes are the sole way recon_orchestrator gets state into a tool container
# (tools/proxy.py mounts the mitmproxy CA so intercepted TLS is trusted). The
# set is closed rather than pattern-matched because a named volume is still
# Docker-managed state that outlives the container, and an open rule here would
# hand any caller who reached the broker a place to stage a payload.
ALLOWED_NAMED_VOLUMES = frozenset({
    "mitmproxy_ca",
})
