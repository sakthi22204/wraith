ALLOWED_IMAGES = [
    "projectdiscovery/subfinder:latest",
    "projectdiscovery/httpx:latest",
    "projectdiscovery/katana:latest",
    "projectdiscovery/naabu:latest",
    "kalilinux/kali-rolling:latest"
]

ALLOWED_COMMANDS_PER_IMAGE = {
    "projectdiscovery/subfinder:latest": ["-d", "-json"],
    "projectdiscovery/httpx:latest": ["-u", "-list", "-json", "-silent"],
    "projectdiscovery/katana:latest": ["-u", "-json", "-silent"],
    "projectdiscovery/naabu:latest": ["-host", "-json", "-silent"],
    "kalilinux/kali-rolling:latest": ["nmap", "nikto"] # Example restricted commands
}

ALLOWED_OPERATIONS = {
    "create",
    "start",
    "stop",
    "remove",
    "logs",
    "wait"
}
