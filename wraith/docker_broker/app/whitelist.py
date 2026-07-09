ALLOWED_IMAGES = [
    "projectdiscovery/subfinder:latest",
    "projectdiscovery/httpx:latest",
    "projectdiscovery/katana:latest",
    "projectdiscovery/naabu:latest",
    "kalilinux/kali-rolling:latest"
]

ALLOWED_COMMANDS_PER_IMAGE = {
    "projectdiscovery/subfinder:latest": ["-d", "-json"],
    "projectdiscovery/httpx:latest": ["-list", "-json"],
    "projectdiscovery/katana:latest": ["-u", "-json"],
    "projectdiscovery/naabu:latest": ["-host", "-json"],
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
