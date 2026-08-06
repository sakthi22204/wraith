ALLOWED_IMAGES = [
    "projectdiscovery/subfinder:latest",
    "projectdiscovery/httpx:latest",
    "projectdiscovery/katana:latest",
    "projectdiscovery/naabu:latest",
    "kalilinux/kali-rolling:latest",
    "projectdiscovery/dnsx:latest",
    "instrumentisto/nmap:latest",
    "projectdiscovery/tlsx:latest",
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
