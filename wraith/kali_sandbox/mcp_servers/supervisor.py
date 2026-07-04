import subprocess
import time
import sys

# Simple script to run multiple processes
processes = [
    ["python3", "-m", "mcp_servers.nmap_server"],
    ["python3", "-m", "mcp_servers.nuclei_server"],
    ["python3", "-m", "mcp_servers.sqlmap_server"],
    ["python3", "-m", "mcp_servers.hydra_server"],
    ["python3", "-m", "mcp_servers.metasploit_server"]
]

procs = []
for cmd in processes:
    procs.append(subprocess.Popen(cmd))

try:
    while True:
        time.sleep(1)
        for p in procs:
            if p.poll() is not None:
                print(f"Process {p.args} exited with code {p.returncode}")
                sys.exit(1)
except KeyboardInterrupt:
    for p in procs:
        p.terminate()
