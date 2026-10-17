# Ops

## Phase-based startup (recommended for 16GB RAM systems)

Running all Wraith containers simultaneously requires 12+ GB RAM and may
cause instability on 16GB VMs. Use the phase script instead:

```bash
# Recon phase (~5GB RAM)
./ops/wraith-phase.sh recon
./ops/wraith-phase.sh down-recon

# Exploit phase (~6GB RAM)
./ops/wraith-phase.sh exploit
./ops/wraith-phase.sh down-exploit

# Reporting phase (~5GB RAM)
./ops/wraith-phase.sh report
./ops/wraith-phase.sh down-report

# Check status + memory
./ops/wraith-phase.sh status
```

Neo4j data persists in Docker volumes between phases — stopping
non-core containers does not lose investigation data.

## Neo4j memory

Capped at 1GB heap + 512MB page cache (2GB container limit) to prevent
OOM on constrained hosts. Tune in docker-compose.yml if you have more RAM.
