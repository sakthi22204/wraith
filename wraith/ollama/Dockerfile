FROM ollama/ollama:latest

# Trust the corporate TLS-inspection CA so `ollama pull` can reach the
# registry through the network's MITM proxy. Without this the container
# fails with "x509: certificate signed by unknown authority".
COPY certs/tnq-ca.crt /usr/local/share/ca-certificates/tnq-ca.crt
RUN update-ca-certificates

# llama.cpp freezes on generation when spawned with the default worker
# thread count (= nproc, here 7) in this VM. Cap it at 4 threads, which the
# scheduler also applies per-slot (Ollama's ComputeThreads uses NumCPU).
# Any request-level options/thread flags are ignored by the Ollama
# scheduler, so the constraint must be applied at the runner binary.
RUN cp /usr/lib/ollama/llama-server /usr/lib/ollama/llama-server.real \
    && printf '#!/bin/sh\nexec /usr/lib/ollama/llama-server.real "$@" -t 5\n' \
        > /usr/lib/ollama/llama-server \
    && chmod +x /usr/lib/ollama/llama-server /usr/lib/ollama/llama-server.real
