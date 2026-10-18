FROM python:3.11-slim
# git clone and pip's network fetches can fail transiently when the recon phase
# builds many tool images concurrently; retry each before failing the build.
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN for i in 1 2 3; do \
      git clone https://github.com/m4ll0k/SecretFinder.git /opt/secretfinder && break || \
      { [ "$i" -lt 3 ] && sleep 5 || exit 1; }; \
    done
WORKDIR /opt/secretfinder
RUN for i in 1 2 3; do \
      pip install --no-cache-dir -r requirements.txt && break || \
      { [ "$i" -lt 3 ] && sleep 5 || exit 1; }; \
    done
ENTRYPOINT ["python3", "SecretFinder.py"]
