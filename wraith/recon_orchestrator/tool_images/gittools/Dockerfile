FROM python:3.11-slim
RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*
# git clone can fail transiently when the recon phase builds many tool images
# concurrently; retry before failing the build. (pip already tolerates failure
# below -- the tool runs via its wrapper regardless.)
RUN for i in 1 2 3; do \
      git clone https://github.com/internetwache/GitTools.git /opt/gittools && break || \
      { [ "$i" -lt 3 ] && sleep 5 || exit 1; }; \
    done
WORKDIR /opt/gittools/Finder
RUN pip install --no-cache-dir -r requirements.txt || true
COPY gittools-wrapper.sh /usr/local/bin/gittools
RUN chmod +x /usr/local/bin/gittools
ENTRYPOINT ["/usr/local/bin/gittools"]
