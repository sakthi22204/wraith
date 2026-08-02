FROM python:3.11-slim
RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/internetwache/GitTools.git /opt/gittools
WORKDIR /opt/gittools/Finder
RUN pip install --no-cache-dir -r requirements.txt || true
COPY gittools-wrapper.sh /usr/local/bin/gittools
RUN chmod +x /usr/local/bin/gittools
ENTRYPOINT ["/usr/local/bin/gittools"]
