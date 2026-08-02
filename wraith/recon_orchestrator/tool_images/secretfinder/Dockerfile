FROM python:3.11-slim
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/m4ll0k/SecretFinder.git /opt/secretfinder
WORKDIR /opt/secretfinder
RUN pip install --no-cache-dir -r requirements.txt
ENTRYPOINT ["python3", "SecretFinder.py"]
