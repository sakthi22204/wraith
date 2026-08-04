FROM python:3.11-slim
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/initstring/cloud_enum.git /opt/cloud_enum
WORKDIR /opt/cloud_enum
RUN pip install --no-cache-dir .
ENTRYPOINT ["python3", "cloud_enum.py"]
