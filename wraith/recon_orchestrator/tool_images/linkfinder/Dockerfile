FROM python:3.11-slim
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/GerbenJavado/LinkFinder.git /opt/linkfinder
WORKDIR /opt/linkfinder
RUN pip install --no-cache-dir -r requirements.txt && python3 setup.py install
ENTRYPOINT ["python3", "linkfinder.py"]
