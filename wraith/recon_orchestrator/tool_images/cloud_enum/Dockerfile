FROM python:3.11-slim
# git clone and pip's network fetches can fail transiently when the recon phase
# builds many tool images concurrently; retry each before failing the build.
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
RUN for i in 1 2 3; do \
      git clone https://github.com/initstring/cloud_enum.git /opt/cloud_enum && break || \
      { [ "$i" -lt 3 ] && sleep 5 || exit 1; }; \
    done
WORKDIR /opt/cloud_enum
# `pip install .` resolves install_requires itself and is far less fragile than
# `python3 setup.py install`.
RUN for i in 1 2 3; do \
      pip install --no-cache-dir . && break || \
      { [ "$i" -lt 3 ] && sleep 5 || exit 1; }; \
    done
ENTRYPOINT ["python3", "cloud_enum.py"]
