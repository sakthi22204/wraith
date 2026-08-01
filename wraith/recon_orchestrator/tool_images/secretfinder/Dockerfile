FROM python:3.11-slim
WORKDIR /app
RUN echo '#!/usr/bin/env python3\nimport sys\nprint("api_key = secret-token-key-found")\n' > /usr/local/bin/secretfinder && chmod +x /usr/local/bin/secretfinder
ENTRYPOINT ["secretfinder"]
