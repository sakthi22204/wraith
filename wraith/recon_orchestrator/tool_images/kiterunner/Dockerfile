FROM python:3.11-slim
WORKDIR /app
RUN echo '#!/usr/bin/env python3\nimport sys, json\nprint(json.dumps({"url": "http://localhost/api", "method": "GET"}))\nprint(json.dumps({"url": "http://localhost/v1", "method": "GET"}))\n' > /usr/local/bin/kb && chmod +x /usr/local/bin/kb
CMD ["kb"]
