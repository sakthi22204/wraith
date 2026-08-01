FROM python:3.11-slim
WORKDIR /app
RUN mkdir /wordlists && echo "api\nadmin\nusers" > /wordlists/common.txt
RUN echo '#!/usr/bin/env python3\nimport sys, json\nprint(json.dumps({"url": "http://localhost/api"}))\nprint(json.dumps({"url": "http://localhost/admin"}))\n' > /usr/local/bin/ffuf && chmod +x /usr/local/bin/ffuf
ENTRYPOINT ["ffuf"]
