FROM python:3.11-slim
WORKDIR /app
RUN echo '#!/usr/bin/env python3\nimport sys\nprint("git repository found exposed!")\n' > /usr/local/bin/gittools && chmod +x /usr/local/bin/gittools
ENTRYPOINT ["gittools"]
