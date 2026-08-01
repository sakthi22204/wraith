FROM python:3.11-slim
WORKDIR /app
RUN echo '#!/usr/bin/env python3\nimport sys\nprint("/api/v1/users")\nprint("/admin/config")\n' > /usr/local/bin/linkfinder && chmod +x /usr/local/bin/linkfinder
ENTRYPOINT ["linkfinder"]
