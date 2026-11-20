FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --timeout=120 --retries=10 -r requirements.txt

COPY . .

EXPOSE 8011

CMD ["sh", "-c", "exec uvicorn app.main:app --host \"${NATIVE_HOST_AGENT_HOST:-127.0.0.1}\" --port \"${NATIVE_HOST_AGENT_PORT:-8011}\""]
