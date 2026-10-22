FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.prod.txt .
RUN pip install -r requirements.prod.txt

COPY server.py .

# Roda sem privilégios de root
RUN useradd --system --uid 10001 --no-create-home app
USER app

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8001/api/')" || exit 1

# --proxy-headers: confia no X-Forwarded-For do Nginx (IP real do cliente no bloqueio de login)
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
