# AccessDesk in a container, meant to sit behind an HTTPS reverse proxy. See "Run it on your own server" in
# GUIDE.md. Publish the port on 127.0.0.1 only, so everything goes through the proxy:
#   docker build -t accessdesk .
#   docker run -d --name accessdesk -p 127.0.0.1:8000:8000 -v accessdesk-data:/data --env-file accessdesk.env accessdesk
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ACCESSDESK_DB=/data/accessdesk.db

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . \
    && useradd --system --uid 10001 --user-group --home-dir /data --create-home --shell /usr/sbin/nologin accessdesk \
    && chmod 700 /data

# Never run as root. The database lives on the /data volume.
USER accessdesk
VOLUME ["/data"]
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4)"]
CMD ["accessdesk", "serve", "--host", "0.0.0.0", "--port", "8000"]
