FROM python:3.12-slim

WORKDIR /app

COPY . .

# Print output immediately so it shows up in `docker logs`
ENV PYTHONUNBUFFERED=1

# Server directory (config, plugins, regions, databases and backups)
VOLUME /data

EXPOSE 7240

HEALTHCHECK --interval=30s --timeout=5s --start-period=120s \
	CMD python -c "import os, socket; socket.create_connection(('127.0.0.1', int(os.environ.get('SC4MP_NETWORK_PORT', 7240))), 5).close()"

CMD ["python", "sc4mpserver.py", "--server-path", "/data", "--skip-update"]
