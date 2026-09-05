FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Hosts inject the port to listen on via $PORT; default to 8050 locally.
ENV PORT=8050
EXPOSE 8050
# Production WSGI server. One worker + threads keeps the in-process scheduler
# single and lets slow scans run without blocking the whole server.
CMD gunicorn --workers 1 --threads 8 --timeout 180 --bind 0.0.0.0:${PORT} "argus.api.app:create_app()"