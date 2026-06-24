FROM python:3.11-slim

WORKDIR /app

# System deps needed for psycopg2 and dnspython builds
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir celery==5.4.0 redis==5.0.7 apscheduler==3.10.4

COPY . .

CMD ["celery", "-A", "tasks.celery_app", "worker", "--loglevel=info"]
