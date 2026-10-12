FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    DATA_DIR=/data \
    TZ=Europe/Madrid

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY static ./static

VOLUME /data
EXPOSE 8080

# Single worker: the polling scheduler lives inside the process.
CMD ["gunicorn", "-b", "0.0.0.0:8080", "-w", "1", "--threads", "8", "--timeout", "400", "app:app"]
