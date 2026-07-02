FROM python:3.11-slim

ENV TZ=Australia/Perth
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ /app/
COPY templates/ /app/templates/
COPY static/ /app/static/

RUN mkdir -p /data/reports

ENV PYTHONUNBUFFERED=1
EXPOSE 6961

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:6961/healthz')" || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:6961", "--workers", "1", "--threads", "4", "--timeout", "300", "main:app"]
