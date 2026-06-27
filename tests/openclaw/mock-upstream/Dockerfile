FROM python:3.13-slim

WORKDIR /app
RUN pip install --no-cache-dir fastapi uvicorn
COPY app.py .

EXPOSE 9999

HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:9999/healthz')"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9999"]
