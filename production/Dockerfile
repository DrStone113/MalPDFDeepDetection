FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=7860 \
    MALPDF_QUARANTINE_DIR=/tmp/malpdf_quarantine

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libqpdf-dev \
    && rm -rf /var/lib/apt/lists/*

COPY production/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

COPY src/malpdf /app/src/malpdf
COPY production/configs /app/configs
COPY production/models /app/models
COPY production/__init__.py production/onnx_taxonomy.py production/onnx_engine.py production/web_service.py production/app.py /app/

EXPOSE 7860

CMD ["python", "app.py"]

