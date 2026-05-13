FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    wget \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# upgrade tooling
RUN pip install --no-cache-dir --upgrade pip setuptools wheel hatchling

# COPY FIRST (needed for pyproject)
COPY . .

# install python dependencies FIRST (this provides playwright CLI)
RUN pip install --no-cache-dir -e .

# NOW playwright CLI exists → safe to run
RUN python -m playwright install --with-deps chromium

# create user
RUN useradd --create-home --shell /bin/bash appuser && \
    chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000"]