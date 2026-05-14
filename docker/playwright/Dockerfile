FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin playwright
RUN mkdir -p /browser-state && chown -R playwright:playwright /browser-state /app

USER playwright

CMD ["python", "-m", "http.server", "9333"]
