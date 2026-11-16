FROM python:3.14-slim

ARG THREATLENS_VERSION=dev

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    THREATLENS_VERSION=${THREATLENS_VERSION}

WORKDIR /app

RUN addgroup --system threatlens \
    && adduser --system --ingroup threatlens threatlens

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY alembic.ini .

RUN mkdir -p /app/data \
    && chown -R threatlens:threatlens /app

USER threatlens

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + str(int(os.environ.get('PORT', '8000'))) + '/ready', timeout=3)"

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port \"$PORT\""]
