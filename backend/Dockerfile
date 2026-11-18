FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    netcat-traditional \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --upgrade pip && pip install -r /app/requirements.txt

# Copy the entrypoint to a safe location (NOT overwritten by bind mounts)
COPY entrypoint.sh /usr/local/bin/cisobrief-entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/cisobrief-entrypoint.sh && chmod +x /usr/local/bin/cisobrief-entrypoint.sh

# Copy the rest of the app
COPY . /app

EXPOSE 8000
