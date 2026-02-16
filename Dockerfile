FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Базовые утилиты + зависимости для CryptoPro
RUN apt-get update && apt-get install -y \
        netcat-openbsd \
        procps \
        wget \
        lsb-release \
    && rm -rf /var/lib/apt/lists/*

# Установка CryptoPro CSP из архива
COPY linux-amd64_deb.tgz /tmp/
RUN cd /tmp \
    && tar -xzf linux-amd64_deb.tgz \
    && cd linux-amd64_deb \
    && ./install.sh \
    && rm -rf /tmp/linux-amd64_deb*

WORKDIR /app

COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

# Чтобы утилиты CryptoPro были в PATH (по желанию, но удобно)
ENV PATH="/opt/cprocsp/bin/amd64:${PATH}"
ENV LD_LIBRARY_PATH="/opt/cprocsp/lib/linux-amd64:${LD_LIBRARY_PATH}"

EXPOSE 8000
