FROM python:alpine

WORKDIR /app
COPY app.py .
RUN pip install flask

RUN apk add --no-cache \
    bash \
    tar \
    gzip \
    coreutils \
    procps \
    netcat-openbsd \
    sqlite \
    iputils \
    curl

CMD ["python", "app.py"]
