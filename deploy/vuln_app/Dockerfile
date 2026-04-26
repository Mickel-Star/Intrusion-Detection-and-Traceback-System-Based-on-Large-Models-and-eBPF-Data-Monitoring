FROM python:alpine

WORKDIR /app
COPY app.py .
RUN pip install flask

RUN apk add --no-cache iputils curl

CMD ["python", "app.py"]
