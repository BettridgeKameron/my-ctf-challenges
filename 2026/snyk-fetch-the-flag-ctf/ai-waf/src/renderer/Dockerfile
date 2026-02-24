FROM python:3.11-slim

ARG FLAG_PART1

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r /app/requirements.txt

RUN echo "$FLAG_PART1" > /flag.txt && chmod 444 /flag.txt

USER nobody

CMD ["python", "/app/main.py"]
