FROM python:3.10-slim

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y; \
    rm -rf /var/lib/apt/lists/*; \
    apt-get clean

WORKDIR /apex

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY config.py .
COPY script.py .

ENV TZ="Europe/Paris"

EXPOSE 9400

CMD [ "script.py" ]
ENTRYPOINT [ "python" ]