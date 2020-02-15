FROM python:3.8-alpine
RUN apk add --no-cache \
        gcc \
        musl-dev \
        curl-dev \
        openssl \
        openssl-dev \
        linux-headers

COPY . /opt/egress0r
WORKDIR /opt/egress0r
RUN python3 -m venv ./venv \
    && venv/bin/pip install --upgrade pip \
    && PYCURL_SSL_LIBRARY=openssl venv/bin/pip install -r ./requirements.txt

ENTRYPOINT ["venv/bin/python"]
CMD ["main.py"]
