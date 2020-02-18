FROM python:3.7-alpine
LABEL maintainer h4rm0ny
WORKDIR /bloodhound-data
VOLUME /bloodhound-data

COPY . /tmp/
RUN apk update && \
    apk add --no-cache --virtual .build-deps \
        build-base \
        openssl \
        bzip2 \
        dbus \
        glib \
        git \
        gcc \
        musl-dev \
        python3-dev \
        libffi-dev \
        libxslt \
        libxslt-dev \
        libgcrypt-dev \
        libxml2 \
        libxml2-dev \
        openssl-dev \
        dbus-libs \
        dbus-dev \
        dbus-glib-dev \
        linux-headers \
        make && \ 
	apk add --no-cache bash && \
    pip3 install --upgrade setuptools && \
    pip install git+https://github.com/SecureAuthCorp/impacket && \
    cd /tmp/ && \
    python setup.py install && \
    apk del .build-deps

ENTRYPOINT /bin/bash

