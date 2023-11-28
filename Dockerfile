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
        rust \
        cargo \
        make && \ 
	apk add --no-cache bash && \
    pip3 install --upgrade setuptools && \
    pip install git+https://github.com/SecureAuthCorp/impacket && \
    pip install pycryptodome && \
    cd /tmp/ && \
    python setup.py install && \
    apk del .build-deps

# Enable MD4
RUN sed -i 's/default = default_sect/default = default_sect\nlegacy = legacy_sect/g' /etc/ssl/openssl.cnf
RUN sed -i 's/# activate = 1/activate = 1\n\n[legacy_sect]\nactivate = 1/' /etc/ssl/openssl.cnf

ENTRYPOINT /bin/bash

