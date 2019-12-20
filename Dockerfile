FROM python:3.7-alpine
RUN apk update
# install dependencies
RUN apk add --no-cache  build-base openssl \
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
                        make \ 
			bash

RUN pip3 install --upgrade setuptools

RUN mkdir /bloodhound-data
WORKDIR /bloodhound-data
RUN pip3 install impacket 'ldap3==2.5.1' dnspython bloodhound

VOLUME /bloodhound-data

ENTRYPOINT /bin/bash
