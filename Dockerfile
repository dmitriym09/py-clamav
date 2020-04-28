FROM python:3.8.2-slim-buster
LABEL maintainer="dmitriym.09.12.1989@gmail.com"

RUN apt update && \
    apt install software-properties-common -y && \
    apt-add-repository non-free && \
    apt update && \
    apt install libclamav9 libclamunrar9 curl -y && \
    pip install py-clamav && \
    mkdir /var/lib/clamav -p && \
    curl --output /var/lib/clamav/main.cvd http://database.clamav.net/main.cvd && \
    curl --output /var/lib/clamav/daily.cvd http://database.clamav.net/daily.cvd && \
    curl --output /var/lib/clamav/bytecode.cvd http://database.clamav.net/bytecode.cvd && \
    apt-get clean && \
    rm -rf /var/cache/apt/archives/*
