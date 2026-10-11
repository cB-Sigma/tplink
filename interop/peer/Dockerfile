# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# python-kasa (GPL-3.0, github.com/python-kasa/python-kasa) as an interop
# peer: its transports' crypto and its recorded device fixtures. It is
# installed from PyPI, and the fixtures are downloaded from its release
# tag, at build time inside the image only; nothing of python-kasa is
# copied into this repository.
FROM python:3.12.10-slim
ARG KASA_VERSION=0.11.0.1
RUN pip install --no-cache-dir python-kasa==${KASA_VERSION}
ADD https://github.com/python-kasa/python-kasa/archive/refs/tags/${KASA_VERSION}.tar.gz /python-kasa.tgz
RUN mkdir /python-kasa && tar -xzf /python-kasa.tgz -C /python-kasa --strip-components=1 && rm /python-kasa.tgz
COPY device.py /peer/device.py
WORKDIR /peer
