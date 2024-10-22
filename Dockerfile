FROM ubuntu:latest as compile
MAINTAINER Helvio Junior <helvio_junior@hotmail.com>

USER root

SHELL ["/bin/bash", "-xo", "pipefail", "-c"]

# Generate locale C.UTF-8
ENV LANG C.UTF-8
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

COPY ./requirements.txt /tmp/
COPY ./tests/requirements-test.txt /tmp/

# Update and install dependencies
RUN apt update \
  && apt upgrade -y \
  && apt install -yqq --no-install-recommends \
      git \
      gcc \
      python3 \
      python3-pip \
      python3-dev \
      build-essential \
      libssl-dev \
      libffi-dev\
      python3-setuptools \
      unzip \
      default-jre-headless \
      default-jdk \
      libmagic-dev \
      curl \
      wget \
      gpg \
      vim \
      ssh \
      locales \
      make \
      libc6-dev \
      graphviz \
      rsync \
      wget \
      jq \
      zip \
      unzip \
      curl \
      ca-certificates \
      apt-utils \
  && apt clean all \
  && apt autoremove \
  && python3 -m pip install --upgrade pip \
  && python3 -m pip install --upgrade wheel setuptools \
  && python3 -m pip install -r /tmp/requirements.txt \
  && python3 -m pip install -r /tmp/requirements-test.txt

# Update and install dependencies
RUN apt update \
  && mkdir /u01/ \
  && cd /tmp/ \
  && curl -fsSL -O https://github.com/kaitai-io/kaitai_struct_compiler/releases/download/0.10/kaitai-struct-compiler_0.10_all.deb \
  && apt install ./kaitai-struct-compiler_0.10_all.deb \
  && echo 'en_US.UTF-8 UTF-8' | tee /etc/locale.gen \
  && echo 'LANG="en_US.UTF-8"' | tee /etc/default/locale \
  && dpkg-reconfigure --frontend=noninteractive locales \
  && locale \
  && ksc --version

# Download binutils package
RUN cd /root \
  && url=$(curl -s https://api.github.com/repos/helviojunior/shellcodetester/releases | jq -r '[ .[] | {id: .id, tag_name: .tag_name, assets: [ .assets[] | select(.name|match("binutils.zip$")) | {name: .name, browser_download_url: .browser_download_url} ]} | select(.assets != []) ] | sort_by(.id) | reverse | first(.[].assets[]) | .browser_download_url') \
  && curl -fsSL -O "${url}"

WORKDIR /u01/

RUN printf "#!/bin/bash \n \
# Starter \n \
set -eu \n \
ksc -t python --outdir ./avsniper/formats/ --python-package avsniper ./avsniper/structs/*.ksy \n \
python3 -m pip install --upgrade pip wheel setuptools \n \
python3 -m pip install -r tests/requirements-test.txt \n \
unzip -o /root/binutils.zip -d ./avsniper/libs/binutils/ \n \
touch ./avsniper/libs/binutils/__init__.py \n \
touch ./avsniper/libs/binutils/linux/__init__.py \n \
touch ./avsniper/libs/binutils/windows/__init__.py \n \
touch ./avsniper/libs/binutils/macosx/__init__.py \n \
python3 -m pip install . \n \
pytest -s tests/tests.py \n \
python3 setup.py sdist \n " > /root/start.sh \
  && chmod +x /root/start.sh

ENTRYPOINT ["/root/start.sh"]
