#!/bin/bash
set -eu

echo "#########################################"
echo "## Installing packages"
echo "############"

apt update \
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

echo
echo "#########################################"
echo "## Installing PIP"
echo "############"

python3 -m pip install --upgrade pip
python3 -m pip install --upgrade wheel setuptools

echo
echo "#########################################"
echo "## Installing kaitai"
echo "############"

pushd /tmp/
apt update \
  && curl -fsSL -O https://github.com/kaitai-io/kaitai_struct_compiler/releases/download/0.10/kaitai-struct-compiler_0.10_all.deb \
  && apt install ./kaitai-struct-compiler_0.10_all.deb \
  && echo 'en_US.UTF-8 UTF-8' | tee /etc/locale.gen \
  && echo 'LANG="en_US.UTF-8"' | tee /etc/default/locale \
  && dpkg-reconfigure --frontend=noninteractive locales \
  && locale \
  && ksc --version
popd


echo
echo "#########################################"
echo "## Build Python class from Kaitai Struct (PE parser)"
echo "############"

# Build Python class from Kaitai Struct (PE parser)
rm -rf ./dist/
ksc -t python --outdir ./avsniper/formats/ --python-package avsniper ./avsniper/structs/*.ksy


echo
echo "#########################################"
echo "## Installing python test packages"
echo "############"

# Install Python Test dependencies
python3 -m pip install -r tests/requirements-test.txt

echo
echo "#########################################"
echo "## Downloading Binutils"
echo "############"

if [ ! -f "/tmp/binutils.zip" ]; then
    releases=$(curl -k -s https://api.github.com/repos/helviojunior/shellcodetester/releases)
    echo "$releases"

    url=$(echo "$releases" | jq -r '[ .[] | {id: .id, tag_name: .tag_name, assets: [ .assets[] | select(.name|match("binutils.zip$")) | {name: .name, browser_download_url: .browser_download_url} ]} | select(.assets != []) ] | sort_by(.id) | reverse | first(.[].assets[]) | .browser_download_url')

    if [ "W$url" = "W" ]; then
        echo "Binutils Release url not found"
        exit 1
    fi

    echo "Available URL for Binutils: ${url}"
    pushd /tmp/
    curl -fsSL -O "${url}"
    popd
fi

unzip -o /tmp/binutils.zip -d ./avsniper/libs/binutils/
touch ./avsniper/libs/binutils/__init__.py
touch ./avsniper/libs/binutils/linux/__init__.py
touch ./avsniper/libs/binutils/windows/__init__.py
touch ./avsniper/libs/binutils/macosx/__init__.py

# Remove nasm from package
find ./avsniper/libs/binutils/ -type f -name "nasm*" -exec rm -rf "{}" \;

# Change build version
#oldv=$( grep '__version__' avsniper/__meta__.py | grep -oE '[0-9\.]+')
#current=$(date '+%Y%m%d%H%M%S')
#meta=$(cat avsniper/__meta__.py | sed "s/__version__.*/__version__ = '"${oldv}"-"${current}"'/")
#echo "$meta" > avsniper/__meta__.py


echo
echo "#########################################"
echo "## Installing python project"
echo "############"

# Install locally the package
python3 -m pip install .


echo
echo "#########################################"
echo "## Running unit tests"
echo "############"

# Do unit tests
pytest -s tests/tests.py


echo
echo "#########################################"
echo "## Creating SDIST package"
echo "############"

# Remove folders
rm -rf ./{docs,tests,tools}

# Create package
python3 setup.py sdist

# Copy generated package
find ./dist/ -type f -name "*avsniper*.tar.gz" -exec cp "{}" "./dist/avsniper-latest.tar.gz" \;
