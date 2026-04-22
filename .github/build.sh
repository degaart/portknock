#!/bin/bash
set -eou pipefail

cat <<EOF > /etc/apt/sources.list
deb http://archive.debian.org/debian buster main contrib non-free
deb http://archive.debian.org/debian buster-updates main contrib non-free
deb http://archive.debian.org/debian-security/ buster/updates main contrib non-free
EOF

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -qy
apt-get install -qy build-essential curl

curl https://sh.rustup.rs -sSf|sh -s -- -y
source "$HOME/.cargo/env"

cargo build --release

