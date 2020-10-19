#!/bin/sh

tdnf --assumeyes update && tdnf --assumeyes upgrade

curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod 655 /usr/local/bin/docker-compose

systemctl enable docker
systemctl start docker
