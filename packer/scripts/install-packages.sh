#!/bin/bash

echo "< Checking for and installing updates..."
sudo apt update && sudo apt upgrade -y
#tdnf --assumeyes update && tdnf --assumeyes upgrade

#curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
#chmod 655 /usr/local/bin/docker-compose

echo "< Installing git, docker.io, and docker-compose..."
sudo apt install -y git docker.io docker-compose open-vm-tools

echo "< Enable and start the docker service..."
systemctl enable docker
systemctl start docker
