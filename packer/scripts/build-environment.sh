#!/bin/bash

sudo apt update && sudo apt upgrade -y

pushd /home/secadmin

echo "> Download required docker and resource directories..."
# download secure-threat-monitor git repository to build containers
svn export https://github.com/1computerguy/secure-threat-monitor/trunk/docker
pushd docker/pmercury
svn export https://github.com/cisco/mercury/trunk/resources
popd

echo "> Set permissions for secadmin resources..."
chown -R secadmin:secadmin {docker,resources}

echo "> Move docker-compose to secadmin home directory..."
mv /home/secadmin/docker/docker-compose.yml /home/secadmin/docker-compose.yml
mkdir -p /var/log/{checkip,pmercury}

echo "> Building containers with docker-compose..."
docker-compose build --force-rm
docker-compose pull
