#!/bin/bash

pushd /home/monadmin

echo "> Download required docker and resource directories..."
# download secure-threat-monitor git repository to build containers
svn export https://github.com/1computerguy/secure-threat-monitor/trunk/docker
pushd docker/pmercury
svn export https://github.com/cisco/mercury/trunk/resources
popd

echo "> Set permissions for monadmin resources..."
chown -R monadmin:monadmin {docker,resources}

echo "> Move docker-compose to monadmin home directory..."
mv /home/monadmin/docker/docker-compose.yml /home/monadmin/docker-compose.yml
mkdir -p /var/log/{checkip,pmercury}

echo "> Building containers with docker-compose..."
docker-compose build --force-rm
docker-compose pull
