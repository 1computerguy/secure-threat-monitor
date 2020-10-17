#!/bin/bash

echo "> Pull secure-threat-monitor git repo and submodules..."
# download secure-threat-monitor git repository to build containers
git clone https://github.com/1computerguy/secure-threat-monitor.git
pushd secure-threat-monitor
git submodule update --init --recursive
popd

echo "> Move secure-threat-monitor to monadmin home"
mv secure-threat-monitor /home/monadmin/
pushd /home/monadmin
chown -R monadmin:monadmin secure-threat-monitor

echo "> Move docker-compose to monadmin home directory..."
mv secure-threat-monitor/docker/docker-compose.yml /home/monadmin/docker-compose.yml

mkdir -p /var/log/checkip

echo "> Building containers with docker-compose..."
docker-compose build -d
popd
