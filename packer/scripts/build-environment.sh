#!/bin/bash

echo "> Checking for and installing updates..."
sudo apt update && sudo apt upgrade -y

echo "> Installing git, docker.io, and docker-compose..."
sudo apt install -y git docker.io docker-compose open-vm-tools findutils subversion

echo "> Enable and start the docker service..."
sudo systemctl enable docker
sudo systemctl start docker

echo '> Adding docker user and adding secadmin to docker group...'
# Add Docker group
sudo groupadd docker
# Add Photon user to Docker group
sudo usermod -a -G docker secadmin

echo "> Download required docker and resource directories..."
# download secure-threat-monitor git repository to build containers
svn export https://github.com/1computerguy/secure-threat-monitor/trunk/docker
pushd docker/pmercury
svn export https://github.com/cisco/mercury/trunk/resources
popd

echo "> Set permissions for secadmin resources..."
sudo chown -R secadmin:secadmin docker

echo "> Move docker-compose to secadmin home directory..."
mv /home/secadmin/docker/docker-compose.yml /home/secadmin/docker-compose.yml

# Set up HGFS generic mount point
echo "> Create hgfs mount directory for shared folders - in case we need them..."
sudo mkdir -p /mnt/hgfs
