#!/bin/sh

#PASSWORD="SomeSecurePassword"

#HOME_DIR="/home/secadmin"

#echo '> Creating secadmin group and user accounts...'
# Add secadmin group
#groupadd secadmin

# Set up a secadmin user and add the insecure key for User to login
#useradd -G secadmin -m secadmin

# Avoid password expiration (https://github.com/vmware/photon-packer-templates/issues/2)
#chage -I -1 -m 0 -M 99999 -E -1 secadmin
#chage -I -1 -m 0 -M 99999 -E -1 root

#echo '> Adding secadmin to sudoers...'
# Configure a sudoers for the secadmin user
#echo "secadmin ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/secadmin

#echo '> Setting secadmin password...'
# Set secadmin password
#echo -e "$PASSWORD\n$PASSWORD" | passwd secadmin

echo '> Adding docker user and adding secadmin to docker group...'
# Add Docker group
groupadd docker
# Add Photon user to Docker group
usermod -a -G docker secadmin

#echo '> Setting global path environment variable for secadmin...'
# Set global path
#echo "PATH=/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin" >> /etc/environment