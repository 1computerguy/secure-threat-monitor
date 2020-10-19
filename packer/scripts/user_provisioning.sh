#!/bin/sh

PASSWORD="SomeSecurePassword"

HOME_DIR="/home/monadmin"

echo '> Creating monadmin group and user accounts...'
# Add monadmin group
groupadd monadmin

# Set up a monadmin user and add the insecure key for User to login
useradd -G monadmin -m monadmin

# Avoid password expiration (https://github.com/vmware/photon-packer-templates/issues/2)
chage -I -1 -m 0 -M 99999 -E -1 monadmin
chage -I -1 -m 0 -M 99999 -E -1 root

echo '> Adding monadmin to sudoers...'
# Configure a sudoers for the monadmin user
echo "monadmin ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/monadmin

echo '> Setting monadmin password...'
# Set monadmin password
echo -e "$PASSWORD\n$PASSWORD" | passwd monadmin

echo '> Adding docker user and adding monadmin to docker group...'
# Add Docker group
groupadd docker
# Add Photon user to Docker group
usermod -a -G docker monadmin

echo '> Setting global path environment variable for users...'
# Set global path
echo "PATH=/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin" >> /etc/environment