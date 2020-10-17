#!/bin/sh

PASSWORD="SomeSecurePassword"

HOME_DIR="/home/monadmin"

# Add monadmin group
groupadd monadmin

# Set up a monadmin user and add the insecure key for User to login
useradd -G monadmin -m monadmin

# Avoid password expiration (https://github.com/vmware/photon-packer-templates/issues/2)
chage -I -1 -m 0 -M 99999 -E -1 monadmin
chage -I -1 -m 0 -M 99999 -E -1 root

# Configure a sudoers for the monadmin user
echo "monadmin ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/monadmin

# Set monadmin password
echo -e "$PASSWORD\n$PASSWORD" | passwd monadmin

# Add Docker group
groupadd docker

# Add Photon user to Docker group
usermod -a -G docker monadmin