#!/bin/sh

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

# Set up insecure monadmin key
mkdir -p ${HOME_DIR}/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ== monadmin insecure public key" > ${HOME_DIR}/.ssh/authorized_keys
chown -R monadmin:monadmin ${HOME_DIR}/.ssh
chmod 700 ${HOME_DIR}/.ssh
chmod 600 ${HOME_DIR}/.ssh/authorized_keys

# Add Docker group
groupadd docker

# Add Photon user to Docker group
usermod -a -G docker monadmin