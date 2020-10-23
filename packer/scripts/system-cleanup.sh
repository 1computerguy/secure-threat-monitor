#!/bin/bash -eux

##
## cleanup everything we can to make the OVA as small as possible
##

echo '> Clearing apt cache and removing unnecessary applications...'
#Getting rid of partial packages
sudo apt-get clean && sudo apt-get autoclean
sudo apt-get remove --purge -y software-properties-common

#Getting rid of no longer required packages
sudo apt-get autoremove -y

#Getting rid of orphaned packages
sudo deborphan | xargs sudo apt-get -y remove --purge

#Free up space by clean out the cached packages
sudo apt-get clean

# Cleanup log files
echo '> Removing Log files...'
#Delete all .gz and rotated file
sudo find /var/log -type f -regex ".*\.gz$" | xargs sudo rm -Rf
sudo find /var/log -type f -regex ".*\.[0-9]$" | xargs sudo rm -Rf

#logrotate -f /etc/logrotate.conf 2>/dev/null
sudo find /var/log -type f -delete
sudo rm -rf /var/log/journal/*
sudo rm -f /var/lib/dhcp/*

# Zero out the free space to save space in the final image, blocking 'til
# written otherwise, the disk image won't be zeroed, and/or Packer will try to
# kill the box while the disk is still full and that's bad.  The dd will run
# 'til failure, so (due to the 'set -e' above), ignore that failure.  Also,
# really make certain that both the zeros and the file removal really sync; the
# extra sleep 1 and sync shouldn't be necessary, but...)
echo '> Zeroing device to make space...'
sudo dd if=/dev/zero of=/EMPTY bs=1M || true; sync; sleep 1; sync
sudo rm -f /EMPTY; sync; sleep 1; sync

unset HISTFILE && history -c && rm -fr /home/secadmin/.bash_history

#echo '> Shrinking disk...'
#sudo vmware-toolbox-cmd disk shrink /

echo '> Done'
