#!/bin/bash

# Had to separate this one in order to download all necessary resources - like the 
# Maxmind database to the local repo since it cannot be shared on GitHub and it cannot
# be downloaded without logging into an account. So it gets pre-positioned on the local
# system, uploaded to the necessary directories, then we build the containers.
echo "> Building containers with docker-compose..."
sudo docker-compose build --force-rm
sudo docker-compose pull