#!/bin/bash

# download secure-threat-monitor git repository to build containers
git clone https://github.com/1computerguy/secure-threat-monitor.git

# Pull git submodules
pushd secure-threat-monitor
git submodule update --init

popd
