#!/bin/bash

# Pull and build NetCap container
git clone https://github.com/dreadl0ck/netcap.git

pushd netcap
git checkout v0.5
docker build . --tag netcap
popd
rm -rf netcap

# Pull and build Cisco Mercury container
git clone https://github.com/cisco/mercury.git

pushd mercury
docker build . --tag mercury
popd
rm -rf mercury

# Pull sFlow containers
docker pull sflow/prometheus
docker pull sflow/host-sflow
docker pull sflow/sflowtool

# Pull Prometheus time-based DB container
docker pull prom/prometheus

# Pull Grafana container
docker pull grafana/grafana

# download secure-threat-monitor git repository to build containers
git clone https://github.com/1computerguy/secure-threat-monitor.git

mv secure-threat-monitor/docker/docker-compose.yml .