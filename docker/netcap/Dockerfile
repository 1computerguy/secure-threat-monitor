FROM dreadl0ck/netcap:alpine-v0.5.9

RUN mkdir -p /usr/local/etc/netcap/dbs && \
    wget https://macaddress.io/database/macaddress.io-db.json -O /usr/local/etc/netcap/dbs/macaddress.io-db.json && \
    wget https://svn.nmap.org/nmap/nmap-service-probes -O /usr/local/etc/netcap/dbs/nmap-service-probes && \
    wget https://raw.githubusercontent.com/tobie/ua-parser/master/regexes.yaml -O /usr/local/etc/netcap/dbs/regexes.yaml && \
    wget https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv -O /usr/local/etc/netcap/dbs/service-names-port-numbers.csv && \
    wget https://raw.githubusercontent.com/salesforce/hassh/master/python/hasshGen/hassh_fingerprints.json -O /usr/local/etc/netcap/dbs/hasshdb.json

COPY GeoLite2-City.mmdb GeoLite2-Country.mmdb GeoLite2-ASN.mmdb \
     ja_3_3s.json ja3UserAgents.json ja3fingerprint.json ja3erDB.json \
     domain-whitelist.csv /usr/local/etc/netcap/dbs/

ENTRYPOINT ["net"]
CMD ["--help"]
