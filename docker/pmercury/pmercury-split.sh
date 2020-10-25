#!/bin/bash

while read line
do
        case "$line" in
                *'"fingerprints": {"tls"'* )
                        echo "$line" >> /output/tls_pmercury.json
                        ;;
                *'"fingerprints": {"tls_server"'* )
                        echo "$line" >> /output/tls_server_pmercury.json
                        ;;
                *'"fingerprints": {"'* )
                        echo "$line" >> /output/other_pmercury.json
                        ;;
        esac
done < <(/usr/local/bin/pmercury -c ${INT})
