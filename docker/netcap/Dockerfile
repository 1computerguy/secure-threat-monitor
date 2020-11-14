FROM dreadl0ck/netcap:alpine-v0.5.9

RUN mkdir -p /usr/local/etc/netcap/dbs 

COPY ./resources/* /usr/local/etc/netcap/dbs/

ENTRYPOINT ["net"]
CMD ["--help"]
