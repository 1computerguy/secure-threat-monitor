FROM python:slim

LABEL maintainer="Bryan Scarbrough <bryan.scarbrough@gmail.com>" \
    org.label-schema.schema-version="1.0" \
    org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.name="checkip" \
    org.label-schema.description="Malicious IP validation using urlhaus and Alienvault from pMercury output" \
    org.label-schema.url="https://github.com/1computerguy/secure-threat-monitor" \
    org.label-schema.vcs-url="https://github.com/1computerguy/secure-threat-monitor" \
    org.label-schema.docker.cmd="docker run --rm -it checkip:v1.0"

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

RUN mkdir -p /checkip/pmercury && \
    mkdir -p /checkip/resources && \
    mkdir -p /checkip/output

COPY ./scripts/* /checkip/
COPY ./GeoLite2-City.mmdb /checkip/resources/

WORKDIR /checkip

ENTRYPOINT [ "python3", "/checkip/check.py" ]
