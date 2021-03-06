FROM ubuntu:20.04 as initial
ARG DEBIAN_FRONTEND=noninteractive

COPY requirements.txt /tmp/requirements.txt

ENV MERCURY_DEPS build-essential libpcap-dev python3 python3-dev \
    python3-pip python3-setuptools

RUN mkdir -p /output/usr/local
ENV PYTHONUSERBASE=/output/usr/local

RUN apt-get update && apt-get install -y --no-install-recommends $MERCURY_DEPS

RUN pip3 install --user --ignore-installed -r /tmp/requirements.txt


# Copy packages to fresh container
FROM ubuntu:20.04

LABEL maintainer="Bryan Scarbrough <bryan.scarbrough@gmail.com>" \
    org.label-schema.schema-version="1.0" \
    org.label-schema.build-date=$BUILD_DATE \
    org.label-schema.vcs-ref=$VCS_REF \
    org.label-schema.name="pmercury" \
    org.label-schema.description="SSL/TLS Fingerprints output in json format and split by protocol type" \
    org.label-schema.url="https://github.com/1computerguy/secure-threat-monitor" \
    org.label-schema.vcs-url="https://github.com/1computerguy/secure-threat-monitor" \
    org.label-schema.docker.cmd="docker run --rm -it pmercury:v1.0"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
            python3-minimal python3-setuptools

RUN mkdir /output
RUN mkdir -p /pmercury/resources

COPY ./config.yaml /pmercury/config.yaml
COPY ./resources /pmercury/resources
COPY ./pmercury-split.sh /usr/local/bin/pmercury-split.sh
COPY --from=initial /output/usr/local /usr/local

# `pip install --user` will place things in `site-packages`, but Ubuntu expects
# `dist-packages` by default, so we need to set configure `site-packages` as an
# additional "site-specific directory".
RUN export PYTHON3_VERSION=`python3 -c 'import sys; version=sys.version_info[:3]; print("python{0}.{1}".format(*version))'` && \
    echo "import site; site.addsitedir('/usr/local/lib/$PYTHON3_VERSION/site-packages')" \
    > /usr/local/lib/$PYTHON3_VERSION/dist-packages/use_site_packages.pth

RUN ldconfig && chmod +x /usr/local/bin/pmercury-split.sh

ENTRYPOINT ["/usr/local/bin/pmercury-split.sh"]