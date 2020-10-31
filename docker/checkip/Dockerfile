FROM python:slim

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

RUN mkdir -p /checkip/{resources,output}
COPY ./scripts/* /checkip
COPY ./GeoLite2-City.mmdb /checkip/resources/

WORKDIR /checkip

ENTRYPOINT [ "python3" "/checkip/check_ip.py" ]
