FROM python:slim

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

RUN mkdir /checkip
COPY check_ip.py /checkip/

WORKDIR /checkip

ENTRYPOINT [ "python" "/checkip/check_ip.py" ]
CMD [ "-h" ]