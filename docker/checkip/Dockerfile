FROM python:slim

COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

RUN mkdir /check
COPY check_ip.py get_malicious.py /check/

WORKDIR /check

ENTRYPOINT [ "python" "/check/check_ip.py" ]
CMD [ "-h" ]