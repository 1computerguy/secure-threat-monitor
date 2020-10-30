#!/usr/bin/env python

import time
import os
import argparse
import json
import logging

from OTXv2 import OTXv2
from check_ip import ip, hostname
from taillog import follow
from datetime import datetime, timezone
from dateutil.parser import parse
from queue import Queue
from threading import Thread

logger = logging.getLogger(__name__)

class OneLineExceptionFormatter(logging.Formatter):
    def formatException(self, exc_info):
        result = super().formatException(exc_info)
        return repr(result)
 
    def format(self, record):
        result = super().format(record)
        if record.exc_text:
            result = result.replace("\n", "")
        return result

class DownloadWorker(Thread):

    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue

    def run(self):
        while True:
            # Get the work from the queue and expand the tuple
            otx, ip_addr, host, urlhaus_api, mmdb, timestamp, outfile = self.queue.get()
            try:
                write_data(ip(otx, ip_addr, mmdb, timestamp), outfile)
                write_data(hostname(host, mmdb, urlhaus_api, timestamp), outfile)
            finally:
                self.queue.task_done()

def write_data(output, filename):
    try:
        with open(filename, 'a') as outfile:
            json.dump(output, outfile)
            outfile.write("\n")
    except Exception as e:
        logging.exception("There was a problem writing data to file... {}".format(e))
        exit(1)        

def main():
    '''Run check_ip and taillog for malicious IP validation and write output to file
    '''
    # Get Command line arguments
    parser = argparse.ArgumentParser(description='Watch log file and pass IP and hostname to check_ip.py')
    parser.add_argument('-f', '--file', action='store', dest='infile', help='Log file to follow for IP and Host info', required=False)
    parser.add_argument('-i', '--ip', action='store', dest='ip', help='IP address to check with AlienVault', required=False)
    parser.add_argument('-t', '--host', action='store', dest='host', help='Hostname to check with URLHause.abuse.ch', required=False)
    parser.add_argument('-o', '--outfile', action='store', dest='outfile', help='File to write output date to.', default="output.json", required=False)
    parser.add_argument('-d', '--db', action='store', dest='mmdb', help='Location of MaxMind City DB', default="../netcap/resources/GeoLite2-City.mmdb", required=False)
    parser.add_argument('-a', '--api', action='store', dest='api_key', help='API Key obtained from Alienvault OTX website', required=False)

    # Set logging before beginning
    handler = logging.StreamHandler()
    formatter = OneLineExceptionFormatter("%(asctime)s - %(levelname)s|%(message)s","%d/%m/%Y %H:%M:%S")
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.setLevel(os.environ.get("LOGLEVEL", "WARNING"))
    root.addHandler(handler)

    # Get options and set timestamp
    options = parser.parse_args()

    if os.environ.get('API_KEY'):
        api_key = os.environ.get('API_KEY')
    elif options.api_key:
        api_key = options.api_key
    else:
        logging.error('Please provide your Alienvault OTX API Key as the API_KEY environment variable or use the --api command-line argument.')
        exit(1)

    # Set URLs and instantiate OTX object
    urlhaus_api = "https://urlhaus-api.abuse.ch/v1/"
    OTX_SERVER = 'https://otx.alienvault.com/'
    otx = OTXv2(api_key, server=OTX_SERVER)

    if options.infile:
        # In case watch file doesn't exist, we'll wait till it's created
        while not os.path.exists(options.infile):
            time.sleep(1)

        # Open file and create initial empty set()
        file_to_follow = open(options.infile,"r")
        data_to_check = set()

        # If there is existing data in the file the use it to prepopulate the
        # data_to_check set so we don't reevaluate those IPs and hosts and risk
        # overrunning the API servers (and reduce web traffic)
        for line in file_to_follow:
            clean_data = str(line).strip("'<>() \r\n").replace('\'', '\"')
            if clean_data:
                try:
                    data = json.loads(clean_data, strict=False)
                    ip_and_host = data['dst_ip'] + ':' + data['tls']['server_name']
                    data_to_check.add(ip_and_host)
                except Exception as e:
                    logging.exception("There was a problem with the JSON Data: {}".format(e))

        queue = Queue()
        
        for x in range(4):
            worker = DownloadWorker(queue)
            worker.daemon = True
            worker.start()

        for line in follow(file_to_follow):
            # Remove any strange/special characters from string
            clean_data = str(line).strip("'<>() \r\n").replace('\'', '\"')

            # Function likes to return empty line causing json.loads to break
            # Check to make sure there's data in the string before loading
            if clean_data:
                try:
                    data = json.loads(clean_data, strict=False)
                    ip_and_host = data['dst_ip'] + ':' + data['tls']['server_name']
                    old_length = len(data_to_check)
                    data_to_check.add(ip_and_host)
                except Exception as e:
                    logging.exception("There was a problem with the JSON Data: {}".format(e))

                # Check to see if data was added to set (meaning it's a new entry)
                # If it is, then run check_ip, otherwise, we'll ignore it
                if len(data_to_check) > old_length:
                    timestamp = datetime.now(timezone.utc).isoformat()
                    queue.put((otx, ip_and_host.split(':')[0], ip_and_host.split(':')[1], urlhaus_api, options.mmdb, timestamp, options.outfile))
        queue.join()

    # Check if we just passed in the IP or Host option - mainly for testing
    elif options.ip:
        timestamp = datetime.now(timezone.utc).isoformat()
        print(ip(otx, options.ip, options.mmdb, timestamp))
    elif options.host:
        timestamp = datetime.now(timezone.utc).isoformat()
        print(hostname(options.host, options.mmdb, urlhaus_api, timestamp))

if __name__ == '__main__':
    try:
        exit(main())
    except Exception:
        logging.exception("Exception in main()")
        exit(1)