#!/usr/bin/env python

import time
import os
import argparse
import json
import logging

from OTXv2 import OTXv2
from check_ip import ip, hostname, allow_list
from taillog import follow
from datetime import datetime
from dateutil.parser import parse
from queue import Queue
from threading import Thread
from collections import deque

# Define logger for cross appliction logging consistency
logger = logging.getLogger(__name__)

# Create custom logging class for exceptions
class OneLineExceptionFormatter(logging.Formatter):
    def formatException(self, exc_info):
        result = super().formatException(exc_info)
        return repr(result)
 
    def format(self, record):
        result = super().format(record)
        if record.exc_text:
            result = result.replace("\n", "")
        return result

# Add multithreading to application so we don't run into a data
# overrun on a single process (query can take up to 10+ seconds) 
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
    '''Write check_ip data out to file
    '''
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
    parser.add_argument('-o', '--outfile', action='store', dest='outfile', help='File to write output date to.', default="/checkip/output/output.json", required=False)
    parser.add_argument('-d', '--db', action='store', dest='mmdb', help='Location of MaxMind City DB', default="/checkip/resources/GeoLite2-City.mmdb", required=False)
    parser.add_argument('-a', '--api', action='store', dest='api_key', help='API Key obtained from Alienvault OTX website', required=False)
    parser.add_argument('-w', '--allow', action='store', dest='allowed', help='Location of the domain-whitelist.csv file', default='/checkip/resources/domain-whitelist.csv', required=False)

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

    if os.environ.get('INFILE'):
        infile = os.environ.get('INFILE')
    elif options.infile:
        infile = options.infile
    else:
        logging.error('Please provide a file to follow for the IP and hostname lookup info.')
        exit(1)
    
    if os.environ.get('OUTFILE'):
        outfile = os.environ.get('OUTFILE')
    elif options.outfile:
        outfile = options.outfile
    else:
        logging.error('Please provide a file to follow for the IP and hostname lookup info.')
        exit(1)

    if os.environ.get('MAXMIND') and os.path.isfile(os.environ.get('MAXMIND')):
        mmdb = os.environ.get('MAXMIND')
    elif options.mmdb and os.path.isfile(options.mmdb):
        mmdb = options.mmdb
    else:
        logging.error('Please provide path to the MaxMind GeoLite2-City.mmdb file...')
        exit(1)

    # Set URLs and instantiate OTX object
    urlhaus_api = "https://urlhaus-api.abuse.ch/v1/"
    OTX_SERVER = 'https://otx.alienvault.com/'
    otx = OTXv2(api_key, server=OTX_SERVER)

    if infile:
        # In case watch file doesn't exist, we'll wait till it's created
        while not os.path.exists(infile):
            time.sleep(1)

        # Open file and create initial empty set()
        file_to_follow = open(infile,"r")
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
        
        for _ in range(4):
            worker = DownloadWorker(queue)
            worker.daemon = True
            worker.start()

        new_length = 0
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
                    new_length = len(data_to_check)
                except Exception as e:
                    logging.exception("There was a problem with the JSON Data: {}".format(e))

                # Check to see if data was added to set (meaning it's a new entry)
                # If it is, then run check_ip, otherwise, we'll ignore it
                if new_length > old_length:
                    timestamp = datetime.utcnow().isoformat()
                    queue.put((otx, ip_and_host.split(':')[0], ip_and_host.split(':')[1], urlhaus_api, mmdb, timestamp, outfile))
                
                # To conserve memory over time, we will reset the ip_and_host set when it either reaches 10000 unique
                # entries, or when it reaches 12am UTC. I may make this user controlled at some point, but for now
                # it will remain hard coded.
                if new_length > 10000 or datetime.utcnow().strftime('%H:%M:%S') == '00:00:00':
                    ip_and_host = set()
                    old_length = 0
                    new_length = 0
        queue.join()

    # Check if we just passed in the IP or Host option - mainly for testing
    elif options.ip:
        timestamp = datetime.utcnow().isoformat()
        print(ip(otx, options.ip, mmdb, timestamp))
    elif options.host:
        timestamp = datetime.utcnow().isoformat()
        print(hostname(options.host, mmdb, urlhaus_api, timestamp))

if __name__ == '__main__':
    try:
        exit(main())
    except Exception:
        logging.exception("Exception in main()")
        exit(1)