#!/usr/bin/env python

#  This script tells if a File, IP, Domain or URL may be malicious according to the data in OTX
import IndicatorTypes
import json
import socket
import requests
import os
import time
import logging
import csv

from datetime import datetime
from dateutil.parser import parse
from OTXv2 import OTXv2

# Define logger for cross appliction logging consistency
logger = logging.getLogger(__name__)

def getValue(results, keys):
    '''
    Get a nested key from a dict, without having to do loads of ifs
    '''

    if type(keys) is list and len(keys) > 0:
        if type(results) is dict:
            key = keys.pop(0)
            if key in results:
                return getValue(results[key], keys)
            else:
                return None
        else:
            if type(results) is list and len(results) > 0:
                return getValue(results[0], keys)
            else:
                return results
    else:
        return results

def ip(api_key, ip):
    '''
    Query AlienVault OTX for malicious IP checking
    '''
    alerts = {}
    full_url_list = []
    report_age = 0
    url_status = 0

    # Set URLs and instantiate OTX object
    OTX_SERVER = 'https://otx.alienvault.com/'
    otx = OTXv2(api_key, server=OTX_SERVER)

    try:
        result = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        pulses = getValue(result['general'], ['pulse_info', 'pulses'])
        if pulses:
            full_url_list = getValue(result['passive_dns'], ['passive_dns'])
            first_reported = datetime.strptime(full_url_list[-1]['first'], "%Y-%m-%dT%H:%M:%S+00:00")
            last_reported = datetime.strptime(full_url_list[0]['last'], "%Y-%m-%dT%H:%M:%S+00:00")
            report_age = int(((last_reported - first_reported).total_seconds() / 86400))
            url_status = 2

    except Exception as e:
        logger.exception(" :  You received this error with the OTX API Data... {}".format(e))

    # Build alerts dictionary from variables
    alerts = {'url_status': url_status, 'report_age': report_age}

    return alerts

def hostname(host, ip_addr, query_two=False):
    '''
    Query urlhaus.abuse.ch for malicious URL checking (if no URL found, check IP as some malicious domains are the unresolved IP)
    '''
    alerts = {}
    report_age = 0
    url_status = 0
    query_results = ''
    __version__ = '0.0.2'

    # URL haus API URL
    urlhaus_api = "https://urlhaus-api.abuse.ch/v1/"
    
    try:
        query_urlhaus = requests.post("{}host/".format(urlhaus_api), headers={"User-Agent" : "urlhaus-python-client-{}".format(__version__)}, data={"host": host})
        if query_urlhaus.ok:
            query_results = query_urlhaus.json()
            if query_results['query_status'] == "no_results" and not query_two:
                hostname(ip_addr, host, True)

            elif query_results['query_status'] == "no_results" and query_two:
                url_status = 0
                report_age = 0

            else:
                if not query_urlhaus.json()['urls']:
                    url_status = 1
                    report_age = 0
                elif query_urlhaus.json()['urls'][0]['url_status'] == 'online':
                    first_seen = datetime.strptime(query_urlhaus.json()['firstseen'], "%Y-%m-%d %H:%M:%S UTC")
                    last_seen = datetime.now()
                    report_age = int(((last_seen - first_seen).total_seconds() / 86400))
                    url_status = 2
                else:
                    url_status = 1
                    report_age = 0

        else:
            logger.error(" :  Unable to read response as json")

    except Exception as e:
        logger.exception(" :  Unable to connect to URLHaus API. Recieved the following error {} - {} - {}".format(e, host, ip_addr))

    # Build alerts dictionary from variables
    alerts = {'url_status': url_status, 'report_age': report_age}
    return alerts

def update_csv(csv_file):
    '''
    Method to update ja3 csv file from sslbl.urlhaus.ch
    '''
    with open(csv_file, 'wb') as write_ja3_csv:
        csv_data = requests.get('https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv')
        write_ja3_csv.write(csv_data.content)

def ja3_sslbl_check(fingerprint):
    '''
    Method to check JA3 database for existence of connection
    '''
    ja3_malware_check = {}
    csv_filename = r'C:\Users\bryan\Desktop\ja3_fingerprints.csv'
    days = 1
    report_age = 0
    ja3_check = 0

    if not os.path.exists(csv_filename):
        update_csv(csv_filename)
    else:
        file_modify_date = os.path.getmtime(csv_filename)
        file_older_than_days = ((time.time() - file_modify_date) / 3600 > 24 * days)
        if file_older_than_days:
            update_csv(csv_filename)

    with open(csv_filename, 'r') as ja3_csv_file:
        # Add csv file to variable and ignore comments
        read_ja3 = csv.reader(filter(lambda row: row[0] != '#', ja3_csv_file))
        # Locate value in csv (if exists)
        for ja3_fingerprint in read_ja3:
            if fingerprint == ja3_fingerprint[0]:
                ja3_check = 1
                first_seen = datetime.strptime(ja3_fingerprint[1], "%Y-%d-%m %H:%M:%S")
                last_seen = datetime.strptime(ja3_fingerprint[2], "%Y-%d-%m %H:%M:%S")
                report_age = int((last_seen - first_seen).total_seconds() / 86400)
                break

    ja3_malware_check = {'ja3_check': ja3_check, 'ja3_record_age': report_age}

    return ja3_malware_check

def main():
    '''
    Run some automated tests for ip and hostname methods
    '''
    api_key = os.environ.get('API_KEY')
    ip_addr = '4.4.4.4'
    host = 'google.com'

    print("IP Query output: {}".format(ip(api_key, ip_addr)))
    print("Hostname Query output: {}".format(hostname(host, ip_addr)))

if __name__ == "__main__":
    try:
        exit(main())
    except Exception:
        logging.exception("Exception in main()")
        exit(1)