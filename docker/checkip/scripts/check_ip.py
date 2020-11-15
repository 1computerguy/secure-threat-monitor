#!/usr/bin/env python

#  This script tells if a File, IP, Domain or URL may be malicious according to the data in OTX
import IndicatorTypes
import json
import geoip2.database
import socket
import requests
import os
import time
import logging

from datetime import datetime
from dateutil.parser import parse
from OTXv2 import OTXv2

logger = logging.getLogger(__name__)

def getValue(results, keys):
    '''Get a nested key from a dict, without having to do loads of ifs
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

def ip(otx, ip, mmdb, query_time):
    '''Query AlienVault OTX for malicious IP checking
    '''
    alerts = {}
    report_db = ''
    latitude = ''
    longitude = ''
    full_url_list = []
    top_five_urls = [] # List of 5 most recent urls
    url_set = set() # Remove duplicates from full_url_list
    first_reported = ''
    last_reported = ''
    url_status = ''

    try:
        result = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        pulses = getValue(result['general'], ['pulse_info', 'pulses'])
        if pulses:
            report_db = 'otx.alienvault.com'
            latitude = result['geo']['latitude']
            longitude = result['geo']['longitude']
            full_url_list = getValue(result['passive_dns'], ['passive_dns'])

            for url in full_url_list:
                if 'hostname' and 'flag_url' in url:
                    url_set.add(url['hostname']+'/'+url['flag_url'])
                
            top_five_urls = list(url_set)[:5]
            first_reported = parse(full_url_list[-1]['first']).isoformat()
            last_reported = parse(full_url_list[0]['last']).isoformat()
            url_status = 'potentially_malicious'
        else:
            response = geoip2.database.Reader(mmdb).city(ip)
            report_db = 'otx.alienvault.com'
            latitude = response.location.latitude
            longitude = response.location.longitude
            try:
                top_five_urls = [socket.gethostbyaddr(ip)[0]]
            except socket.herror:
                top_five_urls = []
            
            first_reported = ''
            last_reported = ''
            url_status = 'likely_benign'

    except Exception as e:
        logger.exception(" :  You received this error with the OTX API Data... {}".format(e))

    # Build alerts dictionary from variables
    alerts = {'report_db': report_db, 'ip_addr': ip, 'latitude': latitude, 'longitude': longitude,
              'urls': top_five_urls, 'first_reported': first_reported, 'last_reported': last_reported,
              'query_date': query_time, 'url_status': url_status}

    return alerts

def hostname(host, mmdb, query_url, query_time):
    '''Query urlhaus.abuse.ch for malicious host checking
    '''
    alerts = {}
    ip_addr = ''
    report_db = ''
    latitude = ''
    longitude = ''
    full_url_list = []
    url_set = set() # Remove duplicates from full_url_list
    first_reported = ''
    last_reported = ''
    url_status = ''
    __version__ = '0.0.2'

    try:
        r = requests.post("{}host/".format(query_url), headers={"User-Agent" : "urlhaus-python-client-{}".format(__version__)}, data={"host": host})
        if r.ok:
            geo_reader = geoip2.database.Reader(mmdb)
            if r.json()['query_status'] == "no_results":
                report_db = 'urlhaus.abuse.ch'
                try:
                    ip_addr = socket.gethostbyname(host)
                except socket.error:
                    ip_addr = ''

                if ip_addr:
                    try:
                        latitude = geo_reader.city(ip_addr).location.latitude
                        longitude = geo_reader.city(ip_addr).location.longitude
                    except:
                        latitude = ''
                        longitude = ''                

                full_url_list = [host]
                first_reported = ''
                last_reported = ''
                url_status = 'likely_benign'

            else:
                report_db = 'urlhaus.abuse.ch'
                try:
                    ip_addr = socket.gethostbyname(host)
                except socket.error:
                    ip_addr = ''

                if ip_addr:
                    try:
                        latitude = geo_reader.city(ip_addr).location.latitude
                        longitude = geo_reader.city(ip_addr).location.longitude
                    except:
                        latitude = ''
                        longitude = ''
                
                for url in r.json()['urls']:
                    url_set.add(url['url'].split('//', 2)[1])

                full_url_list = list(url_set)[:5]
                first_reported = parse(r.json()['firstseen']).isoformat()
                if r.json()['urls'][0]['url_status'] == 'online':
                    url_status = 'potentially_malicious'
                else:
                    url_status = 'potentially_malicious_but_offline'

        else:
            logger.error(" :  Unable to read response as json")

    except Exception as e:
        logger.exception(" :  Unable to connect to URLHaus API. Recieved the following error {}".format(e))

    # Build alerts dictionary from variables
    alerts = {'report_db': report_db, 'ip_addr': ip_addr, 'latitude': latitude, 'longitude': longitude,
              'urls': full_url_list, 'first_reported': first_reported, 'last_reported': last_reported,
              'query_date': query_time, 'url_status': url_status}
    return alerts

def sslbl():
    '''Check IP against SSL Blocklist against sslbl.abuse.ch
    '''

def main():
    '''Run some automated tests for ip and hostname methods
    '''
    api_key = os.environ.get('API_KEY')
    otx_server = 'https://otx.alienvault.com/'
    otx = OTXv2(api_key, server=otx_server)
    
    urlhaus_api = "https://urlhaus-api.abuse.ch/v1/"

    query_timestamp = datetime.utcnow().isoformat()
    mmdb_path = '../netcap/resources/GeoLite2-City.mmdb'

    ip_addr = '4.4.4.4'
    host = 'google.com'

    print("IP Query output: {}".format(ip(otx, ip_addr, mmdb_path, query_timestamp)))
    print("Hostname Query output: {}".format(hostname(host, mmdb_path, urlhaus_api, query_timestamp)))

if __name__ == "__main__":
    try:
        exit(main())
    except Exception:
        logging.exception("Exception in main()")
        exit(1)