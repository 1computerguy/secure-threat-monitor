#!/usr/bin/env python

#  This script tells if a File, IP, Domain or URL may be malicious according to the data in OTX

from OTXv2 import OTXv2
import IndicatorTypes
import json
import geoip2.database
import socket
import requests
import os
from datetime import datetime, timezone
from dateutil.parser import parse
import time
import logging


logger = logging.getLogger(__name__)

# Get a nested key from a dict, without having to do loads of ifs
def getValue(results, keys):
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
    alerts = {}
    url_set = set()

    try:
        result = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)
        pulses = getValue(result['general'], ['pulse_info', 'pulses'])
        if pulses:
            alerts['report_db'] = 'otx.alienvault.com'
            alerts['ip_addr'] = ip
            alerts['latitude'] = result['geo']['latitude']
            alerts['longitude'] = result['geo']['longitude']
            urls = getValue(result['passive_dns'], ['passive_dns'])

            for url in urls:
                if 'hostname' and 'flag_url' in url:
                    url_set.add(url['hostname']+'/'+url['flag_url'])
                
            alerts['urls'] = list(url_set)[:5]
            alerts['first_reported'] = parse(urls[-1]['first']).isoformat()
            alerts['last_reported'] = parse(urls[0]['last']).isoformat()
            alerts['query_date'] = query_time
            alerts['url_status'] = 'potentially_malicious'
        else:
            response = geoip2.database.Reader(mmdb).city(ip)
            alerts['report_db'] = 'otx.alienvault.com'
            alerts['ip_addr'] = ip
            alerts['latitude'] = response.location.latitude
            alerts['longitude'] = response.location.longitude
            try:
                alerts['urls'] = [socket.gethostbyaddr(ip)[0]]
            except socket.herror:
                alerts['urls'] = []
            
            alerts['first_reported'] = ''
            alerts['last_reported'] = ''
            alerts['query_date'] = query_time
            alerts['url_status'] = 'likely_benign'

    except Exception as e:
        logger.exception(" :  You received this error with the OTX API Data... {}".format(e))

    return alerts

def hostname(host, mmdb, query_url, query_time):
    alerts = {}
    url_list = []
    __version__ = '0.0.2'

    try:
        r = requests.post("{}host/".format(query_url), headers={"User-Agent" : "urlhaus-python-client-{}".format(__version__)}, data={"host": host})
        if r.ok:
            if r.json()['query_status'] == "no_results":
                alerts['report_db'] = 'urlhaus.abuse.ch'
                try:
                    alerts['ip_addr'] = socket.gethostbyname(host)
                except socket.error:
                    alerts['ip_addr'] = ''

                try:
                    response = geoip2.database.Reader(mmdb).city(alerts['ip_addr'])
                    alerts['latitude'] = response.location.latitude
                    alerts['longitude'] = response.location.longitude
                except:
                    alerts['latitude'] = ''
                    alerts['longitude'] = ''                

                alerts['urls'] = [host]
                alerts['first_reported'] = ''
                alerts['last_reported'] = ''
                alerts['query_date'] = query_time
                alerts['url_status'] = 'likely_benign'

            else:
                alerts['report_db'] = 'urlhaus.abuse.ch'
                try:
                    alerts['ip_addr'] = socket.gethostbyname(host)
                except socket.error:
                    alerts['ip_addr'] = ''

                try:
                    response = response = geoip2.database.Reader(mmdb).city(alerts['ip_addr'])
                    alerts['latitude'] = response.location.latitude
                    alerts['longitude'] = response.location.longitude
                except:
                    alerts['latitude'] = ''
                    alerts['longitude'] = ''
                
                for url in r.json()['urls']:
                    url_list.append(url['url'].split('//', 2)[1])

                alerts['urls'] = url_list[:5]
                alerts['first_reported'] = parse(r.json()['firstseen']).isoformat()
                alerts['last_reported'] = ''
                alerts['query_date'] = query_time
                if r.json()['urls'][0]['url_status'] == 'online':
                    alerts['url_status'] = 'potentially_malicious'
                else:
                    alerts['url_status'] = 'potentially_malicious_but_offline'

        else:
            logger.error(" :  Unable to read response as json")

    except Exception as e:
        logger.exception(" :  Unable to connect to URLHaus API. Recieved the following error {}".format(e))

    return alerts

def main():
    api_key = os.environ.get('API_KEY')
    otx_server = 'https://otx.alienvault.com/'
    otx = OTXv2(api_key, server=otx_server)
    
    urlhaus_api = "https://urlhaus-api.abuse.ch/v1/"

    query_timestamp = datetime.now(timezone.utc).isoformat()
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