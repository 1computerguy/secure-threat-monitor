#!/usr/bin/env python
#  This script tells if a File, IP, Domain or URL may be malicious according to the data in OTX

from OTXv2 import OTXv2
import argparse
import IndicatorTypes
import json
from ip2geotools.databases.noncommercial import MaxMindGeoLite2City
import socket
import requests
import os
from datetime import datetime, timezone
from dateutil.parser import parse
import time


__version__ = '0.0.2'
API_KEY = os.environ.get('API_KEY')
urlhaus_api = "https://urlhaus-api.abuse.ch/v1/"
OTX_SERVER = 'https://otx.alienvault.com/'
otx = OTXv2(API_KEY, server=OTX_SERVER)
query_timestamp = datetime.now(timezone.utc).isoformat()

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

# Tail a log file so we can extract IP and hostname in real-time
def follow(filename):
    '''generator function that yields new lines in a file
    '''

    # In case file doesn't exist, we'll wait till it's created
    while not os.path.exists(filename):
        time.sleep(1)

    # seek the end of the file
    filename.seek(0, os.SEEK_END)
    
    # start infinite loop
    while True:
        # read last line of file
        line = filename.readline()
        # sleep if file hasn't been updated
        if not line:
            time.sleep(0.1)
            continue

        yield line

def ip(ip):
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
            alerts['query_date'] = query_timestamp
            alerts['url_status'] = 'potentially_malicious'
        else:
            alerts['report_db'] = 'otx.alienvault.com'
            response = MaxMindGeoLite2City.get(ip, db_path)
            alerts['ip_addr'] = ip
            alerts['latitude'] = response.latitude
            alerts['longitude'] = response.longitude
            try:
                alerts['urls'] = [socket.gethostbyaddr(ip)[0]]
            except socket.herror:
                alerts['urls'] = []
            
            alerts['first_reported'] = ''
            alerts['last_reported'] = ''
            alerts['query_date'] = query_timestamp
            alerts['url_status'] = 'likely_benign'

    except Exception as e:
        error_msg = query_timestamp + " :  You received this error the OTX API Data... {}".format(e)
        write_data(error_msg, error_log, True)

    return alerts

def hostname(host):
    alerts = {}
    url_list = []
    try:
        r = requests.post("{}host/".format(urlhaus_api), headers={"User-Agent" : "urlhaus-python-client-{}".format(__version__)}, data={"host": host})
        if r.ok:
            if r.json()['query_status'] == "no_results":
                alerts['report_db'] = 'urlhaus.abuse.ch'
                try:
                    alerts['ip_addr'] = socket.gethostbyname(host)
                except socket.error:
                    alerts['ip_addr'] = ''

                try:
                    response = MaxMindGeoLite2City.get(alerts['ip_addr'], db_path)
                    alerts['latitude'] = response.latitude
                    alerts['longitude'] = response.longitude
                except:
                    alerts['latitude'] = ''
                    alerts['longitude'] = ''                

                alerts['urls'] = [host]
                alerts['first_reported'] = ''
                alerts['last_reported'] = ''
                alerts['query_date'] = query_timestamp
                alerts['url_status'] = 'likely_benign'

            else:
                alerts['report_db'] = 'urlhaus.abuse.ch'
                try:
                    alerts['ip_addr'] = socket.gethostbyname(host)
                except socket.error:
                    alerts['ip_addr'] = ''

                try:
                    response = MaxMindGeoLite2City.get(alerts['ip_addr'], db_path)
                    alerts['latitude'] = response.latitude
                    alerts['longitude'] = response.longitude
                except:
                    alerts['latitude'] = ''
                    alerts['longitude'] = ''
                
                for url in r.json()['urls']:
                    url_list.append(url['url'].split('//', 2)[1])

                alerts['urls'] = url_list[:5]
                alerts['first_reported'] = parse(r.json()['firstseen']).isoformat()
                alerts['last_reported'] = ''
                alerts['query_date'] = query_timestamp
                if r.json()['urls'][0]['url_status'] == 'online':
                    alerts['url_status'] = 'potentially_malicious'
                else:
                    alerts['url_status'] = 'potentially_malicious_but_offline'

        else:
            error_msg = query_timestamp + " :  Unable to read response as json"
            write_data(error_msg, error_log, True)

    except Exception as e:
        error_msg = query_timestamp + " :  Unable to connect to api. Recieved the following error {}".format(e)
        write_data(error_msg, error_log, True)

    return alerts

def write_data(output, filename, err=False):
    if err:
        with open(filename, 'a') as err_outfile:
            err_outfile.write(output)
            err_outfile.write("\n")
    else:
        with open(filename, 'a') as outfile:
            json.dump(output, outfile)
            outfile.write("\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='OTX CLI Example')
    parser.add_argument('-ip', action='store', dest='ip',
                        help='IP eg; 4.4.4.4', required=False)
    parser.add_argument('-host', action='store', dest='host',
                        help='Hostname eg; www.alienvault.com', required=False)
    parser.add_argument('-outfile', action='store', dest='outfile',
                        help='File to save data to. eg; /checkip/output.json',
                        default="/checkip/output.json", required=False)
    parser.add_argument('-maxmind', action='store', dest='db_path',
                        help='MaxMind DB file location eg; /checkip/GeoLite2-City.mmdb', required=False)
    parser.add_argument('-err', action='store', dest='error_log',
                        help='Error log file location eg; /checkip/error.log', required=False)
    parser.add_argument('-api', action='store', dest='API_KEY',
                        help='API Key obtained from Alienvault OTX website', required=False)

    options = parser.parse_args()

    if options.error_log:
        error_log = options.error_log
    if os.environ['ERROR_LOG']:
        error_log = os.environ['ERROR_LOG']
    else:
        error_log = '/checkip/error.log'

    if os.environ.get('API_KEY'):
        API_KEY = os.environ.get('API_KEY')
    elif options.API_KEY:
        API_KEY = options.API_KEY
    else:
        error = 'Please provide your Alienvault OTX API Key as the API_KEY environment variable or use the -api command-line argument.'
        print(error)
        write_data(error, options.error_log, True)
        exit()

    __version__ = '0.0.2'
    urlhaus_api = "https://urlhaus-api.abuse.ch/v1/"
    OTX_SERVER = 'https://otx.alienvault.com/'
    otx = OTXv2(API_KEY, server=OTX_SERVER)
    query_timestamp = datetime.now(timezone.utc).isoformat()

    if options.db_path:
        db_path = options.db_path
    elif os.environ['MAXMIND_DB']:
        db_path = os.environ['MAXMIND_DB']
    else:
        db_path='/checkip/resources/GeoLite2-City.mmdb'

    if options.ip:
        try:
            write_data(ip(otx, options.ip), options.filename)
        except Exception as e:
            error_msg = query_timestamp + " :  There was an error with IP lookup... {}".format(e)
            write_data(error_msg, error_log, True)
        
    if options.host:
        try:
            write_data(hostname(options.host), options.filename)
        except Exception as e:
            error_msg = query_timestamp + " :  There was an error with hostname lookup... {}".format(e)
            write_data(error_msg, error_log, True)
        