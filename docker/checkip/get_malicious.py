#!/usr/bin/env python

import IndicatorTypes
import json

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

def hostname(otx, hostname):
    alerts = []
    result = otx.get_indicator_details_by_section(IndicatorTypes.HOSTNAME, hostname, 'general')

    # Return nothing if it's in the whitelist
    validation = getValue(result, ['validation'])
    if not validation:
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            for pulse in pulses:
                if 'name' in pulse:
                    alerts.append('In pulse: ' + pulse['name'])

    result = otx.get_indicator_details_by_section(IndicatorTypes.DOMAIN, hostname, 'general')
    # Return nothing if it's in the whitelist
    validation = getValue(result, ['validation'])
    if not validation:
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            for pulse in pulses:
                if 'name' in pulse:
                    alerts.append('In pulse: ' + pulse['name'])


    return alerts


def ip(otx, ip):
    alerts = []
    result = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip)

    # Return nothing if it's in the whitelist
    validation = getValue(result['general'], ['validation'])
    if not validation:
        pulses = getValue(result['general'], ['pulse_info', 'pulses'])
        if pulses:
            alerts.append(ip)
            alerts.append(result['geo']['latitude'])
            alerts.append(result['geo']['longitude'])
            #dom = getValue(result['general'], ['passive_dns', 'hostname'])
            #url = getValue(result['general'], ['passive_dns', 'flag_url'])
            urls = getValue(result['passive_dns'], ['passive_dns'])
            #alerts.append(urls)
            #alerts.append(getValue(result['general'], ['pulse_info', 'pulses']))
            for url in urls:
                if 'hostname' and 'flag_url' in url:
                #if 'flag_url' in url:
                    alerts.append(url['hostname'])

    return alerts

def url(otx, url):
    alerts = []
    result = otx.get_indicator_details_full(IndicatorTypes.URL, url)

    google = getValue( result, ['url_list', 'url_list', 'result', 'safebrowsing'])
    if google and 'response_code' in str(google):
        alerts.append({'google_safebrowsing': 'malicious'})

    clamav = getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','clamav'])
    if clamav:
            alerts.append({'clamav': clamav})

    avast = getValue( result, ['url_list', 'url_list', 'result', 'multiav','matches','avast'])
    if avast:
        alerts.append({'avast': avast})

    return alerts
