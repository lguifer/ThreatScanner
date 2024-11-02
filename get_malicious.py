#!/usr/bin/env python

import IndicatorTypes
import pdb
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
    try:
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

        #print('Identified as potentially malicious')
        print(hostname+str(alerts))
    except Exception as e:
        print(f"Error leyendo la entrada {hostname}")
    return alerts


def ip(otx, ip):
    alerts = []
    result = otx.get_indicator_details_by_section(IndicatorTypes.IPv4, ip, 'general')

    # Return nothing if it's in the whitelist
    validation = getValue(result, ['validation'])
    if not validation:
        pulses = getValue(result, ['pulse_info', 'pulses'])
        if pulses:
            for pulse in pulses:
                if 'name' in pulse:
                    alerts.append('In pulse: ' + pulse['name'])

    return alerts



def url(otx, url):
    alerts = []
    result = otx.get_indicator_details_by_section(IndicatorTypes.URL, url, 'general')
    pulses = getValue(result, ['pulse_info', 'pulses'])
    if pulses:
        for pulse in pulses:
            if 'name' in pulse:
                alerts.append('In pulse: ' + pulse['name'])
    return alerts

def file(otx, hash):

    alerts = []

    hash_type = IndicatorTypes.FILE_HASH_MD5
    if len(hash) == 64:
        hash_type = IndicatorTypes.FILE_HASH_SHA256
    if len(hash) == 40:
        hash_type = IndicatorTypes.FILE_HASH_SHA1

    result = otx.get_indicator_details_full(hash_type, hash)

    avg = getValue( result, ['analysis','analysis','plugins','avg','results','detection'])
    if avg:
        alerts.append({'avg': avg})

    clamav = getValue( result, ['analysis','analysis','plugins','clamav','results','detection'])
    if clamav:
        alerts.append({'clamav': clamav})

    avast = getValue( result, ['analysis','analysis','plugins','avast','results','detection'])
    if avast:
        alerts.append({'avast': avast})

    microsoft = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Microsoft','result'])
    if microsoft:
        alerts.append({'microsoft': microsoft})

    symantec = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Symantec','result'])
    if symantec:
        alerts.append({'symantec': symantec})

    kaspersky = getValue( result, ['analysis','analysis','plugins','cuckoo','result','virustotal','scans','Kaspersky','result'])
    if kaspersky:
        alerts.append({'kaspersky': kaspersky})

    suricata = getValue( result, ['analysis','analysis','plugins','cuckoo','result','suricata','rules','name'])
    if suricata and 'trojan' in str(suricata).lower():
        alerts.append({'suricata': suricata})

    return alerts
