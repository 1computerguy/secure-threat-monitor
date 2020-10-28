#!/usr/bin/env python

import time
import os
import argparse
import check_ip
import json

def follow(filename):
    '''generator function that yields new lines in a file
    '''

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

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Watch log file and pass IP and hostname to check_ip.py')
    parser.add_argument('-f', '--file', action='store', dest='file',
                        help='Name of log file from which to obtain IP and hostname data',
                        required=True)
    
    args = parser.parse_args()

    # In case file doesn't exist, we'll wait till it's created
    while not os.path.exists(args.file):
        time.sleep(1)

    logfile = open(args.file,"r")
    data_to_check = set()

    for line in follow(logfile):
        clean_data = str(line).strip("'<>() \r\n").replace('\'', '\"')
        # Function likes to return empty line causing json.loads to break
        # Check to make sure there's data in the string before loading
        if clean_data:
            data = json.loads(clean_data, strict=False)
            ip_and_host = data['dst_ip'] + ':' + data['tls']['server_name']
            old_length = len(data_to_check)
            data_to_check.add(ip_and_host)
            
            # Check to see if data was added to set (meaning it's a new entry)
            # If it is, then run check_ip, otherwise, we'll ignore it
            if len(data_to_check) > old_length:
                print(check_ip.ip(ip_and_host.split(':')[0]))
                print(check_ip.host(ip_and_host.split(':')[1]))