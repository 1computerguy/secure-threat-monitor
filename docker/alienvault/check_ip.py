#!/usr/bin/python
#coding:utf-8
import urllib2
import json
import time
import sys
import dpkt
import socket
from optparse import OptionParser
from OTXv2 import OTXv2
import IndicatorTypes
import argparse
#import get_malicious
import hashlib
#!/usr/bin/env python

reload(sys);
sys.setdefaultencoding('utf-8');

url = 'http://ip.taobao.com/service/getIpInfo.php?ip='
API_KEY = '9facf92fec62a521c595aece7d587c954db42f7d0e05bc92ccf04c489a125944'  #change your API_Key
OTX_SERVER = 'https://otx.alienvault.com/'

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

def CheckIp(otx, ip):
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

def checkhostname(otx, hostname):
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

def IsMalicious(Lfile):
    otx = OTXv2(API_KEY, server=OTX_SERVER)
    fin = open(Lfile,'r')
    fout = open('malicious_results.txt','w') 
    count = 0
    for line in fin:
        ip= line.strip('\n').split(":")[0].strip()
        location = line.strip('\n').split(":")[1].strip()
        alerts = CheckIp(otx,ip)
        if len(alerts) > 0:
            reference = 'https://otx.alienvault.com/indicator/ip/'+ip
            print 'potentially malicious:'+line+"reference:"+reference
            print>>fout,"%s"%line
            count=count+1
    print "-----There are %d malicious IP-----" % count
    fin.close()
    fout.close()

def IsDNSMalicious(Lfile):
    otx = OTXv2(API_KEY, server=OTX_SERVER)
    fin = open(Lfile,'r')
    fout = open('maliciousDNS.txt','w')
    count=0
    for line in fin:
        hostname=line.strip('\n').strip()
        alerts=checkhostname(otx,hostname)
        if len(alerts)>0:
            reference='https://otx.alienvault.com/indicator/hostname/'+hostname
            print 'potentially malicious:'+line+'reference:'+reference
            print>>fout,"%s"%(line+' '+reference)
            count=count+1
    print "-----There are %d malicious hostname-----"%count
    fin.close()
    fout.close()

def checkTaobaoIP(ip, fout1):
    try:
        response = urllib2.urlopen(url + ip, timeout=10)
        result = response.readlines()
        data = json.loads(result[0])
        #sys.exit(1)                      
        if data['data']['city'] == "内网IP":
            return
        return "%15s: %s-%s-%s" % (ip,data['data']['country'],data['data']['region'],data['data']['city'])
    except Exception,err:
        print "[error] %s" % err
        print >>fout1, "%s" %ip
        return "%15s: time out" % ip 

def parseIPlistLocation(IPfile):
    try:
        f1 = open(IPfile, "r+")
        ips = f1.readlines()
        f1.close()
        fout1 = open("out_error.txt", "wb")
        f2 = open('ip_location.txt', 'w')
        for ip in ips:
            line = checkTaobaoIP(ip.strip(), fout1)
            if line:
                print line.encode('utf-8')
                f2.write(line.encode('utf-8')+'\n')
            else:
                continue
                #print line
        f2.close()
        fout1.close()
        #print "---------IP Location Result---------"
    except Exception,err:
        print "[error] %s" % err

def parseDNS(pcap):
    lines_seen=set()
    
    fout1=open("text1.txt","wb")
    fout2=open("out_DNS.txt","wb")
    for(ts,buf) in pcap:
        try:

            eth = dpkt.ethernet.Ethernet(buf)
            ip=eth.data
            udp=ip.data
            if udp.dport!=53 and udp.sport!=53:
                continue
            dns=dpkt.dns.DNS(udp.data)
            if dns.qr!=dpkt.dns.DNS_R:
                continue
            if dns.opcode!=dpkt.dns.DNS_QUERY:
                continue
            if dns.rcode!=dpkt.dns.DNS_RCODE_NOERR:
                continue
            if len(dns.an)<1:
                continue
            for answer in dns.an:
                #print answer.name
                result=answer.name+"\n"
                fout1.write(result)
                
        except:
            pass
    fout1.close()
    f=open("text1.txt","r")

    for line in f:
            
        if line not in lines_seen:
            print line
            fout2.write(line)
            lines_seen.add(line)
            
    f.close
    fout2.close

def printPcap(pcap, if_srcIp, if_dstIP):
    flowList = [[] for i in range(20000)]
    counts = 0
    countFlow = [0]*20000
    isFlag = 0
    fout = open("out_IP.txt", "wb")   
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                #print('Non IP Packet type not supported %s' % eth.data.__class__.__name__)
                continue
            ip = eth.data
            if isinstance(ip.data, dpkt.icmp.ICMP): 
                continue      
            if isinstance(ip.data, dpkt.igmp.IGMP):
                continue          #filter tcp packets
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            udp = ip.data
            if counts == 0 :
                flowList[0].append(src)
                flowList[0].append(udp.sport)
                flowList[0].append(dst)
                flowList[0].append(udp.dport)
                counts = counts + 1
                countFlow[0] = 1
                '''if flowList[0][2] == '119.23.18.179':'''
                if if_srcIp == True:
                    print >>fout, "%s"% (flowList[0][0])
                    print "%s"% (flowList[0][0])
                if if_dstIP == True:
                    print >>fout, "%s"% (flowList[0][2])
                    print "%s"% (flowList[0][2])
                continue

            if if_srcIp == True:
                for i in range(0, counts):
                    if flowList[i][0] == src:
                        countFlow[i] = countFlow[i] + 1
                        isFlag = 1
                        break
                    else:
                        isFlag = 0
                        continue

            if if_dstIP == True:
                for i in range(0, counts):
                    if flowList[i][2] == dst:
                        countFlow[i] = countFlow[i] + 1
                        isFlag = 1
                        break
                    else:
                        isFlag = 0
                        continue

            if i == counts - 1 and isFlag == 0:
                flowList[counts].append(src) 
                flowList[counts].append(udp.sport) 
                flowList[counts].append(dst) 
                flowList[counts].append(udp.dport)
                '''if flowList[counts][2] == '119.23.18.179':'''  #filter some packets relying on dstIP
                if if_srcIp == True:
                    print >>fout, "%s"% (flowList[counts][0])
                    print "%s"% (flowList[counts][0])
                if if_dstIP == True:
                    print >>fout, "%s"% (flowList[counts][2])
                    print "%s"% (flowList[counts][2])
                    
                countFlow[counts] = 1
                counts = counts + 1 
                
            isFlag = 0    
        except Exception,err:
            print "[error] %s" % err 

    fout.close
     
if __name__ == "__main__":
    usage = "usage: hot_ip.py --pcapfile=./out.pcap -d -c |--OR--| hot_ip.py --IPfile=./iplist.txt -c|--OR--|hot_ip.py --pcapf=./out.pcap -p"
    parser = OptionParser(usage=usage)  
    parser.add_option(
        "--pcapfile", dest="pcapfile",
        action='store', type='string',
        help="special the pcap file path",
        default=None
    )

    parser.add_option(
        "--pcapf",dest="pcapf",
        action='store',type='string',
        help="special the pcap file path",
        default=None)

    parser.add_option(
        "--IPfile", dest="IPfile",
        action='store', type='string',
        help="special the IP list file path",
        default=None
    )

    parser.add_option(
        "-s", "--srcIP", action="store_true", 
        help="parse pcapfile srcIP location",
        dest="srcIP", default=False
    )

    parser.add_option(
        "-d", "--dstIP", action="store_true", 
        help="parse pcapfile dstIP location",
        dest="dstIP", default=False
    )

    parser.add_option(
        "-c", "--check", action="store_true", 
        help="check whether IP is malicious",
        dest="checkIP", default=False
    )

    parser.add_option(
        "-p", "--checkhostname",action='store_true',
        help="check whether hostname is malicious",
        dest="checkhostname",default=False)
  
    (options, args) = parser.parse_args() 

    if (options.pcapfile is None) and (options.IPfile is None)and(options.pcapf is None):
        print usage
        sys.exit(0)

    if options.srcIP == True and  options.dstIP == True:
        print "either -s or -d, can not both"
        sys.exit(0)

    print "Let's start!"
    print "------------------------------------"

    if options.IPfile is not None:
        parseIPlistLocation(options.IPfile)
        if options.checkIP == True:
            print "-------------check ip--------------"
            IsMalicious("./ip_location.txt")
        sys.exit(0)

    if options.pcapf is not None:
        f=open(options.pcapf)
        try:
            pcap = dpkt.pcapng.Reader(f)
        except:
            print "it is not pcapng format..."
            f.close()
        finally:
            f = open(options.pcapf)
            pcap = dpkt.pcap.Reader(f)
        parseDNS(pcap)

        if options.checkhostname==True:
            print "-----------check hostname-----------"
            IsDNSMalicious("./out_DNS.txt")
        sys.exit(0)

    if options.pcapfile is not None:
        if (options.srcIP or options.dstIP) == False:
            print "choose -s or -d"
            sys.exit(0)
        f = open(options.pcapfile)
        try:
            pcap = dpkt.pcapng.Reader(f)
        except:
            print "it is not pcapng format..."
            f.close()
        finally:
            f = open(options.pcapfile)
            pcap = dpkt.pcap.Reader(f)
        printPcap(pcap, options.srcIP, options.dstIP)
        parseIPlistLocation("./out_IP.txt")
        
        if options.checkIP == True:
            print "-------------check ip--------------"
            IsMalicious("./ip_location.txt")
        sys.exit(0)