#! /usr/bin/python
#! -*- coding: UTF-8 -*-
import sys
sys.path.append("./packet")
from optparse import OptionParser
import whois
from packet import whois
import socket
import os
import requests

def webip(url):   #get target's ip address
    ip=socket.gethostbyname(url)
    return ip

def whoisinfo(url):   #get target's whois information
    info=whois.whois(url)
    return info

def cdn_judge(url):  #judge if cdn exists
    ns="nslookup "+url
    data=os.popen(ns,"r").read()
    if data.count(".")>8:
        return 1
    else:
        return 0

def port_scan(url,port):   #judge if port is open
    try:
        ip = socket.gethostbyname(url)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        url=url.replace("http://","")
        url=url.replace("https://","")
        ip=url.replace("/","")

    try:
        server.connect((ip,port))
        print("Port:"+str(port)+" is On")
        return
    except:
        print("Port:" + str(port) + " is Off")
        return


def ym_list_check(url,location):   #mulu scan
    for ym_list in open(location):
        ym_list=ym_list.replace("\n","")
        url2=url+ym_list
        try:
            code = requests.get(url2).status_code
            if code == 200 or code == 302:
                print("url2:" + url2 + " Status:" + code)
        except:
            print("*****Unknown Errors!")





def main():
    usage="usage:webinfo.py -u <url:http://xxx/com> -l <dic location/None> -p <port/20-80/20,30,40/all/default>"
    parser=OptionParser(usage=usage)
    parser.add_option("-u","--url",type="string",dest="url",help="target web url")
    parser.add_option("-l","--local",type="string",dest="local",help="local dic location")
    parser.add_option("-p","--port",type="string",dest="port",help="target's port")
    (options,args)=parser.parse_args()
    url=options.url
    local=options.local
    port=options.port
    try:
        print("*****Url:" + url + " IP is:" + webip(url))
    except:
        print("Get ip Failed!")
    print("*****Whois information:")
    print(whoisinfo(url))
    result=cdn_judge(url)
    if(result==1):
        print("*****This website has CDN!")
    elif(result==0):
        print("*****This website do not have CDN!")
    else:
        print("*****CDN scan failed!")
    if ',' in port:  # 80,3306,3389
        port = port.split(',')
        for x in port:
            port_scan(url,int(x))
    elif '-' in port:  # 80-99
        port = port.split('-')
        start = int(port[0])
        end = int(port[1])
        for x in range(start, end + 1):
            port_scan(url,int(x))
    elif 'all' in port:  # all
        for x in range(1, 65536):
            port_scan(url,int(x))
    elif 'default' in port:  # default
        defaultport = [80, 135, 139, 445, 1433, 3306, 3389, 5944, 8000]
        for x in defaultport:
            port_scan(url,int(x))
    else:
        try:
            port_scan(url,int(port))
        except:
            try:
                defaultport = [80, 135, 139, 445, 1433, 3306, 3389, 5944, 8000]
                for x in defaultport:
                    port_scan(url,int(x))
            except:
                print("Scan Errors!")
    if local== None:
        pass
    else:
        try:
            ym_list_check(url,local)
        except:
            print("Scan dir failed!")
    print("*****All Scan finished!")


if __name__ == '__main__':
    main()