#! /usr/bin/python
#! -*- coding: UTF-8 -*-

import sys
sys.path.append("./packet")
from optparse import OptionParser
#from multiprocessing import Queue   多进程中的队列
from total import *


#def udp_scan(ip,port):

def main():
    usage="usage:GodScan.py -f icmp/banner/default/tcp -t <ip address> -p <port/1-2/1,2,3/all/default> -w 1/2/3 -level <1-10>"
    parser=OptionParser(usage=usage)
    parser.add_option("-f","--function",type="string",dest="funs",help="choose a way that you want to use to scan!")
    parser.add_option("-t","--target",type="string",dest="ipaddress",help="input your target ip address!")
    parser.add_option("-p","--port",type="string",dest="port",help="input your target's port!")
    parser.add_option("-w","--ways",type="int",dest="way",help="please input the level of TCP scan! 1 refers to HostScan, 2 refers to Full TCP-scan, 3 refers to half TCP-scan!")
    parser.add_option("-l","--level",type="int",dest="level",help="please input the model and corrections of the scan!")
    (options,args)=parser.parse_args()
    fun=options.funs
    ipaddress=options.ipaddress
    port=options.port
    way=options.way
    level=options.level
    port_list = []
    if ',' in port:   #80,3306,3389
        port=port.split(',')
        for x in port:
            port_list.append(int(x))
    elif '-' in port:  #80-99
        port=port.split('-')
        start=int(port[0])
        end=int(port[1])
        for x in range(start,end+1):
            port_list.append(x)
    elif 'all' in port:   #all
        for x in range(1,65536):
            port_list.append(int(x))
    elif 'default' in port:  #default
        defaultport = [80,135,139,445,1433,3306,3389,5944,8000]
        for x in defaultport:
            port_list.append(x)
    else:
        port_list.append(port)
    if fun=="tcp":
        if way == 1:
            fun="tcp1"
        elif way==2:
            fun="tcp2"
        elif way==3:
            fun="tcp3"
        else:
            fun="tcp1"  #默认情况下的模式

    try:
        if level < 1 and level > 10:
            level = 5  # 默认level攻击水平
        elif level >= 1 and level <= 10:
            pass
        else:
            level = 5
    except:
        level=5


    if fun =="icmp" or fun=="banner" or fun=="default" or fun=="tcp1" or fun=="tcp2" or fun=="tcp3":
        total_scan(ipaddress,port_list,fun,level)
    else:
        print("Unknown parameter! Please try again!")
        return 0


if __name__ == '__main__':
    main()