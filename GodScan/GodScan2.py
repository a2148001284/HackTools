#! /usr/bin/python
#! -*- coding: UTF-8 -*-

import sys
sys.path.append("./packet")
from optparse import OptionParser
#from multiprocessing import Queue   多进程中的队列
from total import *
import timeout_decorator
from scapy.all import *
from random import randint
from threading import Thread,Lock
from queue import Queue  #标准队列


@timeout_decorator.timeout(15,use_signals=False)
def banner_scan(ip,port):
    try:
        s = socket.socket()
        s.connect((ip, int(port)))
        s.send('testing'.encode())
        banner = s.recv(1024)
        s.close()
        string = "port:" + port + " banner is:" + str(banner)
        print(string)
        return
    except:
        print("target port has no response")
        return

def icmp_scan(flag,ip):  #用于主机发现  由于本身误差较大 所以进行多次发包从而使结果更可信
    while(flag):
        try:
            ip_id=randint(1,65535)
            icmp_id=randint(1,65535)
            icmp_seq=randint(1,65535)
            packet=IP(dst=ip,ttl=64,id=ip_id)/ICMP(id=icmp_id,seq=icmp_seq)/b'rootkit'
            result=sr1(packet,timeout=1,verbose=False)
            if result:
                for rcv in result:
                    scan_ip = rcv[IP].src
                    return 1
                break
            else:
                flag=flag-1
            if(flag==0):
                print("this1")
                return 0
        except:
            return 0

def python_open(ip,port):
    s=socket.socket()
    try:
        s.connect((ip,port))
        string="Host:"+ip+" port:"+str(port)+"is open!"
        print(string)
        return
    except:
        string = "Host:" + ip + " port:" + str(port) + "is close!"
        print(string)
        return



def tcp_scan(flag,ip,port,lock):   #flag=1 TCP随机端口扫描 用于主机发现  flag=2 TCP全开放扫描   flag=3  TCP半开放扫描
    times=3
    if flag==1:
        while(times):
            dport=randint(1,65535)
            packet=IP(dst=ip)/TCP(flags="A",dport=dport)
            response=sr1(packet,timeout=1.0,verbose=0)
            if response:
                if int(response[TCP].flags)==4:
                    time.sleep(0.5)
                    return 1
                else:
                    if(times==0):
                        return 0
                    times = times - 1
            else:
                if(times==0):
                    return 0
                times = times - 1

    elif flag==2:
        global q
        while(times):
            packet=IP(dst=ip)/TCP(sport=12345,dport=port,flags="S")
            response=sr1(packet,timeout=2)
            if (str(type(response))=="<type 'NoneType'>" or str(type(response))=="<'NoneType'>"):
                if(times==1):
                    string="port:"+str(port)+" is Off"
                    lock.acquire()
                    q.put(string)
                    lock.release()
                    return
                times = times - 1
            else:
                try:
                    if (response.haslayer(TCP)):
                        if (response.getlayer(TCP).flags == 0x12):
                            string = "port:" + str(port) + " is On"
                            lock.acquire()
                            q.put(string)
                            lock.release()
                            send_rst = sr(IP(dst=ip) / TCP(sport=12345, dport=port, flags="AR"), timeout=2)
                            return
                        elif response.getlayer(TCP).flags == 0x14:
                            if(times==1):
                                string = "port:" + str(port) + " is Off"
                                lock.acquire()
                                q.put(string)
                                lock.release()
                                return
                            times=times-1
                except:
                    if (times == 1):
                        string = "port:" + str(port) + " is Off"
                        lock.acquire()
                        q.put(string)
                        lock.release()
                        return
                    times=times-1
                    continue


    elif flag==3:
        while(times):
            packet=IP(dst=ip)/TCP(sport=12345,dport=port,flags="S")
            response=sr1(packet,timeout=2)
            if (str(type(response))=="<type 'NoneType'>" or str(type(response))=="<'NoneType'>"):
                if(times==1):
                    string = "port:" + str(port) + " is Off"
                    lock.acquire()
                    q.put(string)
                    lock.release()
                    return
                times = times - 1
            else:
                try:
                    if (response.haslayer(TCP)):
                        if (response.getlayer(TCP).flags == 0x12):
                            string = "port:" + str(port) + " is On"
                            lock.acquire()
                            q.put(string)
                            lock.release()
                            send_rst = sr(IP(dst=ip) / TCP(sport=12345, dport=port, flags="R"), timeout=2)
                            return
                        elif response.getlayer(TCP).flags == 0x14:
                            if(times==1):
                                string = "port:" + str(port) + " is Off"
                                lock.acquire()
                                q.put(string)
                                lock.release()
                                return
                            times=times-1
                except:
                    if (times == 1):
                        string = "port:" + str(port) + " is Off"
                        lock.acquire()
                        q.put(string)
                        lock.release()
                        return
                    times=times-1
                    continue


q = Queue(65535)



def total_scan(ip,list,function,level):
    if function=="icmp":
        result=icmp_scan(level,ip)
        if result:
            print("Host:"+ip+" is on")
            return
        else:
            print("Host:"+ip+" is close")
            return
    elif function=="banner":   #-----------???
        print("please wait for a minute!")
        for x in list:
            x=int(x)
            s=Thread(target=banner_scan,args=(ip,x,))
            s.start()
        return
    elif function =="default":
        for x in list:
            x=int(x)
            s=Thread(target=python_open,args=(ip,x,))
            s.start()
        return
    elif function=="tcp1" or function=="tcp2" or function=="tcp3":
        if function=="tcp1":
            mark=1
        elif function=="tcp2":
            mark=2
        elif function=="tcp3":
            mark=3
        else:
            mark=1
        if mark==1:
            res=tcp_scan(mark,ip,80)  #此时port随便写 用不到
            if res==1:
                print("Host:"+ip+"is Open!")
                return
            elif res==0:
                print("Host:" + ip + "is Closed!")
                return
            else:
                print("Host:" + ip + "is Closed!")
                return
        elif mark==2 or mark==3:   #多线程的结果可以通过栈或者队列来实现存储
            l=[]
            lock=Lock()
            for x in list:
                x=int(x)
                s=Thread(target=tcp_scan,args=(mark,ip,x,lock,))
                l.append(s)
                s.start()
            for s in l:
                s.join()  #全都阻塞当前进程  多线程结束才会继续执行当前的函数
            #time.sleep(15)
            #print(q.queue)
            while True:
                print(q.get())
                if  q.empty()==True:
                    break
            return




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