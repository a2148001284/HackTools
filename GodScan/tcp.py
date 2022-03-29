import sys
sys.path.append("./packet")
from random import randint
from scapy.all import *

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