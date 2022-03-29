import sys
sys.path.append("./packet")
from random import randint
from scapy.all import *

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

'''
if __name__ == '__main__':
    print(icmp_scan(5,"192.168.56.107"))
'''