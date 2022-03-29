import sys
sys.path.append("./packet")
import timeout_decorator
import socket
from scapy.all import *

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