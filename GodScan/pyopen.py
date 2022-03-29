import sys
sys.path.append("./packet")
import socket
from scapy.all import *


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