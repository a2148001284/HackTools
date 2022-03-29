import sys
sys.path.append("./packet")
from banner import *
from icmp import *
from pyopen import *
from tcp import tcp_scan
from threading import Thread,Lock
from queue import Queue  #标准队列
from scapy.all import *

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
