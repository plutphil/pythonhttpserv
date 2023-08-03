import socket
#https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib/
def getlanip():
    return socket.gethostbyname(socket.gethostname())
from netifaces import interfaces, ifaddresses, AF_INET, AF_INET6
import netifaces
def getlanips():
    ip_list = []
    for interface in interfaces():
        ifa = ifaddresses(interface)
        if AF_INET in ifa:
            for link in ifa[AF_INET]:
                ip_list.append(link['addr'])
                #print(link['addr'],socket.gethostbyaddr(link['addr'])[0])
    return ip_list
def getlanipsv6():
    ip_list = []
    for interface in interfaces():
        ifa = ifaddresses(interface)
        if AF_INET6 in ifa:
            for link in ifa[AF_INET6]:
                ip_list.append(link['addr'])
    return ip_list
if __name__=="__main__":
    print(socket.gethostname())
    print(getlanips())
    print(getlanipsv6())