import socket
#https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib/
def getlanip():
    return socket.gethostbyname(socket.gethostname())