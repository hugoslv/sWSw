from struct import *
import hashlib
import socket
import sys
import pylab
import re
import json


def tostring(data):
    dtype=type(data).__name__
    if dtype=='ndarray':
        if pylab.shape(data)!=(): data=list(data)
        else: data='"'+data.tostring()+'"'
    elif dtype=='dict' or dtype=='tuple' or dtype=='str' or dtype=='unicode':
        data=json.dumps(data)
    elif dtype=='NoneType':
        data=''
#    elif dtype=='str' or dtype=='unicode':
#        data='"'+unicode(data)+'"'
    return str(data)


def part(token):
    digits=""
    for d in re.compile('[0-9]').findall(token):
        digits = digits + str(d)
    count=0
    for s in re.compile(' ').findall(token):
        count = count + 1
    return int(int(digits)/count)


def handshake(data):
    bytes = data[len(data)-8:]
    resource = re.compile("GET (.*) HTTP").findall(data)[0]
    host = re.compile("Host: (.*)\r\n").findall(data)[0]
    origin = re.compile("Origin: (.*)\r\n").findall(data)[0]
    key1 = re.compile("Sec-WebSocket-Key1: (.*)\r\n").findall(data)[0]
    key2 = re.compile("Sec-WebSocket-Key2: (.*)\r\n").findall(data)[0]

    challenge = pack('>II', part(key1), part(key2)) + ''.join([ pack('>B', ord( x )) for x in bytes ])

    hash = hashlib.md5(challenge).digest()

    return "HTTP/1.1 101 Web Socket Protocol Handshake\r\n"+"Upgrade: WebSocket\r\n"+"Connection: Upgrade\r\n"+"Sec-WebSocket-Origin: "+origin+"\r\n"+"Sec-WebSocket-Location: "+" ws://"+host+resource+"\r\n\r\n".encode('latin-1')+hash


def encode(data):
    return b"\x00" + data.encode('utf-8') + b"\xff"


def decode(data):
    return data.decode('utf-8', 'ignore').replace('\x00','')


def connect(addr="localhost", port=9999):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    sock.bind((addr, port))  
    sock.listen(0)  
    
    print "LISTENING ON PORT " + str(port)
    
    peer, info = sock.accept()
    
    peer.send(handshake(peer.recv(256)))
    
    print "ACCEPTED CONNECTION FROM " + info[0]
    print "_____________________________"

    return (peer, info)


def handle(peer, sigterm="DISCONNECTED", callback=(lambda msg: msg)):
    while True:
        try: req=decode(peer.recv(256))
        except Exception as e: print e
    
        if req!='':
            
            if req.find(sigterm)>=0: break
        
            cmds=re.compile('\)[a-z]|\)[A-Z]').findall(req)
            ncmds=len(cmds)+1
            
            for i in range(0,ncmds):
                if i==(ncmds-1): cmd=req
                else:
                    end=req.find(cmds[i])+1
                    cmd=req[:end]
                    req=req[end:]
                
                print cmd
            
                res=callback(cmd)
                peer.send(encode(res))

                print res
        
    try:
        peer.shutdown(socket.SHUT_RDWR)
    except:
        pass

    peer.close()
    
    print sigterm

if __name__=='__main__':

    handle(connect()[0])