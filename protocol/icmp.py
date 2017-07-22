import struct
import socket

class ICMP(object):
    def __init__(self, payload=''):
        self.payload = payload
        self.type = 8
        self.code = 0
    def pack(self):
        packet = struct.pack(
            "!BBHHH", self.type, self.code, 0, 0, 0
        )
        chksum = icmpchecksum(packet)
        packet = struct.pack(
            "!BBHHH", self.type, self.code, chksum, 0, 0
        )
        return packet


def icmpchecksum(source_string):
    sum = 0
    countTo = (len(source_string)/2)*2
    count = 0
    while count<countTo:
        thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff 
        count = count + 2
    if countTo<len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff 
    sum = (sum >> 16)  +  (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer
    