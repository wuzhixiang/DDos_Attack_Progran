'''
    Ethernet
'''

import struct

def mac2byte(addr):
    '''
        Convert MAC address to byte
    '''
    mac = []
    byte = ''
    if ':' in addr:
        mac = addr.split(':')
    elif '-' in addr:
        mac = addr.split('-')
    else:
        raise ValueError('error: MAC address not valid')
    for m in mac:
        byte += chr(int(m, 16))
    return byte

class layer():
    pass

class ETHER(object):
    def __init__(self, src='', dst='', type=''):
        self.src = mac2byte(src)
        self.dst = mac2byte(dst)
        self.type = type
    def pack(self):
        ethernet = struct.pack('!6s6sH',
                               self.dst,
                               self.src,
                               self.type)
        return ethernet
    def unpack(self, data):
        ethernet = layer()
        packet = data[:14]
        dst, src, type = struct.unpack('!6s6sH', packet)
        ethernet.src = src
        ethernet.dst = dst
        ethernet.type = type
        ethernet.list = [dst, src, type]
        return ethernet
