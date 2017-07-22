＃UDP Flood／ ICMP Flood ／TCP Flood Generate Program
# Configure File

[PROG]
THREADNUM = 1
#-1 means as fast as possible; other value means pps for each thread
SPEED = 1000
#TCP/UDP/ICMP/IPFRAGMENT
MODE  = TCP
DEV   = eth0

[ETHER]
GWADDR = 00:00:00:00:00:00

[IP]
# RANDOM / LOCALRANDOM / TRUE
ADDRMODE = RANDOM
DSTADDR  = "10.0.0.1"

[UDP]
# portlist, 70000 means each thread random select one; 70001 means each packet random select one; 0~65535 means use the designated value, the user can give a list of designated ports seperated by colon
DSTPORTS       = 53,80
# from 0 to 1460, 70000 means each thread random select one; 70001 means each packet random select one; 0~1460 means use the designated value
PAYLOADLENGTH  = -1
#70000 means each thread random create constant payload;,  70001 means each thread read content from cache file
PAYLOADCONTENT = -1
PAYLOADFILE    = "1.dat"

[ICMP]
#type, 70000 means each thread random select one; 70001 means each packet random select one; 0~255 means use the designated value
ICMPTYPE       = 1
#code, 70000 means each thread random select one; 70001 means each packet random select one; 0~255 means use the designated value
ICMPCODE       = 1
# from 0 to 1460, 70000 means each thread random select one; 70001 means each packet random select one; 0~1460 means use PAYLOADLENGTH  = -1
#70000 means each thread random create constant payload;,  70001 means each thread read content from cache file
PAYLOADCONTENT = -1
PAYLOADFILE    = "1.dat"


[TCP]     
# portlist, 70000 means each thread random select one; 70001 means each packet random select one; 0~65535 means use the designated value
DPORTS          = 53,80
#FLAGS is the combination of SYN, ACK, PUSH, RST... 
FLAGS          = SYN,ACK
# from 0 to 1460, 70000 means each thread random select one; 70001 means each packet random select one; 0~1460 means use the designated value
PAYLOADLENGTH  = -1
#70000 means each thread random create constant payload;,  70001 means each thread read content from cache file
PAYLOADCONTENT = -1
PAYLOADFILE    = "1.dat"

