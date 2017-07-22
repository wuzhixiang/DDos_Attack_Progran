#coding=utf-8
import MySQLdb
import subprocess

conn = MySQLdb.connect(host="localhost",user="root",passwd="",db="test")
portcur = conn.cursor()
portcur.execute("select experimentID from atkmanage_platformconfig")
portcontent = portcur.fetchall()
modeid = portcontent[0][0]
print modeid
portcur.execute("select nicname, gwaddr, attackid, attacktime, name from atkmanage_hostconfig where experimentid = " + str(modeid))
portcontent = portcur.fetchall()
device = portcontent[0][0]
gatewayaddress = portcontent[0][1]
atkid = portcontent[0][2]
time = portcontent[0][3]
destination = portcontent[0][4]
portcur.execute("select attacktype, attackspeed, addressmode, dstports, tcpflags, icmptype, icmpcode, payloadlength, payloadcontent, payloadfile from atkmanage_attackprofile where atk_id = " + str(atkid))
portcontent = portcur.fetchall()
floodingmode = portcontent[0][0]
speed = portcontent[0][1]
addressmode = portcontent[0][2]
dstports = portcontent[0][3]
tcpflags = portcontent[0][4]
icmptype = portcontent[0][5]
icmpcode = portcontent[0][6]
payloadlength = portcontent[0][7]
payloadcontent = portcontent[0][8]
payloadfile = portcontent[0][9]
sen = 'python attack.py' + ' -s ' + str(speed) + ' -m ' + str(floodingmode) + ' -d ' + str(device) + ' -g ' + str(gatewayaddress) + ' -a ' + str(addressmode) + ' -e ' + str(destination) + ' -p ' + str(dstports) + ' -l ' + str(payloadlength) + ' -c ' + str(payloadcontent) + ' -f ' + str(tcpflags) + ' -i ' + str(icmptype) + ' -o ' + str(icmpcode) + ' -j ' + str(time) + ' -r ' + str(payloadfile) 
p = subprocess.Popen(sen, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
for line in p.stdout.readlines():
    print line,
    retval = p.wait()
portcur.close()
