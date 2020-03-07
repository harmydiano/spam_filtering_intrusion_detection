import socket
import os
import time
from struct import *
import binascii
#import optparse
#from  scapy.all import *
#from IPy import IP as IPTEST
# host to listen on
host = "192.168.43.167"
if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP
s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
s.bind((host, 0))
#sock,addr =s.accept()
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)


ttlValues = {}
THRESH = 5

def checkTTL(ipsrc, ttl):
    if IPTEST(ipsrc).iptype() == 'PRIVATE':
        return
    if not ttlValues.has_key(ipsrc):
        pkt = sr1(IP(dst=ipsrc)/ICMP(), retry=0, timeout=1, verbose=0)
        ttlValues[ipsrc] = pkt.ttl
    if abs(int(ttl) - int(ttlValues[ipsrc])) > THRESH:
        print('\n[!] Detected Possible Spoofed Packet From: ' + ipsrc)
        print('[!] TTL: ' + ttl + ', Actual TTL: ' + str(ttlValues[ipsrc]))

pktcount ={}
def ddos(packet):
    THRESH = 5000
    
    #packet string from tuple
    packet = packet[0]
    
    #take first 20 characters for the ip header
    ip_header = packet[0:20]

    #now unpack them :)
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    
    iph_length = ihl * 4
    total_len = iph[2]
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
    t =iph_length
    tcp_header = packet[t:t+20]    
    tcpheader = packet[0][34:52] # TCP headers are also 20 bytes in length. We start at offset 34 and go to 54.
    tcp_hdr = unpack("!HHLLBBHHH", tcp_header)
    src_port=tcp_hdr[0]
    dst_port=tcp_hdr[1]
    #pktcount = {}
    #print "---------- TCP Header -----------"
    #print "Source Port:", tcp_hdr[0]
    #print "Destination Port:", tcp_hdr[1]
    #print "Flags:", binascii.hexlify(tcp_hdr[3])    
       
    if protocol == 6:
        print "---------- TCP Header -----------"
        print "Source Port:" +str(s_addr)+ ':' +str(src_port)
        print "Destination Port:" + str(d_addr)+ ':' +str(dst_port)
            
        if dst_port == 6667:
            if '!lazor' in data.lower:
                print '[] DDoS Hivemind issued by: '+src_addr
                print '[+] Target CMD: ' + data
        elif src_port ==6667:
            if '!lazor' in data.lower:
                print '[] DDoS Hivemind issued by: '+src_addr
                print '[+] Target CMD: ' + data        
        elif dst_port == 80:
            print "the port is now 80"
            stream = s_addr + ':' +d_addr
            #print stream
            if pktcount.has_key(stream):
                print "stream in pktcount"
                pktcount[stream] =pktcount[stream]+1
            else:
                pktcount[stream] =1
        
    #print pktcount
    
    for stream in pktcount:
        pktsent = pktcount[stream]
        print pktsent
        if pktsent > THRESH:
            s_addr = stream.split(':')[0]
            d_addr = stream.split(':')[1]
            print "A Denial of service attack attempt detected"
            print '[+]' +s_addr+ ' atttacked ' +d_addr+ ' with ' +str(pktsent) + 'pkts'
        #checkTTL(src_addr, ip_ttl)


while True:
    data=s.recvfrom(65565)
    ddos(data)
    
    try:  
        if "HTTP" in data[0][54:]:
            print "[","="*30,']'
            print "Checking if user is downloading a bad software on the network"
            raw=data[0][54:]
            #if "\r\n\r\n" in raw:
             #   line=raw.split('\r\n\r\n')[0]
              #  print "[*] Header Captured "
               # print line[line.find('HTTP'):]
                #if "dabworld" in line:
                 #   print "user visited dabworld"
            if ".jpg" in raw:
                print "packet contains images"
            elif "loic" in raw and not ".zip" in raw:
                print "User attempting to download ddos tool"
            elif "porn" and ".mp4" in raw or "porn" in raw:
                print "user is downloading porn"
            elif ".zip" and "loic" in raw or "LOIC" in raw:
                print "user downloaded loic"            
            elif "aircrack" and ".tar" in raw:
                print "User is downloading a bad software for the system"
            else:
                print "no images yet"
            #print raw
        else:
            #print '[{}]'.format(data)
            pass
        except:
            pass    