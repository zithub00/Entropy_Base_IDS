from entropy_calculator import ddosDetection
from scapy.all import *
import time

calculate_permit=0
protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
de_ip = ddosDetection()
so_ip = ddosDetection()
de_port = ddosDetection()
so_port = ddosDetection()
len=ddosDetection()





def showPacket(packet):
    proto = packet[0][1].proto
    src_ip = packet[0][1].src
    dst_ip = packet[0][1].dst
    length = packet[0][1].len

    #ttl = packet[0][1].ttl
    #flag = packet[0][1].flags

    #packet.show()

    #if proto == 1:
        #print(proto)
        #print("protocol: %s: %s -> %s" % (protocols[proto], src_ip, dst_ip))
        #print("ttl : %s , packet_le : %s, flag : %s" % (ttl, length, flag))

    if proto == 6:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        
        #print("protocol: %s: %s[%s] -> %s[%s]" % (protocols[proto], src_ip,src_port, dst_ip, dst_prot))
        #print(ttl, length, flag)
        #print("ttl : %s , packet_le : %s, flag : %s" % (ttl, length, flag))

    if proto == 17:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    if proto == 6 or proto==17:
        so_ip.addinfo(src_ip)
        so_port.addinfo(src_port)
        de_ip.addinfo(dst_ip)
        de_port.addinfo(dst_port)
        len.addinfo(length)


def IDS(data):


    '''
    if .TH_min< <.TH_max
    if .TH_min < <.TH_max
    if .TH_min < <.TH_max
        warning()
    '''


def sniffing(filter):
    print('Destination IP       Destination Port        Source IP       Source Port         packet len')


    while 1:

        sniff(filter=(filter), prn=showPacket, count=1000)

        so_ip.calculateEntropy()
        so_port.calculateEntropy()
        de_ip.calculateEntropy()
        de_port.calculateEntropy()
        len.calculateEntropy()

        print(de_ip.sumEntropy_history[-1:], de_port.sumEntropy_history[-1:], so_ip.sumEntropy_history[-1:], so_port.sumEntropy_history[-1:], len.sumEntropy_history[-1:])

if __name__ == '__main__':
    filter = 'ip'
    sniffing(filter)

