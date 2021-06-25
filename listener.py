import scapy.all as scapy
from scapy_http import http

def listen_packet(interface):
    scapy.sniff(iface=interface,store=False,prn=analyze_packet)
    #prn=callback func
def analyze_packet(packets):
    #packets.show()
    if packets.haslayer(http.HTTPRequest):
        if packets.haslayer(scapy.Raw):
            print(packets[scapy.Raw].load)


listen_packet("eth0")