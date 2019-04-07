import pyshark
import numpy as np

""""
Explanation of display filter:
'ip' filters out ipv6 traffic
'not arp' removes arp requests
'!(udp.port == 53 or udp.port == 5353 or udp.port == 17)' removes dns, msdns, and dhcp requests
'!(eth.dst[0] & 1)' removes all broadcast/multicast requests
"""
DISPLAY_FILTER = 'ip and not arp and !(udp.port == 53 or udp.port == 5353 or udp.port == 17) and !(eth.dst[0] & 1)'

PACKET_PATH = '../GatewayVM/recorded_traffic'


# Extract the time between packets (in seconds) with pkt_b following after pkt_a
def pkt_delta(pkt_a, pkt_b):
    time_a = float(pkt_a.sniff_timestamp)
    time_b = float(pkt_b.sniff_timestamp)
    return time_b - time_a


# Extracts the distance (in seconds) between each packet and their lengths in bytes
def extract_pkt(path):
    cap = pyshark.FileCapture(path, display_filter=DISPLAY_FILTER)
    lengths = []
    times = []
    prev = cap[0]
    for pkt in cap:
        time_delta = pkt_delta(prev, pkt)
        length = int(pkt.length)
        times.append(time_delta)
        lengths.append(length)
        prev = pkt

    return np.concatenate(([times], [lengths]), axis=0)


# test = extract_pkt(PACKET_PATH + '/browser.pcap')
# print(np.shape(test))
# print(test[:,1])
