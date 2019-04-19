import pyshark
import numpy as np
import flow as fl
import os

null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
save = os.dup(1), os.dup(2)

DISPLAY_FILTER = 'ip and !(arp or icmp) and !(udp.port == 53 or udp.port == 5353 or udp.port == 17) and !(eth.dst[0] & 1) and (tcp or udp)'


# Extract the time between packets (in seconds) with pkt_b following after pkt_a
def pkt_delta(pkt_a, pkt_b):
    time_a = float(pkt_a.sniff_timestamp)
    time_b = float(pkt_b.sniff_timestamp)
    return time_b - time_a


def check_burst(a,b):
    return pkt_delta(a,b) > 1


def extract_pkt(path, src_ip=None):
    os.dup2(null_fds[0], 1)
    os.dup2(null_fds[1], 2)
    flow_dict = dict()
    bursts = []
    cap = pyshark.FileCapture(path, display_filter=DISPLAY_FILTER)
    meta = []
    ips = []
    burst_index = 0
    if not src_ip:
        for pkt in cap:
            ips.append(str(pkt.ip.src))
            ips.append(str(pkt.ip.dst))

        src_ip = max([(ips.count(chr), chr) for chr in set(ips)])[1] # get most occuring ip address in capture file
    prev = cap[0]
    for pkt in cap:
        pkt_dict = fl.packet_extract(pkt, src_ip) if src_ip else fl.packet_extract(pkt)

        flow_id = fl.packet_serialize(pkt_dict)

        if flow_id not in flow_dict.keys():
            flow_dict[flow_id] = fl.Flow()

        flow_dict[flow_id].add_pkt(pkt_dict)

        if not bursts:
            bursts.append([flow_dict[flow_id].get_analysis(pkt_dict)])

        if check_burst(prev, pkt):
            burst_index += 1
            bursts.append([flow_dict[flow_id].get_analysis(pkt_dict)])
        else:
            bursts[burst_index].append(flow_dict[flow_id].get_analysis(pkt_dict))
        prev = pkt

        meta.append(flow_dict[flow_id].get_feature_vector())
    os.dup2(save[0], 1)
    os.dup2(save[1], 2)

    # for flow in flow_dict.values():
    #     feature_vector = flow.get_feature_vector()
    #     meta.append(feature_vector)

    return np.array(meta), bursts


# test = extract_pkt('../GatewayVM/recorded_traffic/browser.pcap')
# print(np.shape(test))
# print(test[:,1])