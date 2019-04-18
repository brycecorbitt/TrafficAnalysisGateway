import pyshark
import os
import ip_tool
import flow as fl
import classifyFlows
BURST_SECONDS = 1
DISPLAY_FILTER = 'ip and !(arp or icmp) and !(udp.port == 53 or udp.port == 5353 or udp.port == 17) and !(eth.dst[0] & 1) and (tcp or udp)'
IDENTIFIER_KEYS = ['src_port', 'dst_port', 'protocol']
null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
local_ip = ip_tool.get_ip_address
pkt_stats = dict()
burst_strings = []


# compares with previous packet read. Returns True if time difference >= 1 second
# Extract the time between packets (in seconds) with pkt_b following after pkt_a
def pkt_delta(pkt_a, pkt_b):
    if not pkt_a:
        return 0
    time_a = float(pkt_a.sniff_timestamp)
    time_b = float(pkt_b.sniff_timestamp)
    return time_b - time_a


def check_burst(a, b):
    return pkt_delta(a, b) >= 1


# Extract necessary information for calculating/printing statistics
def packet_extract(pkt):
    timestamp = str(pkt.sniff_time)
    src = str(pkt.ip.src)
    outbound = True if str(src) == str(local_ip) or '192.168.12' in str(src) else False
    dst = str(pkt.ip.dst)
    src_port = str(pkt.layers[2].srcport)
    dst_port = str(pkt.layers[2].dstport)

    protocol = str(pkt.layers[2].layer_name)
    length = int(pkt.length)
    # return the information we need as a dictionary
    return {'timestamp': timestamp, 'src': src, 'dst': dst, 'src_port': src_port, 'dst_port': dst_port,
            'protocol': protocol, 'outbound': outbound, 'length': length}


# generates a string to be used for indexing in dictionary
def packet_serialize(pkt_dict):
    val = ''
    if not pkt_dict['outbound']:
        val += pkt_dict['src']
        val += pkt_dict['dst_port']
        val += pkt_dict['src_port']
    else:  # inbound data needs the same indexing as outbound data, so we reverse the source and destination
        val += pkt_dict['dst']
        val += pkt_dict['src_port']
        val += pkt_dict['dst_port']

    val += pkt_dict['protocol']

    return val


# return pkt_dict info + pkt_stats collected for its index as a string to print
def get_analysis(pkt, index):
    return str(pkt['timestamp'] + " " + pkt['src'] + " " + pkt['dst'] + " " + pkt['src_port'] + " " + pkt['dst_port'] +
               " " + pkt['protocol'] + " " + str(pkt_stats[index]['pkts_sent']) + " " +
               str(pkt_stats[index]['pkts_received']) + " " + str(pkt_stats[index]['bytes_sent']) + " " +
               str(pkt_stats[index]['bytes_received']))


def run(interface="eth1"):
    global burst_strings
    flow_dict = {}
    capture = pyshark.LiveCapture(interface=interface, display_filter=DISPLAY_FILTER)
    prev = None
    for pkt in capture.sniff_continuously():  # for each packet received...
        pkt_dict = fl.packet_extract(pkt, local_ip) if local_ip else fl.packet_extract(pkt)

        flow_id = fl.packet_serialize(pkt_dict)

        if flow_id not in flow_dict.keys():
            flow_dict[flow_id] = fl.Flow()

        flow_dict[flow_id].add_pkt(pkt_dict)

        if check_burst(prev, pkt):
            for line in burst_strings:
                print(line)
            burst_strings = []

        flow_string = flow_dict[flow_id].get_analysis(pkt_dict)
        flow_string += " " + classifyFlows.get_label([flow_dict[flow_id].get_feature_vector()])
        burst_strings.append(flow_string)

        prev = pkt


if __name__ == '__main__':
    try:
        run()
    except KeyboardInterrupt:
        # print remaining packets that would've been used for next burst
        print()
        for l in burst_strings:
            print(l)

        # Used to suppress errors on KeyboardInterrupt
        os.dup2(null_fds[0], 1)
        os.dup2(null_fds[1], 2)
        exit(0)





