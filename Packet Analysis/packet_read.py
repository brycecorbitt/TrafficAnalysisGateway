import pyshark
import os
import sys

INTERFACE = 'wlp3s0'
BURST_SECONDS = 1
READ_SECONDS = 1

IDENTIFIER_KEYS = ['src_port', 'dst_port', 'protocol']
public_ip = os.popen('curl -s ifconfig.me').readline()
pkt_stats= {}


def check_burst(cap, start_index=0):
    for i in range(start_index, len(cap)-1):
        pkt_delta = float(cap[i+1].sniff_timestamp) - float(cap[i].sniff_timestamp)
        if pkt_delta >= BURST_SECONDS:
            return i
    return -1


# Extract necessary information for calculating/printing statistics
def packet_extract(pkt):
    timestamp = str(pkt.sniff_time)
    src = str(pkt.ip.src)
    outbound = True if str(src) == str(public_ip) else False
    dst = str(pkt.ip.dst)
    src_port = str(pkt.layers[2].srcport)
    dst_port = str(pkt.layers[2].dstport)

    protocol = str(pkt.layers[2].layer_name)
    length = int(pkt.length)
    return {'timestamp': timestamp, 'src': src, 'dst': dst, 'src_port': src_port, 'dst_port': dst_port,
            'protocol': protocol, 'outbound': outbound, 'length': length}


def packet_serialize(pkt_dict):
    val = ''
    if not pkt_dict['outbound']:
        val += pkt_dict['src']
        val += pkt_dict['dst_port']
        val += pkt_dict['src_port']
    else:
        val += pkt_dict['dst']
        val += pkt_dict['src_port']
        val += pkt_dict['dst_port']

    val += pkt_dict['protocol']

    return val


def print_analysis(pkt, index):

    print(pkt['timestamp'] + " " + pkt['src'] + " " + pkt['dst'] + " " + pkt['src_port'] + " " + pkt['dst_port'] + " "
          + pkt['protocol'] + " " + str(pkt_stats[index]['pkts_sent']) + " " + str(pkt_stats[index]['pkts_received']) +
          " " + str(pkt_stats[index]['bytes_sent']) + " " + str(pkt_stats[index]['bytes_received']))


def run(interface="eth1"):
    capture = pyshark.LiveCapture(interface=interface, display_filter='ip and tcp or udp')
    pkt_index = 0
    current_burst = []

    # main loop
    while True:

        # This loop will keep capturing packets until a burst interval is detected
        while check_burst(capture, pkt_index) == -1:
            capture.sniff(timeout=READ_SECONDS)

        end_burst = check_burst(capture, pkt_index) + 1
        current_burst = capture[pkt_index:end_burst]
        capture.clear() # performed to prevent memory overflow
        pkt_index = end_burst

        # do analysis with current burst...
        entries = pkt_stats.keys()
        for pkt in current_burst:
            pkt_dict = packet_extract(pkt)
            index = packet_serialize(pkt_dict)
            if index not in entries:
                pkt_stats[index] = {'pkts_sent': 0, 'pkts_received': 0, 'bytes_sent': 0, 'bytes_received': 0}

            if pkt_dict['outbound']:
                pkt_stats[index]['pkts_sent'] += 1
                pkt_stats[index]['bytes_sent'] += pkt_dict['length']
            else:
                pkt_stats[index]['pkts_received'] += 1
                pkt_stats[index]['bytes_received'] += pkt_dict['length']

            print_analysis(pkt_dict, index)


if __name__ == '__main__':
    try:
        run()
    except KeyboardInterrupt:
        sys.exit(0)





