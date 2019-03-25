import pyshark
import os

INTERFACE = 'wlp3s0'
BURST_SECONDS = 1
READ_SECONDS = 2

IDENTIFIER_KEYS = ['dst', 'src_port', 'dst_port']
public_ip = os.popen('curl -s ifconfig.me').readline()
packet_statistics = {}


def check_burst(cap, start_index=0):
    for i in range(start_index, len(cap)-1):
        pkt_delta = float(cap[i+1].sniff_timestamp) - float(cap[i].sniff_timestamp)
        if pkt_delta >= BURST_SECONDS:
            return i
    return -1


# Extract necessary information for calculating/printing statistics
def packet_extract(pkt):
    timestamp = pkt.sniff_time
    src = str(pkt.ip.src)
    outbound = True if src == public_ip else False
    dst = str(pkt.ip.dst)
    src_port = str(pkt.layers[2].srcport)
    dst_port = str(pkt.layers[2].dstport)
    protocol = str(pkt.layers[-1].layer_name)
    length = pkt.capture_length
    return {'timestamp': timestamp, 'src': src, 'dst': dst, 'src_port': src_port, 'dst_port': dst_port,
            'protocol': protocol, 'outbound': outbound, 'length': length}


def packet_serialize(pkt_dict):
    val = ''
    for entry in IDENTIFIER_KEYS:
        val += pkt_dict[entry]

    return val


def print_analysis(pkts):
    for pkt in pkts:
        timestamp = pkt.sniff_time
        src = pkt.ip.src
        dst = pkt.ip.dst
        src_port = pkt.layers[2].srcport
        dst_port = pkt.layers[2].dstport
        protocol = pkt.layers[-1].layer_name
        print(str(timestamp) + " " + src + " " + dst + " " + src_port + " " + dst_port + " " + protocol)


def run(interface="eth1"):
    capture = pyshark.LiveCapture(interface=INTERFACE, display_filter='ip and tcp or udp')
    pkt_index = 0
    current_burst = []

    # main loop
    while True:

        # This loop will keep capturing packets until a burst interval is detected
        while check_burst(capture, pkt_index) == -1:
            capture.sniff(timeout=READ_SECONDS)

        end_burst = check_burst(capture, pkt_index) + 1
        current_burst = capture[pkt_index:end_burst]
        pkt_index = end_burst

        # do analysis with current burst...
        print_analysis(current_burst)



run(interface=INTERFACE)




