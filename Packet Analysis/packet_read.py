import pyshark
import os
BURST_SECONDS = 1

IDENTIFIER_KEYS = ['src_port', 'dst_port', 'protocol']
null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
public_ip = os.popen('curl -s ifconfig.me').readline()
pkt_stats = dict()
burst_strings = []
last_pkt = None


# compares with previous packet read. Returns True if time difference >= 1 second
def check_burst(pkt):
    global last_pkt
    if not last_pkt:
        last_pkt = pkt
        return False
    pkt_delta = float(pkt.sniff_timestamp) - float(last_pkt.sniff_timestamp)

    if pkt_delta >= BURST_SECONDS:
        last_pkt = pkt
        return True
    last_pkt = pkt  # store packet to be used for checking next packet
    return False


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
    capture = pyshark.LiveCapture(interface=interface, display_filter='ip and tcp or udp')

    for pkt in capture.sniff_continuously():  # for each packet received...
        # extract packet information, add it to statistics dictionary
        entries = pkt_stats.keys()
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

        # if a burst is detected, print all stored packet strings and clear the list
        if check_burst(pkt):
            for line in burst_strings:
                print(line)
            burst_strings = []

        # instead of storing packet until burst is detected, store the string that is to be printed for memory
        # efficiency.
        burst_strings.append(get_analysis(pkt_dict, index))


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





