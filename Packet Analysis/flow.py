import statistics

TRAIN_SRC_IP='130.215.215.74'


def packet_extract(pkt, src_ip=TRAIN_SRC_IP):
    timestamp = str(pkt.sniff_time)
    time = str(pkt.sniff_timestamp)
    src = str(pkt.ip.src)
    outbound = True if str(src) == str(src_ip) or '192.168.12' in str(src) else False
    dst = str(pkt.ip.dst)
    src_port = str(pkt.layers[2].srcport)
    dst_port = str(pkt.layers[2].dstport)
    protocol = str(pkt.layers[2].layer_name)
    window_size = str(pkt.layers[2].window_size) if protocol == 'tcp' else -1
    length = int(pkt.length)
    # return the information we need as a dictionary
    return {'timestamp': timestamp, 'time': time, 'src': src, 'dst': dst, 'src_port': src_port, 'dst_port': dst_port,
            'protocol': protocol, 'outbound': outbound, 'length': length, 'window_size': window_size}


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


class Flow(object):

    def __init__(self):
        self.lengths = []
        self.time_deltas = []
        self.pkts_sent = 0
        self.pkts_recvd = 0
        self.bytes_sent = 0
        self.bytes_recvd = 0
        self.window_sizes = []
        self.blocked = False

    def add_pkt(self, pkt_dict):
        self.lengths.append(pkt_dict['length'])
        self.window_sizes.append(int(pkt_dict['window_size']))
        if not self.time_deltas:
            self.time_deltas.append(0)
        else:
            self.time_deltas.append(float(pkt_dict['time']) - self.time_deltas[-1])

        if pkt_dict['outbound']:
            self.pkts_sent += 1
            self.bytes_sent += pkt_dict['length']

        else:
            self.pkts_recvd += 1
            self.bytes_recvd += pkt_dict['length']

    def get_analysis(self, pkt_dict):
        return str(
            pkt_dict['timestamp'] + " " + pkt_dict['src'] + " " + pkt_dict['dst'] + " " + pkt_dict['src_port'] + " " + pkt_dict['dst_port'] +
            " " + pkt_dict['protocol'] + " " + str(self.pkts_sent) + " " +
            str(self.pkts_recvd) + " " + str(self.bytes_sent) + " " + str(self.bytes_recvd))

    def get_feature_vector(self):
        lengths = self.lengths + [0] * (10 - len(self.lengths)) if len(self.lengths) < 10 else self.lengths[:10]
        sizes = self.window_sizes + [0] * (10 - len(self.window_sizes)) if len(self.window_sizes) < 10 else self.window_sizes[:10]
        time_deltas = self.time_deltas + [0] * (10 - len(self.time_deltas)) if len(self.time_deltas) < 10 else self.time_deltas[:10]
        len_mean = statistics.mean(self.lengths)
        delta_mean = statistics.mean(self.time_deltas)
        window_mean = statistics.mean(self.window_sizes)

        if self.pkts_sent + self.pkts_recvd < 2:
            len_std_dev = 0
            delta_std_dev = 0
            window_std_dev = 0
        else:
            len_std_dev = statistics.stdev(self.lengths)
            delta_std_dev = statistics.stdev(self.time_deltas)
            window_std_dev = statistics.stdev(self.window_sizes)

        vector = [len_mean, len_std_dev, delta_mean, delta_std_dev, self.pkts_sent, self.pkts_recvd, window_mean, window_std_dev]
        # vector = [window_mean, len_std_dev, delta_mean]
        vector.extend(lengths)
        vector.extend(sizes)
        #vector.extend(time_deltas)
        #vector = [len_mean, delta_mean, self.pkts_recvd + self.pkts_sent]
        return vector