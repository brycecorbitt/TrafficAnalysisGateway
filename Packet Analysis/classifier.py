import sklearn
import packet_extract
PACKET_PATH = '../GatewayVM/recorded_traffic/'

training_captures = ['browser', 'youtube', 'weather_channel', 'google_news', 'fruit_ninja']


if __name__ == '__main__':
    training_features = []
    for cap in training_captures:
        path = PACKET_PATH + cap + '.pcap'
        print(path)
        data = packet_extract.extract_pkt(path)
        training_features.append(data)

    print(training_features)