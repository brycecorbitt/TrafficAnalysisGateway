import sklearn
import packet_extract
import numpy as np
from sklearn.ensemble import RandomForestClassifier

PACKET_PATH = '../GatewayVM/recorded_traffic/'

training_captures = ['browser', 'youtube', 'weather_channel', 'google_news', 'fruit_ninja']


def format_sample(sample_caps):
    formatted = np.array([[0, 0]])
    lbls = np.array([])

    for i in range(len(sample_caps)):
        formatted = np.append(formatted, sample_caps[i], axis=0)
        lbls = np.append(lbls, np.array([(i)]*len(sample_caps[i])))

    formatted = formatted[1:]
    return formatted, lbls


if __name__ == '__main__':
    training_sample = []
    # Get training sample data for each pcap file
    for cap in training_captures:
        path = PACKET_PATH + cap + '.pcap'
        # print(path)
        data = packet_extract.extract_pkt(path)
        training_sample.append(data)

    training, labels = format_sample(training_sample)
    rf = RandomForestClassifier(n_estimators=100)

    rf.fit(training, labels)
    results = []
    for x in range(len(training_sample)):
        r = rf.predict(training_sample[x])
        results.append((r == x).sum()/len(r))

    print(sum(results)/len(results))
