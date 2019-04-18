import sklearn
import packet_extract
import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
import random
import itertools

PACKET_PATH = '../GatewayVM/recorded_traffic/'
TEST_PATH = '../GatewayVM/recorded_traffic/test_data/'
TRAINED_PATH = '../GatewayVM/recorded_traffic/trained.forest'

training_captures = ['browser', 'youtube', 'weather_channel', 'google_news', 'fruit_ninja']


def format_sample(sample_caps):
    formatted = sample_caps[0]
    lbls = np.zeros(len(formatted))

    for i in range(1, len(sample_caps)):
        formatted = np.append(formatted, sample_caps[i], axis=0)
        lbls = np.append(lbls, np.array([i]*len(sample_caps[i])))

    return formatted, lbls


if __name__ == '__main__':
    training_sample = []
    if(not os.path.exists(TRAINED_PATH)):
        # Get training sample data for each pcap file
        for cap in training_captures:
            path = PACKET_PATH + cap + '.pcap'
            print(path)
            data = packet_extract.extract_pkt(path)
            training_sample.append(data)
        with open(TRAINED_PATH, 'wb') as f:
            pickle.dump(training_sample, f)

    else:
        with open(TRAINED_PATH, 'rb') as f:
            training_sample = pickle.load(f)

    training, labels = format_sample(training_sample)
    rf = RandomForestClassifier(n_estimators=100, max_depth=7)

    print("Start Training!!!")
    rf.fit(training, labels)

    testing_sample = []
    for cap in training_captures:
        path = TEST_PATH  + cap + '.pcap'
        # print(path)
        testing_sample.append(packet_extract.extract_pkt(path))

    s = [4,1,2,4,5]
    best_estimators = 100
    # 2, 3, 2, 3, 3

    rf = RandomForestClassifier(n_estimators=100, max_depth=7, class_weight={0: s[0], 1:s[1],2:s[2], 3: s[3],4: s[4]})
    rf.fit(training, labels)
    results = []
    for x in range(len(testing_sample)):
        r = rf.predict(testing_sample[x])
        results.append((r == x).sum() / len(r))
        print(results[-1])

    print(sum(results) / len(results))
    print(s)
    # Max
    # accuracy: 0.7302498839618605
    # weights: (4, 1, 2, 4, 5)
    # 0.6566308844482602