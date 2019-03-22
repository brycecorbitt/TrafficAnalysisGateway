import pyshark

INTERFACE = 'enp0s31f6'
BURST_MILLIS = 1000
READ_INTERVAL = 1 #number of packets to read in each loop iteration
capture = pyshark.LiveCapture(interface=INTERFACE)


def run():
    capture.sniff(packet_count=READ_INTERVAL)
    print(capture[0])
    #for packet in capture.sniff_continuously(packet_count=1):
    #    print("Just arrived! " + str(packet))


run()