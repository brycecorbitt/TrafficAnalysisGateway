

import socket
import fcntl
import struct
import subprocess


# hardcoded for temp fix
def get_ip_address(interface=b'eth1'):
    return '192.168.12.2'
    #s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #return socket.inet_ntoa(fcntl.ioctl(
    #    s.fileno(),
    #    0x8915,  # SIOCGIFADDR
    #    struct.pack('256s', interface[:15])
    #)[20:24])


def block_ip_address(ip):
    subprocess.Popen(['sudo', '/usr/local/sbin/iptables', '-I', 'INPUT', '-s', str(ip), '-j', 'DROP'])

