#!/bin/sh

INTERFACE=eth1
ADDRESS=192.168.12.1
BROADCAST=192.168.12.255
GATEWAY=192.168.0.1
NETMASK=255.255.255.0
NAMESERVER1=130.215.41.1
NAMESERVER2=130.215.41.2
NAMESERVER3=130.215.41.3

# If you are booting Tiny Core from a very fast storage such as SSD / NVMe Drive and getting 
# "ifconfig: SIOCSIFADDR: No such Device" or "route: SIOCADDRT: Network is unreachable"
# error during system boot, use this sleep statemet, otherwise you can remove it -
sleep .2

# kill dhcp client for $INTERFACE
sleep 1
if [ -f /var/run/udhcpc.$INTERFACE.pid ]; then
kill `cat /var/run/udhcpc.$INTERFACE.pid`
sleep 0.1
fi

# configure interface $INTERFACE
ifconfig $INTERFACE $ADDRESS netmask $NETMASK broadcast $BROADCAST up

# Start the DHCP Server Process once the Interface is Ready with the IP Add
sleep .1

sudo udhcpd /etc/udhcpd.conf &
