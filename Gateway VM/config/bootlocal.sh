#!/bin/sh
# put other system startup commands here
/usr/local/etc/init.d/openssh start &
/opt/eth1.sh &
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
sudo dnsmasq
