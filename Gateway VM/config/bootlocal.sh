#!/bin/sh
# put other system startup commands here
/usr/local/etc/init.d/openssh start &
/opt/eth1.sh &
sudo syslogd
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o eth1 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
sudo dnsmasq
