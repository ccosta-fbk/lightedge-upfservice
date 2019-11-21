#!/bin/sh


ip route add $enbs_subnet dev tun0
iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.20.0.0/16 -o eth0 -j MASQUERADE
ip route add 10.10.0.0/16 dev tun1
ip route add 10.20.0.0/16 dev tun1

