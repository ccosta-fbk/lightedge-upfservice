#!/bin/sh

while [ -z $(getent hosts epc-service-pod | awk '{ print $1 }') ]
do
    echo "Waiting for the EPC to come up..."
    sleep 10
done

echo "EPC pod found"
EPC_POD_ADDR=$(getent hosts epc-service-pod | awk '{ print $1 }')


ip route add $EPC_POD_ADDR/32 dev tun0
