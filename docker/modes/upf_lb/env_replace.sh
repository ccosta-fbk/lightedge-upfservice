#!/bin/sh

while [ -z $(getent hosts upf-service | awk '{ print $1 }') ]
do
    echo "Waiting for the UPF to come up..."
    sleep 10
done

echo "UPF found"
upf_addr=$(getent hosts upf-service | awk '{ print $1 }')


sed -i 's/UPF_ADDR/'$upf_addr'/g' /modes/upf_lb/upf_lb.click
