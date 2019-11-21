#!/bin/sh

while [ -z $(getent hosts upf-lb-service | awk '{ print $1 }') ]
do
    echo "Waiting for the UPF LB to come up..."
    sleep 10
done

echo "UPF LB found"
upf_lb_addr=$(getent hosts upf-lb-service | awk '{ print $1 }')


sed -i 's/REMOTE_ADDR/'$upf_lb_addr'/g' /modes/upf/upf.click


./modes/upf/install_vgtp.sh
