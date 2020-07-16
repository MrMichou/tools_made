#!/bin/bash
interface="eno1"
date=$(date +%H:%M_%m-%d-%Y)
value=$(/usr/bin/ifstat -i $interface .5 1 | /bin/grep -o '[0-9]\{1,9\}\.[0-9]\{1,9\}' | awk 'NR==1{ print $1}')

echo "$value"
if [[ $value < 102400 ]]; then
        echo "TCPDUMP"
        tcpdump -w dumpfile_$date.pcap -i $interface -c 100000
fi
