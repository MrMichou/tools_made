#!/bin/sh
# To output ip's with  
# sudo tcpdump -nn -r dumpfile.pcap -q ip -l | awk '{ ip = gensub(/([0-9]+.[0-9]+.[0-9]+.[0-9]+)(.*)/,"\\1","g",$3); if(!d[ip]) { print ip; d[ip]=1; fflush(stdout) } }' > IPFILE
# sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4  IPFILEtcpdump
# 
OUTPUT_FILE=/tmp/server_location.txt

# Grab this server's public IP address
PUBLIC_IP=`curl -s https://ipinfo.io/ip`

# Call the geolocation API and capture the output
for i in $(cat IPFILE);do
	GETIP=$(curl -s https://ipvigilante.com/$i/full | jq '.data.country_name' | tr -d \" )
	echo "$i $GETIP" >> ${OUTPUT_FILE}
done;
