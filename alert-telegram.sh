#!/bin/bash
# Made by MrMichou
# Bot to alert in case the value is to big

interface="eth0"
date=$(date +%m-%d-%Y)
hours=$(date +%H:%M)
value_original=$(/usr/bin/ifstat -b -i $interface .5 1 | /bin/grep -o '[0-9]\{1,9\}\.[0-9]\{1,9\}' | awk 'NR==1{ print $1}')
TOKEN=xxxxxxxxxxxxxxxxxxxxxxxxxxxxx
ID="xxxxxxxxx"
URL="https://api.telegram.org/bot$TOKEN/sendMessage"

value=$(echo $value_original | cut -f1 -d".")
avoid_alert=$(date +%s)

if (( $avoid_alert < $(cat $PATH/scripts/time.log) ));then
	for ip in $(sudo cat /var/log/syslog | grep "$cat_date" | grep IPTables--UDP--666: | awk '{print $10}' | tr -d SRC= | sort -h | uniq -u);do
	        last_ip=$(whois $ip | grep country: | awk '{ print $2 }' | uniq -u)
	        list="$list \n$ip $last_ip"
	done;
	curl -s -X POST $URL -d chat_id=$ID -d text="$(echo -e "$list")" > /dev/null 2>&1
	exit 0;
fi

if (( "$value" > 10000 )); then
        if (( "$value" > 1024 ));then
                metrics="Mbit/s"
                value=$(awk "BEGIN { print int( $value/ 1000) }")
                # Check for date instead for number line        
        else
                metrics="Kbit/s"
        fi
        #done;
        curl -s -X POST $URL -d chat_id=$ID -d text="$(echo -e "$date \n$hours : Attaque en cours de $value $metrics \n$list")" > /dev/null 2>&1
        avoid_alert=$(awk "BEGIN { print int($avoid_alert + 300) }")
        echo $avoid_alert > $PATH/scripts/time.log
fi
