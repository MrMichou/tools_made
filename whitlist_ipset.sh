#!/bin/bash
value=""
for ip in $(sudo cat /var/log/syslog | grep "$cat_date" | grep "$value" | awk '{print $10}' | tr -d SRC= | sort -h | uniq -u);do
	country=$(whois $ip | egrep -i '[C|c]ountry:' | awk '{ print $2 }' | uniq -u)
	ISP=""	
	if [[ $country == "FR" ]];then
		ISP=$(whois $ip | grep 'role')
		case $ISP in
  			*"SFR"*)
				route=$(whois $ip | grep route | awk '{ print $2 }')
				if [[ $1 =~ '(Y|y)es' ]];then
					 sudo ipset add IpAuto $route
				fi
    				ISP="SFR"
				;;
  			*"Bouygue"*)
				route=$(whois $ip | grep route | awk '{ print $2 }')
    				if [[ $1 =~ '(Y|y)es' ]];then
					 sudo ipset add IpAuto $route
    				fi
				ISP="Bouygue"
				;;
  			*"Wanadoo"*)
				route=$(whois $ip | grep route | awk '{ print $2 }')
				if [[ $1 =~ '(Y|y)es' ]];then
					 sudo ipset add IpAuto $route
				fi
    				ISP="Wanadoo"
				;;
			*"ProXad"*)
				route=$(whois $ip | grep route | awk '{ print $2 }')
				if [[ $1 =~ '(Y|y)es' ]];then
					 sudo ipset add IpAuto $route
				fi
				ISP="Free"
				;;
			*"Numericable"*)
				route=$(whois $ip | grep route | awk '{ print $2 }')
				if [[ $1 =~ '(Y|y)es' ]];then
					 sudo ipset add IpAuto $route
				fi
				ISP="Numericable"
				;;		
			*)
				ISP=""
				;;
		esac
	fi
	list="$list \n$ip \t $country \t $ISP"
done;
echo -e $list

