# !/usr/bin/python3
# coding=utf-8
# -*- coding: utf-8 -*-
# Fait par Michael N. Alias MrMichou

# You need to install ifstat, tcpdump, 
# pip install pygeoip
import os, re, sys, subprocess as sub
import socket, fcntl, struct, time, binascii
import pygeoip
from struct import *
from threading import Thread
#

# Variable Global
interface = 'enp0s31f6'
interface_ip = ""
pallier_UN = 10
pallier_DEUX = 20
folder = ""
nbPacket = 1000

# Global arrays to store informations
tabip = []
tabipPays = []
storenbPacket = []
storeData = []

# Fonction flag_values_Country
def flag_values_Country() :
	valeurBL = 0
	valeurWL = 0
	valueFlagCountry = 0
	tabBL = []
	tabWL = []
	for i in range(len(tabipPays)) :
		if tabipPays[i] == 'CA' or tabipPays[i] == 'RU' or tabipPays[i] == 'CN' : # Fear the mapple syrop lelelel 
			#print 'IP B : %s ' % tabip[i]
			tabBL = tabip[i]
			valeurBL = valeurBL + 1
		else :
			#print 'IP C : %s ' % tabip[i]
			tabWL = tabip[i]
			valeurWL = valeurWL + 1
	if valeurBL + valeurWL > 0 :	
		valueFlagCountry = (valeurBL / float(valeurBL + valeurWL)) * 100 # Convert the values on a 100%
		valueFlagCountry = valueFlagCountry * 25 / float(100) # Convert on a 25 
		valueFlagCountry = int(valueFlagCountry)
	return valueFlagCountry
# comment1	
# Fonction flag_values_packet 
# Pas vraiment un flag a revoir la fonction et faire une autre
# Celle-ci peu quand meme aider. Sur quoi est-ce que je me base le % ?
# Une IP qui envoie 
def flag_values_packet() :
	totalpacket = 0
	valeur = 0
	calculvaleurPacket = []
	for i in range(len(storenbPacket)) :
		totalpacket = totalpacket + storenbPacket[i]
		
	for i in range(len(storenbPacket)) :
		if totalpacket > 0 :
			valeur = storenbPacket[i]
			valeur = ((valeur / float(totalpacket)) * 100)
			calculvaleurPacket.append(int(valeur))
	return calculvaleurPacket

# Fonction Compare_Check_Data_AND_Store():
def Compare_Check_Data_AND_Store(Newvalue):
	Newvalue = binascii.hexlify(b''+Newvalue+'')
	if Newvalue in storeData:
		i = 0
	else :
		storeData.append(Newvalue)

# Fonction write_data_packet
def write_data_packet():
	file = open("datapacket.txt","w")
	for i in range(len(storeData)) :
		file.write(str( storeData[i] +"\n"))
	file.close()


# Fonction Compare_OldNew_Packet
def Compare_OldNew_Packet(Newvalue, Oldvalue):
	values = []
	valuesPourcentage = []

	if Oldvalue :
		if len(Newvalue) == len(Oldvalue) :
			for x in range(len(Newvalue)) :
				valueNew = Newvalue[x]
				valueOld = Oldvalue[x]
				if valueNew > 0 or valueOld > 0:
					values.append(valueNew - valueOld)
		return values

# Fonction Compare_Individual_Pourcent_Packet 		
def Compare_Individual_Pourcent_Packet(Newvalue, Oldvalue):
	values = []
	valuesPourcentage = []

	if Oldvalue :
		if len(Newvalue) == len(Oldvalue) :
			for x in range(len(Newvalue)) :
				valueNew = Newvalue[x]
				valueOld = Oldvalue[x]
				if valueNew > 0 or valueOld > 0:
					valeurPour = (valueNew - valueOld) / valueOld * 100
					valeurPour = int(valeurPour)
					valuesPourcentage.append(valeurPour)
		return valuesPourcentage		

# Fonction Compare_ONly
def Compare_ONly(ValueOldNew) :
	if ValueOldNew :
		if len(ValueOldNew) > 0 :
			for i in range(len(ValueOldNew)) :
				if ValueOldNew[i] == 0 :
					remove_position(i)
	
# Fonction Compare_ON_and_POUR
def Compare_ON_and_POUR(ValueOldNew, ValuePour) :
	if ValueOldNew :
		if ValueOldNew :
			if len(ValueOldNew) == len(ValuePour) : 
				for i in range(len(ValuePour)) :
					if ValueOldNew[i] == 0 and ValuePour[i] == 0 :
						remove_position(i)

# Fonction flag_values_bytes
def flag_values_bytes(value_in, avg_b) :
	moyenne = 0.1
	val_moyenne = 0
	avg_moyenne = 0

	for i in range(len(avg_b)) :
		moyenne = avg_b[i] + moyenne
		if avg_b > 0 or moyenne < 0 :
			val_moyenne = float(moyenne / float(len(avg_b)))
			avg_moyenne = float(value_in / float(moyenne) * 100)
		# if (val_moyenne < value_in) :
			# Est-ce que j'analyse plus ?
		# elif (val_moyenne > value_in) :
			# Ma valeur est plus grande que la moyenne ?
			# On doit faire un cycle jour nuit aussi etant donnee que les valeurs la journee son plus nombreuse
	return (avg_moyenne, val_moyenne)
	#elif value_in < avg_b 
		
# Fonction flag_values_ip
def flag_values_ip(valeur, oldvaleur) :
	calcul = 0
	if (valeur > oldvaleur) :
		calcul = valeur - oldvaleur
		if oldvaleur != 0 :
			calcul = calcul / float(oldvaleur)
			calcul = int(calcul * 100)
		else :
			calcul = 0
	# print 'Valeur : ' + str(valeur)
	# print 'Valeur Old : ' + str(oldvaleur)
	return calcul
# Fonction flag total

# Fonction flag compare data
#def compare_flag():
	# Il faut une partie DDoS et une DoS
	# Il faut trouver une corralessence entre les valeurs de chacune des variables qui pourrait
	# faire en sorte que les faux-positif soit affer un maximum
	# Pour les DDoS on sait que les IP sont en general de pays etranger a celui du pays
	# Un autre facteur est la connexion massives de celle-ci en un laps de temps tres cours
	# Se lancer sur une base de temps X avec le nombre IP et le % des payes connecter
	# 
	#if valeurdip > lanciennevaleurdip :
	#if (len(storenbPacket) > 3) :
	#	for i range(len(storenbPacket)) :
	#		if i > 95 or  :
	#		
# Fonction remove_position()
def remove_position(valeur) :
	try: 
		os.system('echo '+ tabip[valeur] + ' ' + tabipPays[valeur] +'>> saveip.txt')
		os.system('sort saveip.txt | uniq')
		tabip.pop(valeur)
		tabipPays.pop(valeur)
		storenbPacket.pop(valeur)
	except IndexError:
		print ('Nop') 

# Fonction get_ip_interface
def get_ip_interface(interface):
	IP = os.popen('ifconfig '+ str(interface) +' | grep "inet\ addr" | cut -d: -f2 | cut -d" " -f1')
	IP_ADRESS=IP.read()
	return IP_ADRESS

# Fonction get_network_direct_traffic
def get_network_direct_traffic() :
	f = os.popen('ifstat -i '+ str(interface) +' .5 1 | grep -o "[0-9]\{1,9\}\.[0-9]\{1,9\}"')
	now = f.read()
	ligne = now.splitlines()

	Val_IN = float (ligne[0])
	Val_OUT = float (ligne[1])
	return (Val_IN, Val_OUT)

# Fonction ipLocator 	
def ipLocator(ip):
	GeoIPDatabase = 'GeoLiteCity.dat'
	ipData = pygeoip.GeoIP(GeoIPDatabase)
	record = ipData.record_by_name(ip)
	return record['country_code']
	
# Fonction get_network_bytes
def get_network_bytes(interface):
    for line in open('/proc/net/dev', 'r') :
        if interface in line:
            data = line.split('%s:' % interface)[1].split()
            rx_bytes, tx_bytes = (data[0], data[8])
            return (rx_bytes, tx_bytes)

# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b

 
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error as err:
    #print('Socket could not be created. Error Code : ' + str(err[0]) + ' Message ' + err[1])
	print(str(__getitem__()))
	sys.exit()
  
# Fonction get_record_tcpdump
def get_record_tcpdump(condition) :
	if condition == True:
		print("Lancement de TCPDUMP")
		p = sub.Popen(('tcpdump', '-nn', '-s', '0', '-c', '2500', '-w', 'oui.pcap'), stdout=sub.PIPE) # Ajouter des argument modulable date pour le nbPacket, carte et date pour le fichier
		for row in iter(p.stdout.readline, b''):
			print(row.rstrip()) # process here
	else:
		print('Bien')
# Fonction get_ip_TCP
# netstat -nt | grep ':30120.*ESTABLISHED' | awk '{ print $5 }' | grep -Po '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort -V | uniq > /root/iptables/tcp.log		
# def get_ip_TCP():
# Fonction get_ip_UDP
def sniffer_UDP() :
	
	ip_priv_A = "(10)(\.([2]([0-5][0-5]|[01234][6-9])|[1][0-9][0-9]|[1-9][0-9]|[0-9])){3}"
	ip_priv_B = "(172)\.(1[6-9]|2[0-9]|3[0-1])(\.([2][0-5][0-5]|[1][0-9][0-9]|[1-9][0-9]|[0-9])){2}"
	ip_priv_C = "(192)\.(168)(\.[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]){2}"

	while True : 
		packet = s.recvfrom(65565)
		#packet string from tuple
		packet = packet[0]
		#parse ethernet header
		eth_length = 14
		
		eth_header = packet[:eth_length]
		eth = unpack('!6s6sH' , eth_header)
		eth_protocol = socket.ntohs(eth[2])
		#print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)
	
		#Parse IP packets, IP Protocol number = 8
		if eth_protocol == 8 :
			#Parse IP header
			#take first 20 characters for the ip header
			ip_header = packet[eth_length:20+eth_length]
			#now unpack them :)
			iph = unpack('!BBHHHBBH4s4s' , ip_header)
	
			version_ihl = iph[0]
			version = version_ihl >> 4
			ihl = version_ihl & 0xF
	
			iph_length = ihl * 4
	
			ttl = iph[5]
			protocol = iph[6]
			s_addr = socket.inet_ntoa(iph[8]);
			d_addr = socket.inet_ntoa(iph[9]);
	
			#UDP packets
			if protocol == 17 :
				u = iph_length + eth_length
				udph_length = 8
				udp_header = packet[u:u+8]
	
				#now unpack them :)
				udph = unpack('!HHHH' , udp_header)
				
				source_port = udph[0]
				dest_port = udph[1]
				length = udph[2]
				checksum = udph[3]
				#print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
				#print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum)
				
				if (str(s_addr) in tabip) : 
					for i in range(len(tabip)):
						if str(s_addr) == tabip[i] :
							val = storenbPacket[i]
							storenbPacket[i] = val + 1
						else:
							i = 0
				else :
					if str(s_addr) == '127.0.0.1' or str(s_addr) == '127.0.0.53' :
						i = 0
					elif re.search(ip_priv_A, s_addr):
						i = 0
					elif re.search(ip_priv_B, s_addr):
						i = 0
					elif re.search(ip_priv_C, s_addr):
						i = 0	
					else :
						tabip.append(str(s_addr))
						tabipPays.append(ipLocator(str(s_addr)))
						storenbPacket.append(1)
					#print tabipPays
				h_size = eth_length + iph_length + udph_length
				data_size = len(packet) - h_size
				#get data from the packet
				data = packet[h_size:]
				#print 'Data : ' + data
				Compare_Check_Data_AND_Store(packet)
				
# Fonction write_data
def write_data(rx_bytes, tx_bytes, valKB_in, valKB_out) :
	# Store data rx and tx
	# Need the average of all the data
	file = open("RXTXData.txt","w")
	
	file.write("DONNER IFCONFIG : \n")
	file.write("Valeur RX : " + str(rx_bytes) + " kb/s \n")
	file.write("Valeur TX : " + str(tx_bytes) + " kb/s \n")
	
	file.write("DONNER IFSTAT : \n")
	file.write("Valeur RX : " + str(valKB_in) + " kb/s \n")
	file.write("Valeur TX : " + str(valKB_out) + " kb/s \n")
	file.write("DONNER DU SCRIPT : \n")
	file.write("Addresse IP : " + str(tabip) + " \n")
	file.write("Country IP : " + str(tabipPays) + " \n")
	file.write("NB Packet : " + str(storenbPacket) + " \n")
	file.close()



if __name__ == '__main__':
	# Threading
	t1 = Thread(target = sniffer_UDP)
	t1.start()
	# Call Fonction
	interface_ip = get_ip_interface(interface)
	# write_data(rx_bytes, tx_bytes, valKB_in, valKB_out)
	
	rx_bytes, tx_bytes = get_network_bytes(interface)
	valKB_in, valKB_out = get_network_direct_traffic()
	# ------------------------
	ValTime = 0
	ValuesIP = 0
	ValuesIPOLD = 0
	ValuesFlagIP = 0
	ValuesFlagBytesVal = 0
	ValuesFlagBytesAvg = 0
	
	array_oldnbpacket = []
	array_compPacket = []
	array_oldcompPacket = []
	array_compPacketPour = []

	array_pourcentage = []
	array_ValuesComp = []
	array_ValuesBytes = []
	# ------------------------
	while True:
		clear = lambda: os.system('clear')
		print ('Version 1.0.7')
		if (t1.is_alive() == True) : # Check if the thread is dead
			print ('Thread is running') # Sometime it crashes to check this
		#else :
			#t1.start()
		print('---------------------') 
		print('IP DE LA MACHINE : %s' % interface_ip)
		print('%s kb/s Val IN' % valKB_in)
		print('%s kb/s Val OUT' % valKB_out)
		print('%s bytes received' % rx_bytes)
		print('%s bytes sent' % tx_bytes)
		print('---------------------') 
		print('IP NB :                %s' % ValuesIP)
		print('IP NB OLD :            %s' % ValuesIPOLD)
		print('IP List :              %s' % tabip)
		print('IP PAYS :              %s' % tabipPays)
		print('---------------------')
		print('NB PACKET              %s' % storenbPacket)
		print('OLD PACKET             %s' % array_oldnbpacket)
		print('COMPARE PACKET         %s' % array_compPacket)
		print('COMPARE PACKET OLD     %s' % array_oldcompPacket)
		print('COMPARE PACKET POUR    %s' % Compare_Individual_Pourcent_Packet(array_compPacket, array_oldcompPacket))
		print('---------------------')
		print('Valeur Bytes :         %s' % int(ValuesFlagBytesVal))
		print('Val pour Bytes :       %s' % int(ValuesFlagBytesAvg))
		print('---------------------') 
		flag_values_Country()
		print ('Valeur flag Packet:    %s' % str(array_pourcentage))
		print ('Valeur flag country :  %s' % str(flag_values_Country()))
		print ('Valeur flag IP :       %s' % str(ValuesFlagIP))
		print ('Valeur Time  :         %s' % str(ValTime))
		print ('---------------------')
		print('Oui' + str(array_ValuesBytes))
		# print('Data' + str(storeData))
		ValuesIP = len(tabip)
		
		array_pourcentage = flag_values_packet()
		Compare_ON_and_POUR(array_compPacket, array_pourcentage)
		array_ValuesComp = Compare_ONly(array_compPacket)
		#print ValTime
		time.sleep(3)
		
		rx_bytes, tx_bytes = get_network_bytes(interface)
		valKB_in, valKB_out = get_network_direct_traffic()
		write_data_packet()
		if ValTime % 3 != 0 :
			array_compPacket = Compare_OldNew_Packet(storenbPacket, array_oldnbpacket)
		#array_compPacketPour = Compare_Individual_Pourcent_Packet(array_compPacket, array_oldcompPacket)
		ValuesFlagIP = flag_values_ip(ValuesIP, ValuesIPOLD)

		if ValTime % 2 == 0 :
			array_oldnbpacket = storenbPacket[:]
			ValuesIPOLD = ValuesIP

		if ValTime % 3 == 0 :
			if array_compPacket is not None: 
				array_oldcompPacket = array_compPacket[:]	
		elif ValTime % 5 == 0 :
				# PARTIS A TESTER ET REGARDER SI LOGIQUEMENT SEST PROPRE
				#if valKB_in > 0 : # ON RAJOUTE POUR TEST KEKEKEK
				if array_ValuesBytes : # On test pour ajouter la 1er valeur afin de calculer les valeurs
						array_ValuesBytes.append(valKB_in) 
				else :
					array_ValuesBytes.append(ValuesFlagBytesVal)		
				
				ValuesFlagBytesAvg, ValuesFlagBytesVal = flag_values_bytes((valKB_in), array_ValuesBytes)
				# Moyenne pour les valeurs en pourcentage et valeur.
				# Find a way to save data and analyse it
		elif ValTime == 500 :
			ValTime = 0
		#elif ValTime % 500 == 0 :
			#write_data(rx_bytes, tx_bytes, valKB_in, valKB_out)
			#ValTime = 0
		ValTime = ValTime + 1
		clear()
		# Convertir en MB/s actuellement en kb/s A FAIRE
		#if valKB_in <= 10:
			#print 'valeur stade 1'
			#get_record_tcpdump(False) # TU CHANGERAS CA !!
		#if valKB_in >= 10:
			#print 'valeur stade 2'
