#!/usr/bin/python3
# Created by MrMichou
# ToDo:
# - Reorganise with function and call (I'm too lazy right now)
# - Add a "part" to clear ip not used | Done

import pymysql
import subprocess

connection = pymysql.connect(host='',port=, user='', password='', db='', charset='utf8mb4', cursorclass=pymysql.cursors.DictCursor)
try:
	with connection.cursor() as cursor:
        	# Read a single record
        	sql = "SELECT `xxxxxxxx` FROM `xxxxxxx`"
        	cursor.execute(sql)
        	result = cursor.fetchall()
finally:
    	connection.close()
list_ip = subprocess.Popen("/sbin/ipset list xxxxxxxxxx", stdout = subprocess.PIPE, shell=True)
values = list_ip.stdout.readlines()

del values[:7]
ipset_list = []
db_list = []
for y in values:
	y = str(y.strip())
	y = y.strip("'").strip("b'")
	ipset_list.append(y)	

for x in result:
	db_list.append(x['ip'])
	if x['ip'] not in ipset_list:
		print("Adding ip "+ x['ip'])
		cmd_add = "/sbin/ipset add xxxxxxxxxxxx {0}".format(x['ip'])
		out = subprocess.call(cmd_add, shell=True)

for z in ipset_list:
	if z not in db_list:
		print("Removing ip "+ z)
		cmd_delete = "/sbin/ipset del xxxxxxxxxxxxx {0}".format(z)
		out = subprocess.call(cmd_delete, shell=True)
