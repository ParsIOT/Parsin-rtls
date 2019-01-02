#!/usr/bin/python3

"""

sudo /usr/bin/hcitool -i hci0 lescan --duplicates > /dev/null | sudo /usr/bin/btmon | ./scan-ble.py --group ble-1-rtls --server https://lf.internalpositioning.com &
sudo hcitool lescan --duplicates > /dev/null | sudo btmon | ./scan-ble.py --group ble-1-rtls --server http://192.168.0.95:8072 --time 3

	-g, --group
		group name

	-s, --server    default: https://lf.internalpositioning.com
		rtls server address, including port number

	-t --time       default: 1 second
		time interval for sending data to rtls server

"""

import argparse
import atexit
import os
import re
import requests
import socket
import statistics
import sys
import threading
import time
from collections import deque
import numpy as np
import matplotlib.pyplot as plt

fingerprints = {}
fingerprints_lock = threading.Lock()
fingerprints2 = []

plotMaxLen = 100

plotLenCount = 0

def run_plt():
	plt.axis([0, plotMaxLen, -25, -110])
	while 1:
		plt.pause(0.1)
	plt.show()

plt_thread = threading.Thread(target=run_plt)
plt_thread.daemon = True
plt_thread.start()


medians = {}
median_coefficients = [0.005, 0.027, 0.0648, 0.121, 0.176, 0.1995]
median_coefficients_len = len(median_coefficients)
divisor = 0
for i in median_coefficients:
	divisor += i
medians_lock = threading.Lock()


# sys.stdout = open('/home/pi/rtls/out.txt','a')
# sys.stderr = open('/home/pi/rtls/err.txt','a')

def exit_handler():
	print("Exiting...stopping scan..")
	os.system("sudo pkill -9 btmon")
	os.system("sudo pkill -9 hcitool")
	os.system("sudo hciconfig "+args.interface+" down")
	os.system("sudo hciconfig "+args.interface+"hci0 up")


def submit_to_server():
	global plotLenCount
	global plt
	with fingerprints_lock:
		fp = fingerprints.copy()
		fingerprints.clear()

	# Compute medians
	if len(fp) != 0:
		for mac in fp:
			if len(fp[mac]) == 0:
				continue
			print("\n\t\t\t--------------------------\n")

			print("\t\tMAC Address :", mac, ",\t Count :", len(fp[mac]))

			median = int(statistics.median(fp[mac]))

			# Weighted Average
			with medians_lock:
				if mac not in medians:
					medians[mac] = deque(maxlen=median_coefficients_len)
				medians[mac].append(median)
				median = 0
				l = len(medians[mac])
				if l == median_coefficients_len:
					div = divisor
					for i in range(0, median_coefficients_len):
						median += medians[mac][i] * median_coefficients[i]
				else:
					div = 0
					for i in range(0, l):
						median += medians[mac][l - 1 - i] * median_coefficients[median_coefficients_len - 1 - i]
						div += median_coefficients[median_coefficients_len - 1 - i]

			plotLenCount+=1
			if plotLenCount >= plotMaxLen:
				plotLenCount=0
			plt.scatter(plotLenCount, int(median / div), c=args.color)
			fingerprints2.append({"mac": mac, "rssi": int(median / div)})
	else:
		plotLenCount+=1
		if plotLenCount >= plotMaxLen:
			plotLenCount=0
		plt.scatter(plotLenCount, -108, c=args.color)
	payload = {"node": socket.gethostname(), "signals": fingerprints2, "timestamp": int(time.time()), 'group': args.group}

	try:
		if len(payload['signals']) > 0:
			r = requests.post(
				args.server +
				"/reversefingerprint",
				json=payload)
			print("\t\t==========================================\n")
			print("\tSent %s fingerprint(s) to server with status code: %s" % (len(payload['signals']), r.status_code))
			print("\n\t\t==========================================")
			fingerprints2.clear()
	except Exception:
		print("\t\t++++++++++++++++++++++++++++++++++++++++++\n")
		print("\t\tCould not send data to server!")
		print("\n\t\t++++++++++++++++++++++++++++++++++++++++++")
		fingerprints2.clear()
		pass

	t_thread = threading.Timer(args.time, submit_to_server)
	t_thread.daemon = True
	t_thread.start()


atexit.register(exit_handler)

parser = argparse.ArgumentParser()
parser.add_argument("-g", "--group", default="", help="group name")
parser.add_argument(
	"-s",
	"--server",
	default="https://lf.internalpositioning.com",
	help="send payload to this server")
parser.add_argument(
	"-t",
	"--time",
	default=1,
	type=float,  # float int
	help="scanning time in seconds (default 3)")

parser.add_argument(
	"-i",
	"--interface",
	default="hci0",
	help="filtered interface (default hci0)")


parser.add_argument(
	"-c",
	"--color",
	default="r",
	help="plot color (default r)")

args = parser.parse_args()

# Check arguments for group
if args.group == "":
	print("Must specify group with -g")
	sys.exit(-1)

print("Using server " + args.server)
print("Using group " + args.group)

t_thread = threading.Timer(args.time, submit_to_server)
t_thread.daemon = True
t_thread.start()

temp = {}
interfaceFound = False
# Startup scanning
try:
	for line in sys.stdin:
		if not interfaceFound:
			interfaceFound = False if re.findall(r"(.*\["+args.interface+"\].*)", line)==[] else True
		if interfaceFound:
			mac = re.findall(r"(?:[\s]+Address: ((?:[\w:]{2,3}){6}))", line)
			if mac:
				temp['mac'] = mac[0].lower()
			rssi = re.findall(r"(?:[\s]+RSSI: )((?:-[\d]+)|(?:[\w]+))", line)
			if rssi:
				temp['rssi'] = rssi[0]
			else:
				pass

			if 'rssi' in temp and 'mac' in temp:
				if temp['rssi'] != 'invalid':

					with fingerprints_lock:
						# print(temp)
						if temp['mac'] == "04:a3:16:97:d9:c8":
							if temp['mac'] not in fingerprints:
								fingerprints[temp['mac']] = []
							fingerprints[temp['mac']].append(float(temp['rssi']))

				interfaceFound = False
				temp.clear()

except Exception:
	pass
