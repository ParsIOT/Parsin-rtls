#!/usr/bin/python3

"""

sudo /usr/bin/hcitool -i hci0 lescan --duplicates > /dev/null | sudo /usr/bin/btmon | ./scan-ble.py --group ble-1-rtls --server https://lf.internalpositioning.com &
sudo hcitool lescan --duplicates > /dev/null | sudo btmon | ./scan-ble.py --group ble-1-rtls --server http://192.168.0.95:8072 --time 3


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

fingerprints = {}
fingerprints_lock = threading.Lock()
fingerprints2 = []

medians = {}
median_coefficients = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1]
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
	default=3,
	type=float,  # float int
	help="scanning time in seconds (default 3)")

args = parser.parse_args()

# Check arguments for group
if args.group == "":
	print("Must specify group with -g")
	sys.exit(-1)

print(args)
# Startup scanning
print("Using server " + args.server)
print("Using group " + args.group)


def submit_to_server():
	with fingerprints_lock:
		fp = fingerprints.copy()
		fingerprints.clear()

	# Compute medians
	for mac in fp:
		if len(fp[mac]) == 0:
			continue
		print("\n\t\t\t--------------------------\n")

		print("\t\tMAC Address :", mac, ",\t Count :", len(fp[mac]))

		median = int(statistics.median(fp[mac]))

		# Weighted Average
		with medians_lock:
			if mac not in medians:
				medians[mac] = deque(maxlen=10)
			medians[mac].append(median)
			median = 0
			l = len(medians[mac])
			if l == 10:
				div = divisor
				for i in range(0, 10):
					median += medians[mac][i] * median_coefficients[i]
			else:
				div = 0
				for i in range(0, l):
					median += medians[mac][l - 1 - i] * median_coefficients[9 - i]
					div += median_coefficients[9 - i]

		fingerprints2.append({"mac": mac, "rssi": int(median / div)})

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
		pass

	t_thread = threading.Timer(args.time, submit_to_server)
	t_thread.daemon = True
	t_thread.start()


t_thread = threading.Timer(args.time, submit_to_server)
t_thread.daemon = True
t_thread.start()

mac_regex = r"(?:[\s]+Address: ((?:[\w:]{2,3}){6}))"
rssi_regex = r"(?:[\s]+RSSI: )((?:-[\d]+)|(?:[\w]+))"
temp = {}
try:
	for line in sys.stdin:
		mac = re.findall(mac_regex, line)
		if mac:
			temp['mac'] = re.sub(r'[:]', '', mac[0].lower())

		rssi = re.findall(rssi_regex, line)
		if rssi:
			temp['rssi'] = rssi[0]
		else:
			pass

		if 'rssi' in temp and 'mac' in temp:
			if temp['rssi'] != 'invalid':

				with fingerprints_lock:
					# print(temp)
					if temp['mac'] not in fingerprints:
						fingerprints[temp['mac']] = []
					fingerprints[temp['mac']].append(float(temp['rssi']))

			temp.clear()

except Exception:
	pass
