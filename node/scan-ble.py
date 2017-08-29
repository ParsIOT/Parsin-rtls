#!/usr/bin/python3

"""

sudo hcitool -i hci0 lescan --duplicates > /dev/null | sudo btmon | ./ble.py >scan.txt &

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

fingerprints = {}
fingerprints2 = []


def exit_handler():
	print("Exiting...stopping scan..")
	os.system("pkill -9 btmon")
	os.system("pkill -9 hcitool")


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
	default=10,
	help="scanning time in seconds (default 10)")

args = parser.parse_args()

# Check arguments for group
if args.group == "":
	print("Must specify group with -g")
	sys.exit(-1)

# Startup scanning
print("Using server " + args.server)
print("Using group " + args.group)


def submit_to_server():
	# Compute medians
	for mac in fingerprints:
		if len(fingerprints[mac]) == 0:
			continue
		print(mac)
		print(fingerprints[mac])
		fingerprints2.append({"mac": mac, "rssi": int(statistics.median(fingerprints[mac]))})

	fingerprints.clear()

	payload = {"node": socket.gethostname(), "signals": fingerprints2, "timestamp": int(time.time()), 'group': args.group}

	try:
		if len(payload['signals']) > 0:
			r = requests.post(
				args.server +
				"/reversefingerprint",
				json=payload)
			print("Sent to server with status code: " + str(r.status_code))
			fingerprints2.clear()
	except Exception:
		pass
	threading.Timer(args.time, submit_to_server).start()


threading.Timer(args.time, submit_to_server).start()

mac_regex = r"(?:[\s]+Address: ((?:[\w:]{2,3}){6}))"
rssi_regex = r"(?:[\s]+RSSI: )((?:-[\d]+)|(?:[\w]+))"
temp = {}
for line in sys.stdin:
	mac = re.findall(mac_regex, line)
	if mac:
		mac = mac[0].lower()
		if mac not in fingerprints:
			fingerprints[mac] = []
		temp['mac'] = mac

	rssi = re.findall(rssi_regex, line)
	if rssi:
		temp['rssi'] = rssi[0]
	else:
		pass

	if 'rssi' in temp and 'mac' in temp:
		if temp['rssi'] != 'invalid':
			print(temp)
			fingerprints[temp['mac']].append(float(temp['rssi']))
		temp.clear()
