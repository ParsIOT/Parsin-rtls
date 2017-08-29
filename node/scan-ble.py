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

fingerprints = {}
fingerprints2 = []
lock = threading.Lock()

# sys.stdout = open('/home/pi/rtls/out.txt','a')
# sys.stderr = open('/home/pi/rtls/err.txt','a')

print("START ANALYZE")


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
	default=10,
	type=int,
	help="scanning time in seconds (default 10)")

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
	print("\n\n\t\t______________________\n")
	print("SENDING TO SERVER")
	print("\n\t\t______________________\n\n")

	lock.acquire()
	fp = fingerprints.copy()
	fingerprints.clear()
	lock.release()

	# Compute medians
	for mac in fp:
		print(mac)
		if len(fp[mac]) == 0:
			continue
		fingerprints2.append({"mac": mac, "rssi": int(statistics.median(fp[mac]))})

	payload = {"node": socket.gethostname(), "signals": fingerprints2, "timestamp": int(time.time()), 'group': args.group}

	print(len(payload['signals']))

	try:
		if len(payload['signals']) > 0:
			r = requests.post(
				args.server +
				"/reversefingerprint",
				json=payload)
			print("\n\n\t\t=======================\n\n")
			print("Sent to server with status code: " + str(r.status_code))
			print("\n\n\t\t=======================\n\n")
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
		temp['mac'] = re.sub(r'[:]', '', mac[0].lower())

	rssi = re.findall(rssi_regex, line)
	if rssi:
		temp['rssi'] = rssi[0]
	else:
		pass

	if 'rssi' in temp and 'mac' in temp:
		if temp['rssi'] != 'invalid':
			lock.acquire()
			# print(temp)
			if temp['mac'] not in fingerprints:
				fingerprints[temp['mac']] = []
			fingerprints[temp['mac']].append(float(temp['rssi']))
			lock.release()
		temp.clear()
