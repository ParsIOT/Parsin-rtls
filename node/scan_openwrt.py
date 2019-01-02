#!/usr/bin/python3

# Copyright 2015-2017 Zack Scholl. All rights reserved.
# Use of this source code is governed by a AGPL
# license that can be found in the LICENSE file.

# scan.py --interface wlp4s0 --time 1 --group parsiot-1 --server http://192.168.0.24 < /dev/null > std.out 2> std.err &

import sys
import json
import socket
import time
import subprocess
import os
import glob
import argparse
import logging
import statistics
import atexit

logger = logging.getLogger('scan.py')

import requests


def start_monitor_mode(wlan):
	logger.debug("Starting monitor mode...")
	print(run("airmon-zc start "+wlan))
	time.sleep(500)
	return get_first_wifi_card()
	
def stop_monitor_mode(wlanMon):
	logger.debug("Stopping monitor mode...")
	print(run("airmon-zc stop "+wlanMon))
	time.sleep(500)
	


def run_continouesly(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)
    while True:
        line = process.stdout.readline().rstrip()
        if not line:
            break
        yield line

def run(commnad):
    p = subprocess.Popen(commnad, shell=True, stdin=subprocess.PIPE,
	                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
	
    output, err = p.communicate()
    output = output
    if err != None:
        print("Err:" ,err)
    return output


def get_first_wifi_card():
	cmd = "iw dev  | grep Interface | awk '{print $2 }'"
	p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
	                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
	output = p.stdout.read()
	return output

def tcpdump_is_running():
	ps_output = subprocess.Popen(
		"ps", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	ps_stdout = ps_output.stdout.read()
	isRunning = 'tcpdump' in ps_stdout and '[tcpdump]' not in ps_stdout
	#print("tcpdump is running: " + str(isRunning))
	return isRunning


def process_scan(time_window):
	logger.debug("Reading files...")
	output = ""
	maxFileNumber = -1
	fileNameToRead = ""
	for filename in glob.glob("/tmp/tshark-temp*"):
		fileNumber = int(filename.split("_")[1])
		print("\n\t\t", filename, fileNumber)
		if fileNumber > maxFileNumber:
			maxFileNumber = fileNumber
			fileNameToRead = filename

	logger.debug("Reading from %s" % fileNameToRead)
	cmd = subprocess.Popen(("tshark -r " + fileNameToRead + " -T fields -e frame.time_epoch -e wlan.sa -e wlan.bssid -e radiotap.dbm_antsignal").split(
	), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	output += cmd.stdout.read().decode('utf-8')

	timestamp_threshold = float(time.time()) - float(time_window)
	fingerprints = {}
	relevant_lines = 0
	for line in output.splitlines():
		try:
			timestamp, mac, mac2, power_levels = line.split("\t")

			if mac == mac2 or float(timestamp) < timestamp_threshold or len(mac) == 0:
				continue

			relevant_lines += 1
			rssi = power_levels.split(',')[0]
			if len(rssi) == 0:
				continue

			if mac not in fingerprints:
				fingerprints[mac] = []
			fingerprints[mac].append(float(rssi))
		except:
			pass
	logger.debug("..done")

	# Compute medians
	fingerprints2 = []
	for mac in fingerprints:
		if len(fingerprints[mac]) == 0:
			continue
		print(mac, fingerprints[mac])
		fingerprints2.append(
			{"mac": mac, "rssi": int(statistics.median(fingerprints[mac]))})

	logger.debug("Processed %d lines, found %d fingerprints in %d relevant lines" %
	             (len(output.splitlines()), len(fingerprints2), relevant_lines))

	payload = {
		"node": socket.gethostname(),
		"signals": fingerprints2,
		"timestamp": int(time.time())}
	logger.debug(payload)
	return payload


def run_command(command):
	p = subprocess.Popen(
		command.split(),
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT)
	return iter(p.stdout.readline, b'')


def tcpdump_is_running():
	ps_output = subprocess.Popen(
		"ps", stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	ps_stdout = ps_output.stdout.read().decode('utf-8')
	isRunning = 'tcpdump' in ps_stdout and '[tcpdump]' not in ps_stdout
	logger.debug("tcpdump is running: " + str(isRunning))
	return isRunning


def start_scan(wlanMon):
	for path in run_continouesly("tcpdump -nni "+wlanMon+" -v"):
		if (tcpdump_is_running()):
			print(path)
		else:
			break


def stop_scan():
	if tcpdump_is_running():
		print("Exiting...stopping scan..")
    	tcpdumpPID = run("ps | grep tcpdump | awk '{print $1 }'") ######
    	run("kill "+tcpdumpPID)
    
		


def main():
	# Check which interface
	default_wlan = get_first_wifi_card()
	default_wlan_mon = default_wlan+"mon"
	# default_single_wifi = False
	# if len(default_wlan) != 0:
		# default_single_wifi = True
	# else:
		# return
	if len(default_wlan) == 0:
		return

	# Parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("-g", "--group", default="", help="group name")
	parser.add_argument(
		"-i",
		"--interface",
		default=default_wlan,
		help="Interface to listen on - default %s" % default_wlan)
	parser.add_argument(
		"-t",
		"--time",
		default=10,
		help="scanning time in seconds (default 10)")
	# parser.add_argument(
	# 	"--single-wifi",
	# 	default=default_single_wifi,
	# 	action="store_true",
	# 	help="Engage single-wifi card mode?")
	parser.add_argument(
		"-s",
		"--server",
		default="https://lf.internalpositioning.com",
		help="send payload to this server")
	parser.add_argument("-n", "--nodebug", action="store_true")
	args = parser.parse_args()

	# Check arguments for group
	if args.group == "":
		print("Must specify group with -g")
		sys.exit(-1)

	# Check arguments for logging
	loggingLevel = logging.DEBUG
	if args.nodebug:
		loggingLevel = logging.ERROR
	logger.setLevel(loggingLevel)
	fh = logging.FileHandler('scan_openwrt.log')
	fh.setLevel(loggingLevel)
	ch = logging.StreamHandler()
	ch.setLevel(loggingLevel)
	formatter = logging.Formatter(
		'%(asctime)s - %(funcName)s:%(lineno)d - %(levelname)s - %(message)s')
	fh.setFormatter(formatter)
	ch.setFormatter(formatter)
	logger.addHandler(fh)
	logger.addHandler(ch)

	# Startup scanning
	print("Using server " + args.server)
	logger.debug("Using server " + args.server)
	print("Using group " + args.group)
	logger.debug("Using group " + args.group)

	
	default_wlan_mon = start_monitor_mode(args.interface)
	start_scan(default_wlan_mon)

	while True:
		print("\n\n\t======\tWHILE\t======\t\n\n")
		try:
			payload = process_scan(args.time)
			payload['group'] = args.group

			if len(payload['signals']) > 0:
				r = requests.post(
					args.server +
					"/reversefingerprint",
					json=payload)
				logger.debug(
					"Sent to server with status code: " + str(r.status_code))
			time.sleep(float(args.time))  # Wait before getting next window

			
			

		except Exception:
			logger.error("Fatal error in main loop", exc_info=True)
			time.sleep(float(args.time))


	stop_monitor_mode(default_wlan_mon)



def exit_handler():
    stop_scan()
    stop_monitor_mode(get_first_wifi_card())


if __name__ == "__main__":
	atexit.register(exit_handler)
	print("================================")
	print(sys.argv)
	print("================================")
	main()
