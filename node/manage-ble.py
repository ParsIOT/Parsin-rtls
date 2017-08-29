#!/usr/bin/python3

"""
lescan [--privacy] [--passive] [--whitelist] [--discovery=g|l] [--duplicates]
				Start LE scan
	Usage:
		lescan [--privacy] enable privacy
		lescan [--passive] set scan type passive (default active)
		lescan [--whitelist] scan for address in the whitelist only
		lescan [--discovery=g|l] enable general or limited discoveryprocedure
		lescan [--duplicates] don't filter duplicates

"""
import argparse
import atexit
import os
import requests
import socket
import statistics
import subprocess
import sys
import time


def is_scan_running():
	ps_output = subprocess.Popen("ps aux".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	ps_stdout = ps_output.stdout.read().decode('utf-8')
	isRunning = 'hcitool' in ps_stdout or 'btmon' in ps_stdout
	return isRunning


def start_scan(hci):
	if not is_scan_running():
		subprocess.Popen(("sudo hcitool -i " + hci + " lescan --duplicates > /dev/null | sudo btmon | ./scan.py &").split(),
		                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		if is_scan_running():
			print("Scan started")
		else:
			print("Unable to start scan")
	else:
		print("Scan is running")


def main():
	# Check if SUDO
	# http://serverfault.com/questions/16767/check-admin-rights-inside-python-script
	if os.getuid() != 0:
		print("you must run sudo!")
		return

	# Parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("-g", "--group", default="", help="group name")
	parser.add_argument(
		"-i",
		"--interface",
		default='hci0',
		help="Interface to listen on - default hci0")
	parser.add_argument(
		"-t",
		"--time",
		default=10,
		help="scanning time in seconds (default 10)")
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

	# Startup scanning
	print("Using server " + args.server)
	print("Using group " + args.group)

	while True:
		print("\n\n\t======\tWHILE\t======\t\n\n")

		start_scan(args.interface)


def exit_handler():
	print("Exiting...stopping scan..")
	os.system("pkill -9 tshark")


if __name__ == "__main__":
	atexit.register(exit_handler)
	print("================================")
	print(sys.argv)
	print("================================")
	main()
