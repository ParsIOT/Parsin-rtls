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

sudo ./cluster-ble.py -g "ble-1-rtls"

"""
import argparse
import atexit
import json
import os
import requests
import subprocess
import sys
import threading
import time
import urllib.parse as urlparse
from urllib.parse import urlencode

ssh_command = "ssh -o ConnectTimeout=1 %(username)s@%(address)s "


class CommandThread(threading.Thread):
	def __init__(self, configs, command, first):
		threading.Thread.__init__(self)
		self.isFirst = first
		self.config = configs
		self.command = command
		self.output = ""

	def run(self):
		if self.command == "status":
			foo, self.output = self.is_scan_running()
			print(self.output)
		elif self.command == "start":
			self.start_scan()
		elif self.command == "stop":
			self.stop_scan()
		elif self.command == "restart":
			self.restart_scan()
		elif self.command == "update":
			self.update_scanner()
		elif self.command == "clean":
			self.clean_logs()
		elif self.command == "reboot":
			self.reboot_pi()
		elif self.command == "shutdown":
			self.shutdown_pi()
		else:
			if self.isFirst:
				print_help()

	def is_scan_running(self):
		c = ssh_command + '"ps aux"'
		res, code = run_command(c % {'username': self.config['user'], 'address': self.config['address']})
		is_running = 'btmon' in res and 'scan-ble.py' in res
		return is_running, self.config['note'] + ":\tScan is running" if is_running else self.config['note'] + ":\tScan is NOT running"

	def shutdown_pi(self):
		c = ssh_command + '"sudo init 0"'
		r, code = run_command(c % {'username': self.config['user'], 'address': self.config['address']})

	def reboot_pi(self):
		c = ssh_command + '"sudo init 6"'
		r, code = run_command(c % {'username': self.config['user'], 'address': self.config['address']})

	def start_scan(self):
		if self.is_scan_running()[0]:
			print(self.config['note'] + ":\tAlready running")
			return
		c = ssh_command + '"sudo hcitool -i %(interface)s lescan --duplicates > /dev/null | sudo btmon |/home/%(username)s/rtls/scan-ble.py --group %(group)s --server %(server)s --time %(scan_time)s > ' + \
		    ('/home/%(username)s/rtls/result-' + str(int(time.time())) + '.out' if self.config['verbose'] else '/dev/null') + ' &"'
		r, code = run_command(c % {'username': self.config['user'],
		                           'address': self.config['address'],
		                           'interface': self.config['interface'],
		                           'group': self.config['group'],
		                           'server': self.config['rtls_server'],
		                           'scan_time': self.config['scan_time'],
		                           })
		if code == 255:
			return
		if self.is_scan_running()[0]:
			print(self.config['note'] + ":\tScan Started for '", self.config['group'], "' using", self.config['rtls_server'], "on verbose mode" if self.config['verbose'] else "")
		else:
			print(self.config['note'] + ":\tUnable To Start Scan")

	def stop_scan(self):
		is_running, msg = self.is_scan_running()
		if is_running:
			c = ssh_command + '"sudo pkill -9 hcitool && sudo hciconfig hci0 down && sudo hciconfig hci0 up && sudo pkill -9 btmon && sudo pkill -9 scan-ble.py"'
			r, code = run_command(c % {'username': self.config['user'], 'address': self.config['address']})
			if self.is_scan_running()[0]:
				print(self.config['note'] + ":\tCould Not Stop Scan!")
				return False
			else:
				print(self.config['note'] + ":\tStopped!")
				return True
		else:
			print(msg)
			return True

	def restart_scan(self):
		if self.stop_scan():
			self.start_scan()

	def update_scanner(self):
		c = 'scp %(file)s pi@%(address)s:/home/pi/rtls/'
		r, code = run_command(c % {'address': self.config['address'], 'file': os.path.dirname(os.path.abspath(__file__)) + '/../node/scan-ble.py'})

		if code == 255:
			return
		else:
			print(self.config['note'] + ":\tScanner Updated, You can restart scan!")

	def clean_logs(self):
		c = ssh_command + '"rm -f /home/pi/rtls/*.out"'
		r, code = run_command(c % {'username': self.config['user'], 'address': self.config['address'], })
		if code == 255:
			return
		else:
			print(self.config['note'] + ":\tAll .out file deleted")


def run_command(command):
	# print("\n====================\n\t\tRUNNING:\n", command, "\n")
	p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	# p = subprocess.Popen(command, universal_newlines=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	text = p.stdout.read().decode('utf-8')
	retcode = p.wait()
	# print("\n\t\tRESUALT:", retcode, text, "\n====================\n")
	return text, retcode


def print_help():
	print("""
cluster-ble.py COMMAND OPTIONS

Commands:

	status [-c CONFIG]
		get the current status of all Nodes in the cluster

	stop [-c CONFIG]
		stops scanning in all Nodes in the cluster

	start [-g GROUP] [-c CONFIG] [-v]
		starts scanning in all Nodes in the cluster for group GROUP

	restart [-g GROUP] [-c CONFIG] [-v]
		stops scan and starts scanning on all Nodes in the cluster for group GROUP

	update [-c CONFIG]
		uploads the latest version of scan-ble.py to all Nodes

	clean [-c CONFIG]
		delete all .out files in rtls directory on Nodes

	reboot [-c CONFIG]
		reboots all Nodes in cluster

	shutdown [-c CONFIG]
		shutdown all Nodes in cluster

	track [-g GROUP] [-c CONFIG]
		communicate with RTLS server to tell it to track for group GROUP

	learn -l LOCATION [-u USER] [-n NUMBER] [-g GROUP] [-c CONFIG]
		communicate with RTLS server to tell it to perform learning
		in the specified location for the user and group.

	configure [-c CONFIG]
		creates a configuration file interactively

Options:

	-h, --help
		show this help message and exit

	-c, --config	default: ./config-ble.json
		location to configuration file

	-l, --location
		location to use, for learning

	-v, --verbose
		save script output to result-TIMESTAMP.out

	-u, --user
		user to use for learning,
		can be specified in configuration file

	-n, --number	default: 500
		number of fingerprints for send to server at learning,
		can be specified in configuration file

	-g, --group
		group name,
		can be specified in configuration file

""")


def getURL(url, params):
	url_parts = list(urlparse.urlparse(url))
	query = dict(urlparse.parse_qsl(url_parts[4]))
	query.update(params)
	url_parts[4] = urlencode(query)
	try:
		getURL = urlparse.urlunparse(url_parts)
		r = requests.get(getURL, timeout=3)
		return r.text
	except:
		e = sys.exc_info()[0]
		return "Problem requesting"


def generate_config(path):
	if path is None:
		path = input('Choose a name for your configuration File (default: config-ble.json): ')
		if len(path) == 0:
			path = 'config-ble.json'

	if os.path.exists(path):
		print("This file already exist!")
		confirm = input('Are you sure to over write it? [y/n]: ')
		if str(confirm) not in "yY":
			print("Configuration aborted!")
			return

	config = {}
	# get configs from user
	nodes = []

	while True:
		node = input('\nEnter Node address (e.g. 192.168.0.2 Enter blank if no more): ')
		if len(node) == 0:
			break

		note = input('Enter a note for the Node (for you to remember): ')

		user = input('Enter username of the Node (for ssh login - default: pi): ')
		if len(user) == 0:
			user = 'pi'

		interface = input('Interface to use (default: hci0): ')
		if len(interface) == 0:
			interface = "hci0"

		nodes.append({"address": node.strip(), "user": user.strip(), "note": note.strip(), "interface": interface.strip()})

	if len(nodes) == 0:
		print("Must include at least one computer!")
		sys.exit(-1)
	config['nodes'] = nodes

	print("\n\n")

	config['rtls_server'] = input('Enter RTLS Server address (default: lf.internalpositioning.com:443): ')
	if len(config['rtls_server']) == 0:
		config['rtls_server'] = 'https://lf.internalpositioning.com'
	if 'http' not in config['rtls_server']:
		config['rtls_server'] = "http://" + config['rtls_server']

	print("\n\n")

	config['group'] = input('Enter a group (default: RTLS_1): ')
	if len(config['group']) == 0:
		config['group'] = 'RTLS_1'

	print("\n\n")

	config['user'] = input('Enter a user for learning: ')
	if len(config['user']) == 0:
		config['user'] = ''

	print("\n\n")

	config['scan_time'] = input('Enter a scanning time (default 1 second): ')
	if len(config['scan_time']) == 0:
		config['scan_time'] = 1
	try:
		config['scan_time'] = float(config['scan_time'])
	except:
		config['scan_time'] = 1

	print("\n\n")

	config['learn_count'] = input('Enter number of fingerprints to collect for learning (default: 500): ')
	if len(config['learn_count']) == 0:
		config['learn_count'] = 500
	try:
		config['learn_count'] = int(config['learn_count'])
	except:
		config['learn_count'] = 500

	with open(path, 'w') as f:
		f.write(json.dumps(config, indent=4))


if __name__ == "__main__":
	parser = argparse.ArgumentParser(add_help=False)
	parser.add_argument(
		"-h",
		"--help",
		action="count",
		help="Show this help message and exit.")
	parser.add_argument(
		"-c",
		"--config",
		type=str,
		default="config-ble.json",
		help="location to configuration file (default: ./config-ble.json)")
	parser.add_argument(
		"-l",
		"--location",
		type=str,
		default="",
		help="location to use, for learning")
	parser.add_argument(
		"-u",
		"--user",
		type=str,
		default="",
		help="user to use for learning")
	parser.add_argument(
		"-g",
		"--group",
		type=str,
		default="",
		help="group to use")
	parser.add_argument(
		"-n",
		"--number",
		type=int,
		default=500,
		help="number of fingerprints for send to server at learning (default: 500)")
	parser.add_argument(
		"-v",
		"--verbose",
		action='store_true',
		help="save script output to result-TIMESTAMP.out")
	parser.add_argument("command", type=str, nargs="?", default="", help="start stop restart status track learn update reboot shutdown configure")
	args = parser.parse_args()

	if not os.path.exists(args.config):
		generate_config(args.config)

	config = {}
	config = json.load(open(args.config, 'r'))
	if args.group != "":
		config['group'] = args.group

	if args.user != "" and args.user != config['user']:
		config['user'] = args.user

	if args.number != "" and args.number != config['learn_count']:
		config['learn_count'] = args.number

	config['location'] = args.location

	command = args.command.strip().lower()

	if command == "" or args.help:
		print_help()
		sys.exit(2)

	elif command == "configure":
		generate_config(None)
		sys.exit(0)

	elif command == "track":
		if config['group'] == "":
			print("Must include group! Use ./cluster-ble.py -g GROUP track")
			sys.exit(2)

		response = getURL(config['rtls_server'] + "/switch", {'group': config['group']})
		print(response)
		sys.exit(0)

	elif command == "learn":
		if config['user'] == "" or config['location'] == "" or config['group'] == "":
			print("Must include name and location and group! Use ./cluster-ble.py -u USER -l LOCATION learn -g GROUP ")
			sys.exit(2)

		config['user'] = config['user'].replace(':', '').strip()
		response = getURL(config['rtls_server'] + "/switch", {'group': config['group'], 'user': config['user'], 'loc': config['location'], "count": config['learn_countv']})
		print(response)
		sys.exit(0)

	threads = []
	temp = {}
	for node in config['nodes']:
		node['group'] = config['group']
		node['rtls_server'] = config['rtls_server']
		node['scan_time'] = config['scan_time']
		node['verbose'] = args.verbose
		threads.append(CommandThread(node.copy(), command, len(threads) == 0))

	# Start new Threads
	for thread in threads:
		thread.start()
	for thread in threads:
		try:
			thread.join()
		except:
			pass
