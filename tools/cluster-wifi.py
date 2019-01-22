#!/usr/bin/python3

"""
sudo ./cluster-wifi.py -g "wifi-1-rtls"

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

### installation :
## apt update
## apt install screen
print("##################################################\n"*2)
print("NOTE: check remote commands executions(like screen and airodump-ng)")
print("NOTE: delete every wifi ap credential to avoid rp to connect to them")
print("##################################################\n")
## apt install aircrack-ng

## Note: If wlan interface name length exceeds from about 10 char, its monitor interface name will not be in <interfaceName>mon

ssh_command = "ssh -o ConnectTimeout=1 %(username)s@%(address)s "


class CommandThread(threading.Thread):
	def __init__(self, configs, command, first):
		threading.Thread.__init__(self)
		self.isFirst = first
		self.config = configs
		self.command = command

	def run(self):
		if self.command == "status":
			print(self.is_scan_running(Allscan=True)[1])
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
			self.reboot_node()
		elif self.command == "shutdown":
			self.shutdown_node()
		else:
			if self.isFirst:
				print_help()

	def is_scan_running(self,Allscan=False):

		#Note: check each command(scan-wifi.py\&tshark\&airodump) seperetedly
		works = ["python","tshark","airodump"]
		c = ssh_command +""" "ps aux | grep '"""+"\|".join(works) +"""' | grep -v 'grep\|vim'" """

			
		print(c % {'username': self.config['user'], 'address': self.config['address']})
		res, code = run_command(c % {'username': self.config['user'], 'address': self.config['address']})
		is_running = False
		
		if code == 255 or res.find("Connection timed out")!=-1 :
			print("unable to connect to " + self.config['address'])
		else:
			if len(res.strip()) != 0:
				if Allscan:
					is_running = True
					for w in works:
						if w not in res:
							is_running = False
							break
				else:
					is_running = True

		return is_running, self.config['note'] + (":\tScan is running" if is_running else ":\tScan is NOT running")

	def shutdown_node(self):
		c = ssh_command + '"sudo init 0"'
		r, code = run_command(c % {'username': self.config['user'], 'address': self.config['address']})

	def reboot_node(self):
		c = ssh_command + '"sudo init 6"'
		r, code = run_command(c % {'username': self.config['user'], 'address': self.config['address']})

	def start_scan(self):
		if self.is_scan_running()[0]:
			print(self.config['note'] + ":\tAlready running")
			return

		c = ssh_command + '"sudo monstart && /sbin/ifdown --force %(interface)s "'
		r, code = run_command(c % {'username': self.config['user'],
                                   'address': self.config['address'],
                                   'interface': self.config['interface'],})
		if code == 255:
			return

		c1 = ssh_command + '"sudo screen -d -m airodump-ng %(interface)smon & "'

		print(c1% {'username': self.config['user'],
				   'address': self.config['address'],
				   'interface': self.config['interface']
				   })

		r, code = run_command(c1% {'username': self.config['user'],
						 'address': self.config['address'],
						 'interface': self.config['interface'],
						 'group': self.config['group'],
						 'server': self.config['rtls_server'],
						 'scan_time': self.config['scan_time'],
						 })

		if code == 255:
			return

		wait_sync_time = 0
		try:
			wait_sync_time = float(self.config['wait_sync_time'])
		except Exception as e: 
			print(e)
		startProcesingScanTime = float(time.time()) + wait_sync_time

		print(wait_sync_time)
		print(startProcesingScanTime)
		c2 = ssh_command + '"sudo nohup python3 ~/rtls/scan-wifi.py --interface %(interface)smon --time %(scan_time)d --starttime '+str(startProcesingScanTime)+' --group %(group)s --server %(server)s > ' + \
		    ('~/rtls/result-' + str(int(time.time())) + '_wifi.out' if self.config['verbose'] else '/dev/null') + ' &"'

		print(c2 % {'username': self.config['user'],
									'address': self.config['address'],
									'interface': self.config['interface'],
									'group': self.config['group'],
									'server': self.config['rtls_server'],
									'scan_time': self.config['scan_time'],
									})
		r, code = run_command(c2 % {'username': self.config['user'],
									'address': self.config['address'],
									'interface': self.config['interface'],
									'group': self.config['group'],
									'server': self.config['rtls_server'],
									'scan_time': self.config['scan_time'],
									})
		
		print(r)
		
		if code == 255:
			return
		if self.is_scan_running()[0]:
			print(self.config['note'] + ":\tScan Started for '", self.config['group'], "' using", self.config['rtls_server'], "on verbose mode" if self.config['verbose'] else "")
		else:
			print(r)
			print(self.config['note'] + ":\tUnable To Start Scan")

	def stop_scan(self):
		is_running, msg = self.is_scan_running()
		if is_running:
			c = ssh_command + '"sudo pkill -9 python3 && sudo pkill -9 tshark && sudo pkill -9 dumpcap && sudo kill \`cat /run/hostapd.pid\` && sudo pkill screen"'
			r, code = run_command(c % {'username': self.config['user'],
			                           'address': self.config['address'],
			                           'interface': self.config['interface']
			                           })
			c = ssh_command + '"sudo pkill airodump-ng && sudo monstop"'
			r, code = run_command(c % {'username': self.config['user'],
			                           'address': self.config['address']
			                           })
			print(r, ' ', c)
			if self.is_scan_running()[0]:
				# print(r)
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
		c = ssh_command + '"mkdir -p ~/rtls/" && scp %(file)s %(username)s@%(address)s:~/rtls/'
		r, code = run_command(c % {'address': self.config['address'],'username': self.config['user'], 'file': os.path.dirname(os.path.abspath(__file__)) + '/../node/scan-wifi.py'})

		if code == 255:
			return
		elif code == 0:
			print(self.config['note'] + ":\tScanner Updated, You can restart scan!")
		else:
			print(r)
			print(self.config['note'] + ":\tAn error occurred")

	def clean_logs(self):
		c = ssh_command + '"rm -f ~/rtls/*.out"'
		r, code = run_command(c % {'username': self.config['user'], 'address': self.config['address'], })
		if code == 255:
			return
		elif code == 0:
			print(self.config['note'] + ":\tAll .out file deleted")
		else:
			print(r)
			print(self.config['note'] + ":\tAn error occurred")


def run_command(command):
	# print("\n====================\n\t\tRUNNING:\n", command, "\n")
	p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)  # , universal_newlines=True,
	text = p.stdout.read().decode('utf-8')
	retcode = p.wait()
	# print("\n\t\tRESUALT:", retcode, text, "\n====================\n")
	return text, retcode


def print_help():
	print("""
cluster-wifi.py COMMAND OPTIONS

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
		uploads the latest version of scan-wifi.py to all Nodes

	clean [-c CONFIG]
		delete all .out files in rtls directory on Nodes

	reboot [-c CONFIG]
		reboots all Nodes in cluster

	shutdown [-c CONFIG]
		shutdown all Nodes in cluster

	track [-g GROUP] [-c CONFIG]
		communicate with RTLS server to tell it to track for group GROUP

	learn -l LOCATION [-u USER] [-n NUMBER] [-g GROUP] [-c CONFIG] [-b]
		communicate with RTLS server to tell it to perform learning
		in the specified location for the user and group.

	configure [-c CONFIG]
		creates a configuration file interactively

Options:

	-h, --help
		show this help message and exit

	-c, --config	default: ./config-wifi.json
		location to configuration file

	-l, --location
		location to use, for learning

	-v, --verbose
		save script output to result-TIMESTAMP.out

	-u, --user
		user to use for learning,
		can be specified in configuration file

	-n, --number
		number of fingerprints for send to server at learning,
		can be specified in configuration file

	-b --bulk
		use Find server's bulk learn mode or not

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
		path = input('Choose a name for your configuration File (default: config-wif.json): ')
		if len(path) == 0:
			path = 'config-wifi.json'

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

		user = input('Enter username of the Node (for ssh login - default: root): ')
		if len(user) == 0:
			user = 'root'

		interface = input('Interface to use (default: wlan0): ')
		if len(interface) == 0:
			interface = "wlan0"

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
	
	print("\n\n")

	config['wait_sync_time'] = input('Enter times that atmost each node must wait and then start processing scans(in sec) (default: 5): ')
	if len(config['wait_sync_time']) == 0:
		config['wait_sync_time'] = 5
	try:
		config['wait_sync_time'] = float(config['wait_sync_time'])
	except:
		config['wait_sync_time'] = 5

	print("\n\n")

	config['bulk_mode'] = input("Use server's Bulk Mode for learning (default: Yes) [y/n]: ")
	if len(config['bulk_mode']) == 0 or config['bulk_mode'] in 'yY':
		config['bulk_mode'] = True
	else:
		config['bulk_mode'] = False

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
		default="config-wifi.json",
		help="location to configuration file (default: ./config-wifi.json)")
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
		help="number of fingerprints for send to server at learning")
	parser.add_argument(
		"-wst",
		"--waitSyncTime",
		type=int,
		help="times that atmost each node must wait and then start processing scans(in sec)")
	parser.add_argument(
		"-b",
		"--bulk",
		action='store_true',
		help="Use bulk mode or not (default: don't use)")
	parser.add_argument(
		"-v",
		"--verbose",
		action='store_true',
		help="save script output to result-TIMESTAMP.out")
	parser.add_argument("command", type=str, nargs="?", default="", help="start stop restart status track learn update reboot shutdown configure")
	args = parser.parse_args()

	command = args.command.strip().lower()

	if command == "" or args.help:
		print_help()
		sys.exit(2)

	if not os.path.exists(args.config):
		generate_config(args.config)

	config = {}
	config = json.load(open(args.config, 'r'))
	try:
		if args.group != "":
			config['group'] = args.group

		if args.user != "" and args.user != config['user']:
			config['user'] = args.user

		if args.number != None and args.number != config['learn_count']:
			config['learn_count'] = args.number

		if args.waitSyncTime != None and args.waitSyncTime != config['wait_sync_time']:
			config['wait_sync_time'] = args.waitSyncTime
		

		if 'bulk_mode' not in config:
			config['bulk_mode'] = args.bulk

		config['location'] = args.location
	except:
		print("Error validating Configurations!")
		sys.exit(2)

	if command == "configure":
		generate_config(None)
		sys.exit(0)

	elif command == "track":
		if config['group'] == "":
			print("Must include group! Use ./cluster-wifi.py -g GROUP track")
			sys.exit(2)

		response = getURL(config['rtls_server'] + "/switch", {'group': config['group']})
		print(response)
		sys.exit(0)

	elif command == "learn":
		if config['user'] == "" or config['location'] == "" or config['group'] == "":
			print("Must include name and location and group! Use ./cluster-wifi.py -u USER -l LOCATION learn -g GROUP ")
			sys.exit(2)

		config['user'] = config['user'].replace(':', '').strip()
		response = getURL(config['rtls_server'] + "/switch", {'group': config['group'], 'user': config['user'], 'loc': config['location'], "count": config['learn_count'], "bulk": config['bulk_mode']})
		print(response)
		sys.exit(0)

	threads = []
	temp = {}
	for node in config['nodes']:
		node['group'] = config['group']
		node['rtls_server'] = config['rtls_server']
		node['scan_time'] = config['scan_time']
		node['wait_sync_time'] = config['wait_sync_time']
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
