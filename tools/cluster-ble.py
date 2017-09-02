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
import urllib.parse as urlparse
from urllib.parse import urlencode

ssh_command = "ssh -o ConnectTimeout=10 pi@%(address)s "


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
		elif self.command == "reboot":
			self.reboot_pi()
		elif self.command == "shutdown":
			self.shutdown_pi()
		else:
			if self.isFirst:
				print_help()

	def is_scan_running(self):
		c = ssh_command + '"ps aux"'
		res, code = run_command(c % {'address': self.config['address']})
		is_running = 'btmon' in res and 'scan-ble.py' in res
		return is_running, self.config['note'] + ":\tScan is running" if is_running else self.config['note'] + ":\tScan is NOT running"

	def shutdown_pi(self):
		c = ssh_command + '"sudo init 0"'
		r, code = run_command(c % {'address': self.config['address']})

	def reboot_pi(self):
		c = ssh_command + '"sudo init 6"'
		r, code = run_command(c % {'address': self.config['address']})

	def start_scan(self):
		if self.is_scan_running()[0]:
			print(self.config['note'] + ":\tAlready running")
			return
		c = ssh_command + '"sudo hcitool -i %(interface)s lescan --duplicates > /dev/null | sudo btmon |/home/pi/rtls/scan-ble.py --group %(group)s --server %(server)s --time %(scantime)s > /dev/null &"'
		r, code = run_command(c % {'address': self.config['address'],
		                           'interface': self.config['interface'],
		                           'group': self.config['group'],
		                           'server': self.config['lfserver'],
		                           'scantime': self.config['scantime']
		                           })
		if code == 255:
			return
		if self.is_scan_running()[0]:
			print(self.config['note'] + ":\tScan Started!")
		else:
			print(self.config['note'] + ":\tUnable To Start Scan")

	def stop_scan(self):
		is_running, msg = self.is_scan_running()
		if is_running:
			c = ssh_command + '"sudo pkill -9 hcitool && sudo hciconfig hci0 down && sudo hciconfig hci0 up && sudo pkill -9 btmon && sudo pkill -9 scan-ble.py"'
			r, code = run_command(c % {'address': self.config['address']})
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
		r, code = run_command(c % {'address': self.config['address'],
		                           'file': os.path.dirname(os.path.abspath(__file__)) + '../node/scan-ble.py'})


def is_scan_running():
	ps_output = subprocess.Popen(["ps", "aux"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	ps_stdout = ps_output.stdout.read().decode('utf-8')
	isRunning = 'hcitool' in ps_stdout or 'btmon' in ps_stdout
	return isRunning


def run_command(command):
	print("\n====================\n\t\tRUNNING:\n", command, "\n")
	p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	# p = subprocess.Popen(command, universal_newlines=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	text = p.stdout.read().decode('utf-8')
	retcode = p.wait()
	print("\n\t\tRESUALT:", retcode, "\n====================\n")
	return text, retcode


def print_help():
	print("""
	cluster-ble.py COMMAND

		status:
			get the current status of all Raspberry Pis in the cluster
		stop :
			stops scanning in all Raspberry Pis in the cluster
		start:
			starts scanning in all Raspberry Pis in the cluster
		restart:
			stops and starts all Raspberry Pis in the cluster
		update :
			uploads the latest version of scan-ble.py to Raspberry Pis
		track -g GROUP:
			communicate with find-lf server to tell it to track
			for group GROUP
		learn -u USER -g GROUP -l LOCATION:
			communicate with find-lf server to
			tell it to perform learning in the specified location for user/group.


	""")


def start_scan(hci, group, server):
	if not is_scan_running():
		# ['sudo', '/usr/bin/hcitool', '-i', hci, 'lescan', '--duplicates', '>', '/dev/null', '|', 'sudo', '/usr/bin/btmon', '|', './scan-ble.py', '--group', group, '--server', server, '&']
		# sudo /usr/bin/hcitool -i hci0 lescan --duplicates > /dev/null | sudo /usr/bin/btmon | ./scan-ble.py --group ble-1-rtls --server https://lf.internalpositioning.com &
		ps_output = subprocess.Popen(
			['sudo', '/usr/bin/hcitool', '-i', hci, 'lescan', '--duplicates', '>', '/dev/null', '|', 'sudo', '/usr/bin/btmon', '|', './scan-ble.py', '--group', group, '--server', server, '&'],
			stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		if is_scan_running():
			print("Scan started")
		else:
			print("\n=========\tERROR\t=========\n")
			print(ps_output.stderr.read().decode('utf-8'))

			print("\n\t===\tERROR\t===\n")
			print(ps_output.stdout.read().decode('utf-8'))

			print("Unable to start scan")
	else:
		print("Scan is running")


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


def main(args, config):
	command = args.command.strip()
	print("", command)

	if command == "track":
		response = getURL(config['lfserver'] + "/switch", {'group': config['group']})
		print(response)
		return

	elif command == "learn":
		if config['user'] == "" or config['location'] == "":
			print("Must include name and location! Use ./cluster-ble.py -u USER -l LOCATION learn")
			return
		config['user'] = config['user'].replace(':', '').strip()
		response = getURL(config['lfserver'] + "/switch", {'group': config['group'], 'user': config['user'], 'loc': config['location']})
		print(response)
		return

	threads = []
	temp = {}
	for pi in config['pis']:
		pi['group'] = config['group']
		pi['lfserver'] = config['lfserver']
		pi['scantime'] = config['scantime']
		threads.append(CommandThread(pi.copy(), command, len(threads) == 0))

	# Start new Threads
	for thread in threads:
		thread.start()
	for thread in threads:
		try:
			thread.join()
		except:
			pass


def exit_handler():
	print("Exiting...")


if __name__ == "__main__":
	atexit.register(exit_handler)
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"-c",
		"--config",
		type=str,
		default="config-ble.json",
		help="location to configuration file")
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
		help="user to use, for learning")
	parser.add_argument(
		"-g",
		"--group",
		type=str,
		default="",
		help="group to use")
	parser.add_argument("command", type=str, default="", help="start stop restart status track learn update reboot shutdown")
	args = parser.parse_args()

	config = {}
	if not os.path.exists(args.config):
		pis = []
		while True:
			pi = input('Enter Raspberry Pi address (e.g. 192.168.0.2 Enter blank if no more): ')
			if len(pi) == 0:
				break
			note = input('Enter a note for the Raspberry Pi (for you to remember): ')
			wlan = input('Interface to use (default: hci0): ')
			if len(wlan) == 0:
				wlan = "hci0"
			pis.append({"address": pi.strip(), "note": note.strip(), "interface": wlan.strip()})
		if len(pis) == 0:
			print("Must include at least one computer!")
			sys.exit(-1)
		config['pis'] = pis
		config['lfserver'] = input(
			'Enter lf address (default: lf.internalpositioning.com): ')
		if len(config['lfserver']) == 0:
			config['lfserver'] = 'https://lf.internalpositioning.com'
		if 'http' not in config['lfserver']:
			config['lfserver'] = "http://" + config['lfserver']
		config['group'] = input('Enter a group: ')
		if len(config['group']) == 0:
			config['group'] = 'default'
		config['scantime'] = input('Enter a scanning time (default 1 seconds): ')
		if len(config['scantime']) == 0:
			config['scantime'] = 1
		try:
			config['scantime'] = int(config['scantime'])
		except:
			config['scantime'] = 1

		with open(args.config, 'w') as f:
			f.write(json.dumps(config, indent=4))

	config = json.load(open(args.config, 'r'))
	if args.group != "":
		config['group'] = args.group
		with open(args.config, 'w') as f:
			f.write(json.dumps(config, indent=4))

	config['user'] = args.user
	config['location'] = args.location

	main(args, config)
