from __future__ import annotations

import hashlib
import inspect
import json
import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import threading as th
import time
import traceback
import platform
from argparse import ArgumentParser, Namespace
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable

try:
	from PIL import Image
	sc4mp_has_pil = True
except ImportError:
	sc4mp_has_pil = False

try:
	import pystray
	sc4mp_has_pystray = True
except ImportError:
	sc4mp_has_pystray = False

from core.config import Config
from core.dbpf import SC4Savegame
from core.networking import ClientSocket, ServerSocket, BaseRequestHandler, \
	NetworkException, ConnectionClosedException
from core.util import *


# Globals

SC4MP_VERSION = "0.9.0"

SC4MP_SERVERS = get_server_list()

SC4MP_GITHUB_REPO = "kegsmr/sc4mp-server"

SC4MP_URL = "www.sc4mp.org"
SC4MP_CONTRIBUTORS_URL = f"https://github.com/{SC4MP_GITHUB_REPO}/contributors/"
SC4MP_ISSUES_URL = f"https://github.com/{SC4MP_GITHUB_REPO}/issues/"
SC4MP_RELEASES_URL = f"https://github.com/{SC4MP_GITHUB_REPO}/releases/"

SC4MP_AUTHOR_NAME = "SimCity 4 Multiplayer Project"
SC4MP_WEBSITE_NAME = "www.sc4mp.org"
SC4MP_LICENSE_NAME = "MIT-0"

SC4MP_CONFIG_PATH = None
SC4MP_LOG_PATH = "sc4mpserver.log" #-" + datetime.now().strftime("%Y%m%d%H%M%S") + ".log"
SC4MP_README_PATH = "readme.html"
SC4MP_RESOURCES_PATH = "resources"

SC4MP_TITLE = format_title("SC4MP Server", version=SC4MP_VERSION)
SC4MP_ICON = os.path.join(SC4MP_RESOURCES_PATH, "icon.ico")

SC4MP_HOST = None
SC4MP_PORT = None

SC4MP_BUFFER_SIZE = 4096

SC4MP_DELAY = .1

SC4MP_CONFIG_DEFAULTS = [
	("NETWORK", [
		("host", "0.0.0.0"),
		("port", 7240),
		# ("upnp", False),	#TODO
		# ("domain", None),	#TODO for servers hosted on a DDNS or other specific domain
		("discoverable", True),
		("domain", '')
	]),
	("INFO", [
		("server_id", generate_server_id()),
		("server_name", generate_server_name()),
		("server_description", "Join and build your city.\n\nRules:\n- Feed the llamas\n- Balance your budget\n- Do uncle Vinny some favors"),
		("server_url", SC4MP_URL),
	]),
	("SECURITY", [
		("private", False),
		("password_enabled", False),
		("password", "maxis2003"),
		("max_ip_users", 3),
	]),
	("RULES", [
		("claim_duration", 30),
		#("abandoned_reset_delay", None) 	#TODO for resetting old abandoned saves
		#("claim_timeout", None), 			#TODO prevent users from making another claim within this time
		("max_region_claims", 1),
		#("max_total_claims", None), 		#TODO max claims accross entire server
		("godmode_filter", True),
		("user_plugins", False),
	]),
	("PERFORMANCE", [
		("request_limit", 60),
		("max_request_threads", 200),
		("connection_timeout", 600),
		("filetable_update_interval", 600),
	]),
	("BACKUPS", [
		("server_backup_interval", 6),
		("backup_server_on_startup", True),
		("max_server_backup_days", 30),
		("max_savegame_backups", 20),
	])
]

if is_windows() and is_frozen():
	SC4MP_CONFIG_DEFAULTS += [
		("UI", [
			("enabled", True)
		])
	]

SC4MP_SERVER_ID = None
SC4MP_SERVER_NAME = None
SC4MP_SERVER_DESCRIPTION = None

SC4MP_INVITES_DOMAIN = "invite.sc4mp.org"

sc4mp_server_path = "_SC4MP"

sc4mp_server_running = False

sc4mp_request_threads = 0


# Functions

def main():
	"""The main function."""

	try:

		# Set working directory
		exec_path = Path(sys.executable)
		exec_file = exec_path.name
		exec_dir = exec_path.parent
		if exec_file == "sc4mpserver.exe":
			os.chdir(exec_dir)

		# Parse arguments
		args = parse_args()

		# -k / --skip-update argument
		global sc4mp_skip_update
		if args.skip_update is True:
			sc4mp_skip_update = True
		else:
			sc4mp_skip_update = False

		# -u / --force-update argument
		global sc4mp_force_update
		if args.force_update is True:
			sc4mp_force_update = True
		else:
			sc4mp_force_update = False

		# -s / --server-path argument
		global sc4mp_server_path
		if args.server_path:
			if not sc4mp_force_update:
				sc4mp_skip_update = True
			sc4mp_server_path = args.server_path
			os.makedirs(sc4mp_server_path, exist_ok=True)

		# -r / --restore argument
		if args.restore:
			restore(args.restore)
			return

		# -p / --prep argument
		global sc4mp_nostart
		if args.prep is True:
			sc4mp_nostart = True
		else:
			sc4mp_nostart = False

		# -v / --verbose argument
		if args.verbose:
			# TODO: use this flag to set logger level to debug once the logger PR is merged
			pass

		# If there's another server running from the same directory, kill it
		prevent_multiple()

		# Exit if --stop argument is provided
		if args.stop:
			return

		# Output
		sys.stdout = Logger()
		set_thread_name("Main", enumerate=False)

		# Title
		report(SC4MP_TITLE)

		# Server
		global sc4mp_server
		sc4mp_server = Server()
		if not sc4mp_nostart:
			sc4mp_server.run()

	except Exception as e:

		fatal_error(e)


def parse_args() -> Namespace:
	"""Parse command line arguments"""

	parser = ArgumentParser(prog="SC4MP Server",
						 description="SimCity 4 Multiplayer Server")

	parser.add_argument("-s", "--server-path", help="specify server directory relative path")

	parser.add_argument("-t", "--stop", help="terminate the server currectly running from the specified server path (Windows-only)", action="store_true")

	parser.add_argument("-k", "--skip-update", help="skip the update check at startup", action="store_true")

	parser.add_argument("-u", "--force-update", help="force update at startup (Windows-only)", action="store_true")

	parser.add_argument("-r", "--restore", help="restore the server to the specified backup")

	parser.add_argument("-v", "--verbose",
					 help="increase stdout/log verbosity",
					 action="store_true")

	parser.add_argument("-p", "--prep",
					 help="prep the server, but do not start",
					 action="store_true")

	parser.add_argument("--version", action="version",
                    version=f"{parser.prog} {SC4MP_VERSION}")

	return parser.parse_args()


def prevent_multiple():

	if is_windows() and is_frozen():

		try:

			DATETIME_FORMAT = "%Y%m%d%H%M%S"

			process_info_path = os.path.join(sc4mp_server_path, "process.json")

			if os.path.exists(process_info_path):

				process_info = load_json(process_info_path)

				if "pid" in process_info.keys() and "creation" in process_info.keys():

					other_process_pid = process_info["pid"]
					other_process_creation = process_info["creation"]

					try:
						o_p_c = datetime.strftime(get_process_creation_time(other_process_pid), DATETIME_FORMAT)
					except Exception:
						o_p_c = None

					if other_process_creation == o_p_c:
						if subprocess.call(f"TASKKILL /F /PID {other_process_pid}", shell=True) != 0:
							raise ServerException("`TASKKILL` did not return exit code 0.")

			this_process_pid = os.getpid()
			this_process_creation = datetime.strftime(get_process_creation_time(this_process_pid), DATETIME_FORMAT)

			os.makedirs(sc4mp_server_path, exist_ok=True)

			update_json(process_info_path, {
				"pid": this_process_pid,
				"creation": this_process_creation
			})

		except Exception as e:

			raise ServerException(f"Failed to terminate the server process already running.\n\n{e}") from e


def prep():
	return #TODO move server init stuff here


def cleanup():
	return #TODO


def get_sc4mp_path(filename):
	"""TODO Gives the path of a given file in the SC4MP "resources" subdirectory

	Arguments:
		filename (str)

	Returns:
		TODO type: the path to the given file
	"""
	return os.path.join(SC4MP_RESOURCES_PATH, filename)


def md5(filename):
	"""TODO Creates the hashcode for a given file.

		filename (str)

	Returns:
		TODO type: hashcode
	"""
	hash_md5 = hashlib.md5()
	with open(filename, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()


def file_md5(file):
	
	hash_md5 = hashlib.md5()
	for chunk in iter(lambda: file.read(4096), b""):
		hash_md5.update(chunk)
	return hash_md5.hexdigest()


def create_empty_json(filename):
	
	with open(filename, 'w') as file:
		data = {}
		file.seek(0)
		json.dump(data, file, indent=4)
		file.truncate()


def load_json(filename):
	"""Returns data from a json file as a dictionary."""
	try:
		with open(filename, 'r') as file:
			data = json.load(file)
			if data is None:
				return {}
			else:
				return data
	except FileNotFoundError:
		return {}


def set_savegame_data(entry, savegame: SC4Savegame):
	"""TODO entry values"""

	# Get budget subfile
	savegame.get_cSC4BudgetSimulator()

	# No overwrite
	entry.setdefault("owner", None)
	entry.setdefault("modified", None)
	entry.setdefault("locked", False)
	entry.setdefault("filename", os.path.basename(os.path.normpath(savegame.filename)))
	entry.setdefault("reset_filename", None)
	entry.setdefault("date_subfile_hashes", [])
	entry.setdefault("last_mayor_name", None)

	# Append
	date_subfile_hash = file_md5(savegame.decompress_subfile("2990c1e5"))
	date_subfile_hashes = entry["date_subfile_hashes"]
	if date_subfile_hash not in date_subfile_hashes:
		date_subfile_hashes.append(date_subfile_hash)

	# Overwrite
	entry["hashcode"] = md5(savegame.filename)
	entry["size"] = savegame.SC4ReadRegionalCity["citySizeX"] 
	entry["city_name"] = savegame.SC4ReadRegionalCity["cityName"]
	entry["mayor_name"] = savegame.SC4ReadRegionalCity["mayorName"] 
	entry["gamemode"] = savegame.SC4ReadRegionalCity["modeFlag"]
	entry["difficulty"] = savegame.SC4ReadRegionalCity["starCount"]
	entry["mayor_rating"] = savegame.SC4ReadRegionalCity["mayorRating"]
	entry["residential_population"] = savegame.SC4ReadRegionalCity["residentialPopulation"]
	entry["commercial_population"] = savegame.SC4ReadRegionalCity["commercialPopulation"]
	entry["industrial_population"] = savegame.SC4ReadRegionalCity["industrialPopulation"]
	entry["population"] = entry["residential_population"] + entry["commercial_population"] + entry["industrial_population"]
	entry["population_density"] = round(entry["population"] / (entry["size"] * entry["size"]))
	entry["residential_population_density"] = round(entry["residential_population"] / (entry["size"] * entry["size"]))
	entry["total_funds"] = savegame.cSC4BudgetSimulator["totalFunds"]

	# Log mayor name
	if sc4mp_server_running:
		owner = entry.get("owner", None)
		if owner is not None:
			mayor_name = entry.get("mayor_name", None)
			if mayor_name is not None:
				last_mayor_name = entry.get("last_mayor_name", None)
				if mayor_name != last_mayor_name:
					mayor_names = sc4mp_users_database_manager.data[owner]["mayors"]
					if mayor_name not in mayor_names:
						mayor_names.append(mayor_name)


def update_json(filename, data):
	
	with open(filename, 'w') as file:
		file.seek(0)
		json.dump(data, file, indent=4)
		file.truncate()


def package_plugins_and_regions():
	

	report("Packaging plugins and regions...")

	report("- packaging plugins...")
	package("plugins")

	report("- packaging regions...")
	package("regions")

	# Regions manager
	global sc4mp_regions_manager
	sc4mp_regions_manager = RegionsManager()
	sc4mp_regions_manager.start()


def package(package_type):
	

	directory = None
	if package_type == "plugins":
		directory = "Plugins"
	elif package_type == "regions":
		directory = "Regions"

	target = os.path.join(sc4mp_server_path, directory)
	destination = os.path.join(sc4mp_server_path, "_Temp", "outbound", directory)

	if os.path.exists(destination):
		os.remove(destination)

	shutil.make_archive(destination, "zip", target)


def export(export_type):
	

	# Select directory name from input
	directory = None
	if export_type == "plugins":
		directory = "Plugins"
	elif export_type == "regions":
		directory = "Regions"

	# Set target and destination directories
	target = os.path.join(sc4mp_server_path, directory)
	destination = os.path.join(sc4mp_server_path, "_Temp", "outbound", directory)

	# Erase file table if exists
	if destination in sc4mp_filetables_manager.filetables.keys():
		sc4mp_filetables_manager.erase(destination)

	#TODO delete old abandoned savegames

	# Replace missing savegame files with the reset savegame file if it exists, and reset the claim
	try:
		if export_type == "regions":
			for region in os.listdir(target):
				if os.path.isdir(os.path.join(target, region)):
					data_filename = os.path.join(target, region, "_Database", "region.json")
					data = load_json(data_filename)
					update_database = False
					for entry in data.values():
						if entry is not None:
							filename = entry.get("filename", None)
							if filename is not None:
								filename = os.path.join(target, region, filename)
								if not os.path.exists(filename):
									print(f"[WARNING] Savegame at \"{filename}\" is missing!")
									reset_filename = entry.get("reset_filename", None)
									if reset_filename is not None:
										reset_filename = os.path.join(target, region, reset_filename)
										if os.path.exists(reset_filename):
											print(f"[WARNING] - replacing with \"{reset_filename}\"...")
											shutil.copy(reset_filename, filename)
										else:
											print(f"[WARNING] - cannot replace with \"{reset_filename}\", since the file does not exist.")
									else:
										entry["filename"] = None
									print("[WARNING] - resetting claim...")
									entry["owner"] = None
									update_database = True
					if update_database:
						update_json(data_filename, data)
	except Exception as e:
		show_error(e)

	# Delete destination directory if it exists 
	if os.path.exists(destination):
		shutil.rmtree(destination)
	
	# Create the parent directories if they do not yet exist
	#if (not os.path.exists(destination)):
	#	os.makedirs(destination)
	
	# Copy recursively
	shutil.copytree(target, destination, ignore=shutil.ignore_patterns('_Backups')) #, '_Database'))	

	# Generate filetable
	sc4mp_filetables_manager.generate(destination)


def purge_directory(directory):
	"""TODO

	Arguments:
		TODO

	Returns:
		TODO
	"""
	for filename in os.listdir(directory):
		file_path = os.path.join(directory, filename)
		try:
			if os.path.isfile(file_path) or os.path.islink(file_path):
				os.unlink(file_path)
			elif os.path.isdir(file_path):
				shutil.rmtree(file_path)
		except PermissionError as e:
			raise ServerException('Failed to delete "' + file_path + '" because the file is being used by another process.') from e #\n\n' + str(e)


def send_filestream(c, rootpath):

	file_table = get_file_table(rootpath)

	# Receive the filetable from the client and verify it
	ft = [tuple(item) for item in c.recv_json()]
	for item in ft:
		if not item in file_table:
			c.close()
	filetable = ft

	# Loop through the filetable and send the respective data
	for _, size, relpath in filetable:
		with open(os.path.join(rootpath, relpath), "rb") as file:
			size_read = 0
			while True:
				size_remaining = size - size_read
				buffer_size = min(size_remaining, SC4MP_BUFFER_SIZE)
				data = file.read(buffer_size)
				if not data:
					break
				size_read += len(data)
				c.sendall(data)


def get_file_table(rootpath):

	while sc4mp_server_running:
		try:
			filetable = sc4mp_filetables_manager.filetables[rootpath]
			break
		except KeyError:
			print("[WARNING] Waiting for file table to generate...")
			time.sleep(SC4MP_DELAY * 10)
	
	return filetable


def receive_file(c, filename, filesize):


	report("Receiving " + str(filesize) + " bytes...")
	report("writing to " + filename)

	if os.path.exists(filename):
		os.remove(filename)

	filesize_read = 0
	with open(filename, "wb") as f:
		while filesize_read < filesize:
			filesize_remaining = filesize - filesize_read
			buffersize = SC4MP_BUFFER_SIZE if filesize_remaining > SC4MP_BUFFER_SIZE else filesize_remaining
			bytes_read = c.recv(buffersize)
			#if not bytes_read:    
			#	break
			f.write(bytes_read)
			filesize_read += len(bytes_read)
			#print('Downloading "' + filename + '" (' + str(filesize_read) + " / " + str(filesize) + " bytes)...", int(filesize_read), int(filesize)) #os.path.basename(os.path.normpath(filename))


def report(message, obj=None, msg_type="INFO", ): #TODO do this in the logger to make sure output prints correctly
	
	'''color = '\033[94m '
	output = datetime.now().strftime("[%H:%M:%S] [SC4MP")
	obj = None
	for item in inspect.stack():
		if (obj != None):
			break
		try:
			obj = item[0].f_locals["self"]
		except Exception:
			pass
	if (obj != None):
		output += "/" + obj.__class__.__name__
		color = '\033[0m '
	output+= "] [" + msg_type + "] " + message
	if (msg_type=="WARNING"):
		color = '\033[93m '
	elif (msg_type == "ERROR" or msg_type == "FATAL"):
		color = '\033[91m '
	print(color + output)'''
	print("[" + msg_type + "] " + message)


def update_config_constants(config):
	

	global SC4MP_HOST
	global SC4MP_PORT
	global SC4MP_SERVER_ID
	global SC4MP_SERVER_NAME
	global SC4MP_SERVER_DESCRIPTION
	
	SC4MP_HOST = config['NETWORK']['host']
	SC4MP_PORT = config['NETWORK']['port']
	SC4MP_SERVER_ID = config['INFO']['server_id']
	SC4MP_SERVER_NAME = config['INFO']['server_name']
	SC4MP_SERVER_DESCRIPTION = config['INFO']['server_description']


def restore(filename):
	
	possible_paths = [
		os.path.join(sc4mp_server_path, "_Backups", filename),
		os.path.join(sc4mp_server_path, "_Backups", filename + ".json"),
		os.path.join(sc4mp_server_path, filename),
		os.path.join(sc4mp_server_path, filename + ".json"),
		filename,
		filename + ".json",
	]
	for path in possible_paths:
		if not os.path.exists(path):
			continue
		else:
			if path[-5:] != ".json":
				raise ServerException("Backup file must be a \".json\" file.")
			print("Restoring backup at \"" + path + "\"")
			data = load_json(path)
			directory, filename = os.path.split(os.path.abspath(path))
			files_entry = data["files"]
			for original_filename, file_entry in files_entry.items():
				hashcode = file_entry["hashcode"]
				size = file_entry["size"]
				data_filename = os.path.join(directory, "data", hashcode + "_" + str(size))
				restore_filename = os.path.join(directory, "restores", filename[:-5], original_filename)
				print("Copying \"" + data_filename + "\" to \"" + restore_filename + "\"")
				restore_directory = os.path.split(restore_filename)[0]
				if not os.path.exists(restore_directory):
					os.makedirs(restore_directory)
				shutil.copy(data_filename, restore_filename)
			print("- done.")
			return
	raise ServerException("File not found.")


def show_error(e, no_ui=False):
	
	message = None
	if isinstance(e, str):
		message = e
	else: 
		message = str(e)

	print("[ERROR] " + message + "\n\n" + traceback.format_exc())

	'''if (not no_ui):
		if (sc4mp_ui != None):
			if (sc4mp_ui == True):
				tk.Tk().withdraw()
			messagebox.showerror(SC4MP_TITLE, message)'''


def fatal_error(e):
	

	message = None
	if isinstance(e, str):
		message = e
	else: 
		message = str(e)

	print("[FATAL] " + message + "\n\n" + traceback.format_exc())

	'''if (sc4mp_ui != None):
		if (sc4mp_ui == True):
			tk.Tk().withdraw()
		messagebox.showerror(SC4MP_TITLE, message)'''

	global sc4mp_server_running
	sc4mp_server_running = False

	if sc4mp_system_tray_icon_manager:
		sc4mp_system_tray_icon_manager.status("Stopped", "A fatal error has occurred. Please check the logs at \"Documents\\SimCity 4\\SC4MP Server\\sc4mpserver.log\" for more details.")

	#sys.exit()


def set_savegame_filename(savegameX, savegameY, savegameCityName, savegameMayorName, savegameModeFlag):

	prefix = f"({savegameX:0>{3}}-{savegameY:0>{3}})"

	if savegameModeFlag == 0:

		return f"{prefix} - (Empty).sc4"
	
	else:

		if savegameCityName:
			city_name = filter_non_alpha_numeric(savegameCityName)
			if len(city_name) < 1:
				city_name = "New City"
		else:
			city_name = "(Error)"

		if savegameMayorName:
			mayor_name = filter_non_alpha_numeric(savegameMayorName)
			if len(mayor_name) < 1:
				mayor_name = "Defacto"
		else:
			mayor_name = "(Error)"
		
		return f"{prefix} - {city_name} - {mayor_name}"[:252] + ".sc4"


def open_upnp_port(port, protocol="TCP", description="Port Forwarding via UPnP"):

	def get_gateway():

		devices = upnpclient.discover()
		
		print([device for device in devices])

		for device in devices:
			print(device.services)
			for service in device.services:
				if "WANIPConnection" in service.service_type or "WANPPPConnection" in service.service_type:
					return device
		
		raise ServerException("No UPnP-enabled gateway found.")

	gateway = get_gateway()
	address = socket.gethostbyname(socket.gethostname())

	if address == "127.0.0.1":
		raise ServerException("Unable to determine LAN IP address.")

	for mapping in gateway.WANIPConnection.GetPortMapping():
		if mapping['NewExternalPort'] == str(port) and mapping['NewProtocol'] == protocol:
			print(f"Port {port} ({protocol}) is already mapped to {mapping['NewInternalClient']}.")
			return

	print(f"Opening port {port} ({protocol}) on \"{gateway.friendly_name}\"...")

	gateway.AddPortMapping(
            NewRemoteHost="",
            NewExternalPort=port,
            NewProtocol=protocol,
            NewInternalPort=port,
            NewInternalClient=address,
            NewEnabled=1,
            NewPortMappingDescription=description,
            NewLeaseDuration=0,
        )


def set_headers(s):

	return s.set_headers(
		server_id=sc4mp_config["INFO"]["server_id"],
		server_name=sc4mp_config["INFO"]["server_name"],
		server_description=sc4mp_config["INFO"]["server_description"],
		server_url=sc4mp_config["INFO"]["server_url"],
		server_version=SC4MP_VERSION,
		private=sc4mp_config["SECURITY"]["private"],
		password_enabled=sc4mp_config["SECURITY"]["password_enabled"],
		user_plugins_enabled=sc4mp_config["RULES"]["user_plugins"],
		claim_duration=sc4mp_config["RULES"]["claim_duration"],
		max_region_claims=sc4mp_config["RULES"]["max_region_claims"],
		godmode_filter=sc4mp_config["RULES"]["godmode_filter"],
		time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	)


# Workers

class Server(th.Thread):
	


	def __init__(self):
		

		super().__init__()

		self.BIND_RETRY_DELAY = 5

		self.load_config()
		self.create_subdirectories()
		self.check_updates()
		self.prep_database()
		self.clear_temp()
		self.prep_filetables()
		self.prep_regions() 
		self.prep_backups()
		self.prep_server_list()
		# self.prep_upnp()

	
	def run(self):
		
		try:

			global sc4mp_server_running, sc4mp_request_threads

			report("Starting server...")

			report("- creating socket...")
			s = self.socket()

			report("- binding host " + SC4MP_HOST + " and port " + str(SC4MP_PORT) + "...")
			while True:
				try:
					s.bind((SC4MP_HOST, SC4MP_PORT))
					break
				except OSError as e:
					show_error(e)
					print(f"[WARNING] - failed to bind socket, retrying in {self.BIND_RETRY_DELAY} seconds...")
					time.sleep(self.BIND_RETRY_DELAY)

			if sc4mp_system_tray_icon_manager:
				sc4mp_system_tray_icon_manager.status("Running", f"Listening on port {SC4MP_PORT}. You may now use the SC4MP Launcher to join.")

			report("- listening for connections...")
			s.listen(5)
			
			sc4mp_server_running = True

			max_request_threads = sc4mp_config["PERFORMANCE"]["max_request_threads"]

			client_requests = {}
			client_requests_cleared = datetime.now()

			while sc4mp_server_running:

				if datetime.now() >= client_requests_cleared + timedelta(seconds=60):

					client_requests = {}
					client_requests_cleared = datetime.now()
				
				if max_request_threads is None or sc4mp_request_threads < max_request_threads:

					try:

						c, (host, port) = s.accept()

						c.settimeout(sc4mp_config["PERFORMANCE"]["connection_timeout"])

						if (sc4mp_config["PERFORMANCE"]["request_limit"] is not None and host in client_requests and client_requests[host] >= sc4mp_config["PERFORMANCE"]["request_limit"]):
							print("[WARNING] Connection blocked from " + str(host) + ":" + str(port) + ".")
							c.close()
							continue
						else:
							client_requests.setdefault(host, 0)
							client_requests[host] += 1

						# report(f"Connection accepted with {host}.")

						self.log_client(c)

						sc4mp_request_threads += 1

						RequestHandler(c).start()	

					except Exception as e: #socket.error as e:

						show_error(e)
			
				else:

					print("[WARNING] Request thread limit reached!")

					while not (sc4mp_request_threads < max_request_threads):
						time.sleep(SC4MP_DELAY)
				
		except (SystemExit, KeyboardInterrupt):

			pass

		except Exception as e:

			fatal_error(e)

		finally:

			report("Shutting down...")
			sc4mp_server_running = False


	def socket(self) -> ServerSocket:

		s = ServerSocket()
		set_headers(s)
		return s


	def log_client(self, c):
		

		# Get ip
		ip = c.getpeername()[0]

		# Get clients database
		clients_data = sc4mp_clients_database_manager.data
		
		# Get data entry that matches ip
		client_entry = None
		try:
			client_entry = clients_data[ip]
		except Exception:
			client_entry = {}
			clients_data[ip] = client_entry

		# Set values
		client_entry.setdefault("users", [])
		client_entry.setdefault("ban", False)
		client_entry.setdefault("first_contact", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
		client_entry["last_contact"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


	def create_subdirectories(self):
		

		report("Creating subdirectories...")

		directories = ["_Backups", "_Database", "_Temp", "Plugins", "Regions"]

		for directory in directories:
			new_directory = os.path.join(sc4mp_server_path, directory)
			if not os.path.exists(new_directory):
				try:
					os.makedirs(new_directory)
					if (directory == "Plugins" or directory == "Regions"):
						shutil.unpack_archive(get_sc4mp_path(directory + ".zip"), new_directory)
				except Exception as e:
					show_error(e)
					#report("Failed to create " + directory + " subdirectory.", None, "WARNING")
					#report('(this may have been printed by error, check your sc4mp_server_path subdirectory)', None, "WARNING")

		# Create helper batch files on Windows
		try:

			exec_path = Path(sys.executable)
			exec_file = exec_path.name
			exec_dir = exec_path.parent

			path = exec_dir if sc4mp_server_path == "_SC4MP" else sc4mp_server_path

			if exec_file == "sc4mpserver.exe":

				with open(os.path.join(path, "logs.bat"), "w") as batch_file:
					batch_file.writelines([
						"@echo off\n",
						(f"title {SC4MP_TITLE}\n" if sc4mp_server_path == "_SC4MP" else f"title {SC4MP_TITLE} - {sc4mp_server_path}\n"),
						"PowerShell -NoProfile -ExecutionPolicy Bypass -Command \"gc sc4mpserver.log -wait -tail 1000\"\n",
					])

				with open(os.path.join(path, "run.bat"), "w") as batch_file:
					batch_file.writelines([
						"@echo off\n",
						f"cd /d \"{exec_dir}\"\n",
						f"sc4mpserver.exe -s \"{sc4mp_server_path}\"\n",
					])

				with open(os.path.join(path, "start.bat"), "w") as batch_file:
					batch_file.writelines([
						"@echo off\n",
						f"cd /d \"{exec_dir}\"\n",
						f"start \"\" sc4mpserver.exe -s \"{sc4mp_server_path}\"\n",
					])

				with open(os.path.join(path, "stop.bat"), "w") as batch_file:
					batch_file.writelines([
						"@echo off\n",
						f"cd /d \"{exec_dir}\"\n",
						f"sc4mpserver.exe -s \"{sc4mp_server_path}\" --stop\n",
					])

				with open(os.path.join(path, "prep.bat"), "w") as batch_file:
					batch_file.writelines([
						"@echo off\n",
						f"cd /d \"{exec_dir}\"\n",
						f"sc4mpserver.exe -s \"{sc4mp_server_path}\" --prep\n",
					])

				with open(os.path.join(path, "restore.bat"), "w") as batch_file:
					batch_file.writelines([
						"@echo off\n",
						f"cd /d \"{exec_dir}\"\n",
						"set /p backup=\"Enter a backup to restore...\"\n",
						f"sc4mpserver.exe -s \"{sc4mp_server_path}\" --restore %backup%\n",
						"pause\n",
					])

				if sc4mp_server_path == "_SC4MP":

					with open(os.path.join(path, "new.bat"), "w") as batch_file:
						batch_file.writelines([
							"@echo off\n",
							f"cd /d \"{exec_dir}\"\n",
							"set /p name=\"Enter the name of the new server configuration...\"\n",
							f"sc4mpserver.exe -s \"{sc4mp_server_path}\" -s %name% --prep\n",
							f"C:\Windows\explorer.exe \"{exec_dir}\\%name%\"\n"
						])

					with open(os.path.join(path, "update.bat"), "w") as batch_file:
						batch_file.writelines([
							"@echo off\n",
							f"cd /d \"{exec_dir}\"\n",
							f"sc4mpserver.exe -s \"{sc4mp_server_path}\" -u\n",
						])

		except Exception as e:

			show_error(f"Failed to create helper batch files.\n\n{e}")


	def load_config(self):
		

		global sc4mp_config, SC4MP_CONFIG_PATH
		SC4MP_CONFIG_PATH = os.path.join(sc4mp_server_path, "serverconfig.ini")

		report("Loading config...")
		
		sc4mp_config = Config(SC4MP_CONFIG_PATH, SC4MP_CONFIG_DEFAULTS, error_callback=show_error, update_constants_callback=update_config_constants)

		# System tray icon
		global sc4mp_system_tray_icon_manager
		if is_windows() and is_frozen() and sc4mp_config["UI"]['enabled'] and sc4mp_has_pystray and sc4mp_has_pil:
			sc4mp_system_tray_icon_manager = SystemTrayIconManager()
			sc4mp_system_tray_icon_manager.start()
			while not sc4mp_system_tray_icon_manager.icon.visible:
				time.sleep(SC4MP_DELAY)
			sc4mp_system_tray_icon_manager.status("Preparing", "Running in the background. Click on the system tray icon to manage your sever.")
		else:
			sc4mp_system_tray_icon_manager = None

		'''global SC4MP_HOST
		global SC4MP_PORT
		global SC4MP_SERVER_ID
		global SC4MP_SERVER_NAME
		global SC4MP_SERVER_DESCRIPTION

		report("Loading config...")

		config_path = os.path.join(sc4mp_server_path, "serverconfig.ini")

		try:

			config = configparser.RawConfigParser()
			config.read(config_path)

			SC4MP_HOST = config.get('server', "host")
			SC4MP_PORT = int(config.get('server', 'port'))
			SC4MP_SERVER_ID = config.get('server', "server_id")
			SC4MP_SERVER_NAME = config.get('server', "server_name")
			SC4MP_SERVER_DESCRIPTION = config.get('server', "server_description")

		except Exception:

			config.remove_section('server')
			config.add_section('server')
			config.set('server', 'host', default_host)
			config.set('server', 'port', default_port)
			config.set('server', 'server_id', default_server_id)
			config.set('server', 'server_name', default_server_name)
			config.set('server', 'server_description', default_server_description)
			
			with open(config_path, 'wt') as config_file:
				config.write(config_file)

			SC4MP_HOST = default_host
			SC4MP_PORT = default_port
			SC4MP_SERVER_ID = default_server_id
			SC4MP_SERVER_NAME = default_server_name
			SC4MP_SERVER_DESCRIPTION = default_server_description'''


	def check_updates(self):

		if not sc4mp_skip_update:

			print("Checking for updates...")

			try:

				global sc4mp_ui

				PROCESS_NAME = "sc4mpserver.exe"

				# Get the path of the executable file which is currently running
				exec_path = Path(sys.executable)
				exec_file = exec_path.name
				exec_dir = exec_path.parent

				# Only update if running a Windows distribution
				if sc4mp_force_update or exec_file == PROCESS_NAME:

					# Get latest release info
					try:
						with urllib.request.urlopen(f"https://api.github.com/repos/{SC4MP_GITHUB_REPO}/releases/latest", timeout=10) as url:
							latest_release_info = json.load(url)
					except urllib.error.URLError as e:
						raise ServerException("GitHub API call timed out.") from e

					# Download the update if the version doesn't match
					if sc4mp_force_update or unformat_version(latest_release_info["tag_name"]) > unformat_version(SC4MP_VERSION):

						# Local function for update thread
						def update():
							
							try:

								set_thread_name("UpdtThread", enumerate=False)

								# Function to write to console and update ui
								def report(message):
									print(message)

								# Change working directory to the one where the executable can be found
								if exec_file == PROCESS_NAME:
									os.chdir(exec_dir)

								# Delete updater.bat
								if os.path.exists("updater.bat"):
									os.unlink("updater.bat")

								# Purge update directory
								try:
									if os.path.exists("update"):
										purge_directory(Path("update"))
								except Exception:
									pass

								# Delete uninstaller if exists
								try:
									for filename in ["unins000.dat", "unins000.exe"]:
										if os.path.exists(filename):
											os.unlink(filename)
								except Exception:
									pass

								# Report
								report("Downloading update...")

								# Get download URL
								download_url = None
								for asset in latest_release_info["assets"]:
									if asset["name"].startswith("sc4mp-server-installer-windows"):
										download_url = asset["browser_download_url"]
										destination = os.path.join("update", asset["name"])
										break

								# Raise an exception if the download URL was not found
								if download_url is None:
									raise ServerException("The correct release asset was not found.")

								# Prepare destination
								os.makedirs("update", exist_ok=True)
								if os.path.exists(destination):
									os.unlink(destination)

								# Download file
								download_size = int(urllib.request.urlopen(download_url).headers["Content-Length"])
								with urllib.request.urlopen(download_url) as rfile:
									with open(destination, "wb") as wfile:
										download_size_downloaded = 0
										while download_size_downloaded < download_size:
											bytes_read = rfile.read(SC4MP_BUFFER_SIZE) 
											download_size_downloaded += len(bytes_read)
											wfile.write(bytes_read)

								# Convert destination to path object
								destination = Path(destination)

								# Report installing update
								report("Installing update...")

								# Create `updater.bat``								
								args = sys.argv
								args.pop(0)
								if "-u" in args:
									args.remove("-u")
								if "--force-update" in args:
									args.remove("--force-update")
								with open("updater.bat", "w") as batch_file:
									batch_file.writelines([
										"@echo off\n",
										f"cd /d \"{os.getcwd()}\"\n",
										"echo Running installer...\n",
										f"cd {destination.parent}\n",
										f"{destination.stem} /dir=\"{os.getcwd()}\" /verysilent\n",
										"cd ..\n",
										"echo Relaunching server...\n",
										f"{PROCESS_NAME} {' '.join(args)}\n"
									])

								# Start installer in very silent mode and exit
								subprocess.Popen(["updater.bat"])
							
							except Exception as e:

								show_error(f"An error occurred in the update thread.\n\n{e}", no_ui=True)

						# Run update function
						update()

						# Exit when complete
						sys.exit()
				
			except Exception as e:

				# Show error silently and continue as usual
				show_error(f"An error occurred while updating.\n\n{e}", no_ui=True)


	def prep_database(self):
		

		report("Preparing database...")

		# Database directory
		database_directory = os.path.join(sc4mp_server_path, "_Database")

		# Users database
		filename = os.path.join(database_directory, "users.json")
		if not os.path.exists(filename):
			create_empty_json(filename)

		# Clients database
		filename = os.path.join(database_directory, "clients.json")
		if not os.path.exists(filename):
			create_empty_json(filename)

		# Get region directory names
		regions = []
		regions_directory = os.path.join(sc4mp_server_path, "Regions")
		items = os.listdir(regions_directory)
		for item in items:
			path = os.path.join(regions_directory, item)
			if not os.path.isfile(path):
				regions.append(item)

		# Create databases for each region
		for region in regions:
			
			# Region directory
			region_directory = os.path.join(regions_directory, region)

			# Create `region.ini` file if not present
			region_ini_path = os.path.join(region_directory, "region.ini")
			if not os.path.exists(region_ini_path):
				print(f"[WARNING] Region \"{region}\" is missing a configuration file. Creating...")
				with open(region_ini_path, "w") as file:
					file.write(f"[Regional Settings]\nName = {region}\nTerrain type = 0\nWater Min = 60\nWater Max = 100\n")

			# Create subdirectories in region directory
			region_subdirectories = ["_Database", "_Backups"]
			for region_subdirectory in region_subdirectories:
				directory = os.path.join(region_directory, region_subdirectory)
				if not os.path.exists(directory):
					os.makedirs(directory)

			# Get database
			filename = os.path.join(region_directory, "_Database", "region.json")
			data = None
			try:
				data = load_json(filename)
			except Exception:
				data = {}
			
			# Get savegame paths
			savegame_paths = []
			items = os.listdir(region_directory)
			for item in items:
				path = os.path.join(region_directory, item)
				if (os.path.isfile(path) and path[-4:] == ".sc4"):
					savegame_paths.append(path)

			# Open savegames as DBPF objects
			savegames: list[SC4Savegame] = []
			for savegame_path in savegame_paths:
				savegames.append(SC4Savegame(savegame_path, error_callback=show_error))

			# Get the region subfile of each DBPF object and update the database
			for savegame in savegames:

				# Get region, budget subfiles
				savegame.get_SC4ReadRegionalCity()

				# Get values from region subfile
				savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
				savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
				savegameSize = savegame.SC4ReadRegionalCity["citySizeX"]
				savegameCityName = savegame.SC4ReadRegionalCity["cityName"]
				savegameMayorName = savegame.SC4ReadRegionalCity["mayorName"]
				savegameModeFlag = savegame.SC4ReadRegionalCity["modeFlag"]

				# Get md5 hashcode of date subfile
				#savegame_date_subfile_hash = file_md5(savegame.decompress_subfile("2990c1e5"))

				# Get dictionary for savegame data
				coords = str(savegameX) + "_" + str(savegameY)
				entry = data.get(coords, {})
				if entry is None:
					entry = {}
				data[coords] = entry

				# Create reset savegame file if needed
				if ("reset_filename" not in entry.keys()) or ((entry["reset_filename"] is not None) and (not os.path.exists(os.path.join(region_directory, entry["reset_filename"])))):
					reset_directory = os.path.join("_Backups", coords)
					os.makedirs(os.path.join(region_directory, reset_directory), exist_ok=True)
					reset_filename = os.path.join(reset_directory, "reset.sc4")
					if not os.path.exists(os.path.join(region_directory, reset_filename)):
						shutil.copy(savegame.filename, os.path.join(region_directory, reset_filename))
					entry["reset_filename"] = reset_filename

				# Set entry values
				set_savegame_data(entry, savegame)
					
				# Reserve tiles which the savegame occupies
				for offsetX in range(savegameSize):
					x = savegameX + offsetX
					for offsetY in range(savegameSize):
						y = savegameY + offsetY
						data.setdefault(str(x) + "_" + str(y), None)

				# Close DBPF file
				savegame.close()

				# Rename savegame file to match correct format
				new_filename = set_savegame_filename(savegameX, savegameY, savegameCityName, savegameMayorName, savegameModeFlag)
				if entry["filename"] is not None and entry["filename"] != new_filename:
					print(f"- renaming \"{entry['filename']}\" to \"{new_filename}\"...")
					try:
						os.rename(os.path.join(region_directory, entry["filename"]), os.path.join(region_directory, new_filename))
						entry["filename"] = new_filename
					except Exception as e:
						show_error(e)

			# Cleanup DBPF objects to avoid errors when attempting to delete save files
			savegames = None

			update_json(filename, data)

		if sc4mp_nostart:
			return

		# Users database manager
		global sc4mp_users_database_manager
		sc4mp_users_database_manager = DatabaseManager(os.path.join(sc4mp_server_path, "_Database", "users.json"))
		sc4mp_users_database_manager.start()

		# Clients database manager
		global sc4mp_clients_database_manager
		sc4mp_clients_database_manager = DatabaseManager(os.path.join(sc4mp_server_path, "_Database", "clients.json"))
		sc4mp_clients_database_manager.start()


	def clear_temp(self):
		

		report("Clearing temporary files...")

		try:
			purge_directory(os.path.join(sc4mp_server_path, "_Temp"))
		except Exception as e:
			show_error(e)


	def prep_regions(self):
		

		if sc4mp_nostart:
			return

		report("Preparing regions...")

		export("regions")

		# Regions manager
		global sc4mp_regions_manager
		sc4mp_regions_manager = RegionsManager()
		sc4mp_regions_manager.start()


	def prep_backups(self):
		

		report("Preparing backups...")

		# Backups manager
		global sc4mp_backups_manager
		sc4mp_backups_manager = BackupsManager()
		if sc4mp_config["BACKUPS"]["backup_server_on_startup"]:
			sc4mp_backups_manager.backup()
		if not sc4mp_nostart:
			sc4mp_backups_manager.start()


	def prep_filetables(self):

		if not sc4mp_nostart:

			report("Preparing plugins...") #report("Preparing file tables...")

			global sc4mp_filetables_manager
			sc4mp_filetables_manager = FileTablesManager()

			sc4mp_filetables_manager.generate(os.path.join(sc4mp_server_path, "Plugins"))

			sc4mp_filetables_manager.start()


	def prep_server_list(self):
		

		if sc4mp_nostart:
			return

		if not sc4mp_config["NETWORK"]["discoverable"]:
			return

		report("Preparing server list...")

		global sc4mp_server_list
		sc4mp_server_list = ServerList()
		sc4mp_server_list.start()


	def prep_upnp(self):

		if sc4mp_config['NETWORK']['upnp']:

			print("Preparing UPnP port...")

			if not sc4mp_has_upnpclient:
				raise ServerException("UPnP requires the `upnpclient` module. Install the module or disable UPnP in `serverconfig.ini`, then restart the server.")

			port = sc4mp_config['NETWORK']['port']

			try:

				open_upnp_port(port, "TCP", "Created by SimCity 4 Multiplayer Project Server.")

			except Exception as e:

				raise ServerException(f"An error occurred while opening a port with UPnP. Disable UPnP in `serverconfig.ini`, forward port {port} manually, then restart the server.\n\n{e}") from e


class BackupsManager(th.Thread):
	


	def __init__(self):
		

		self.backup_dir = Path(sc4mp_server_path) / "_Backups"
		super().__init__()


	def run(self):
		

		try:

			global sc4mp_server_running

			set_thread_name("BakThread", enumerate=False)

			while not sc4mp_server_running:
				
				time.sleep(SC4MP_DELAY)

			while sc4mp_server_running:

				# Delay
				time.sleep(3600 * sc4mp_config["BACKUPS"]["server_backup_interval"])

				while sc4mp_server_running:

					try:

						# Create backup	
						self.backup()

						# Break the loop if the backup was successful
						break

					except Exception as e:

						# Report error
						show_error(e)

						# Wait before retrying backup
						time.sleep(60)

		except Exception as e:

			fatal_error(e)


	def load_json(self, filename):
		
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except Exception:
			return {}


	def update_json(self, filename, data):
		
		with open(filename, 'w') as file:
			file.seek(0)
			json.dump(data, file, indent=4)
			file.truncate()


	def backup(self): #TODO stop backing up the backups subdirectory
		

		# Prune backups
		try:
			self.prune()
		except Exception as e:
			show_error("An error occured while pruning backups.")

		# Report creating backups
		report("Creating backup...", self)

		# Loop through all files in server directory and append them to a list
		fullpaths = []
		for path, directories, files in os.walk(sc4mp_server_path):
			for file in files:
				if not os.path.abspath(os.path.join(sc4mp_server_path, "_Backups")) in os.path.abspath(path):
					fullpaths.append(os.path.join(path, file))

		# Create a files entry for the backup dictionary
		files_entry = {}

		# Loop through fullpaths and backup the files and add them to the files entry
		for fullpath in fullpaths:
			hashcode = md5(fullpath)
			filesize = os.path.getsize(fullpath)
			directory = os.path.join(sc4mp_server_path, "_Backups", "data")
			if not os.path.exists(directory):
				os.makedirs(directory)
			filename = os.path.join(directory, hashcode + "_" + str(filesize))
			if not os.path.exists(filename) or hashcode != md5(filename) or filesize != os.path.getsize(filename):
				report('- copying "' + fullpath + '"...', self)
				if os.path.exists(filename):
					os.remove(filename)
				shutil.copy(fullpath, filename)
			fullpath_entry = {}
			fullpath_entry["hashcode"] = hashcode
			fullpath_entry["size"] = filesize
			#fullpath_entry["backup_filename"] = filename
			files_entry[fullpath] = fullpath_entry

		# Create dictionary for backup and add the files entry
		backup_data = {}
		backup_data["files"] = files_entry

		# Update database
		backup_filename = os.path.join(sc4mp_server_path, "_Backups", datetime.now().strftime("%Y%m%d%H%M%S") + ".json")
		self.update_json(backup_filename, backup_data)

		# Report done
		report("- done.", self)


	def prune(self) -> None:
		"""
		Prunes the backup data by first removing any json backup records
		that are older than the retention period, then comparing the backup
		files to the entries in the remaining json files.
		"""
		report('Pruning backups...', self)
		max_server_backup_days = sc4mp_config["BACKUPS"]["max_server_backup_days"]

		if max_server_backup_days is not None:
			self.prune_backup_records(max_server_backup_days)

		self.prune_backup_data()


	def prune_backup_records(self, days: int) -> None:
		"""Delete expired backup records"""

		cutoff = datetime.now() - timedelta(days=days)

		for backup in self.backup_dir.glob('*.json'):
			backup_date = datetime.strptime(backup.stem, "%Y%m%d%H%M%S")
			if backup_date < cutoff:
				backup.unlink()


	def prune_backup_data(self) -> None:
		"""Delete unreferenced backup data"""

		# collect all backup references from json records
		referenced_files = self.get_referenced_files()

		# remove unreferenced backup files
		backup_file_dir = self.backup_dir / 'data'
		if backup_file_dir.exists():
			for file in [f for f in backup_file_dir.iterdir() if f.is_file()]:
				
				# parse hash and filesize from file name
				hashcode, size_str = file.stem.split('_')
				size = int(size_str)

				if (hashcode, size) not in referenced_files:
					file.unlink()


	def get_referenced_files(self) -> set[tuple[str, int]]:
		"""Return all referenced backup files as a set of tuples of (hashcode, size)"""
		# # types
		# FileDetail = TypedDict('FileDetail', {'hashcode': str, 'size': int})
		# BackupJSON = TypedDict('BackupJSON', {'files': "dict[str, FileDetail]"})

		referenced_files: set[tuple[str, int]] = set()

		for json_path in self.backup_dir.glob('*.json'):

			backup_json = load_json(json_path)

			for file_detail in backup_json['files'].values():
				hashcode = file_detail['hashcode']
				size = file_detail['size']
				referenced_files.add((hashcode, size))

		return referenced_files


class DatabaseManager(th.Thread):
	

	
	def __init__(self, filename):
		

		super().__init__()
	
		self.filename = filename #os.path.join(sc4mp_server_path, "_Database", "users.json")
		self.data = self.load_json(self.filename)


	def run(self):
		
	
		try:

			global sc4mp_server_running

			while not sc4mp_server_running:
				
				time.sleep(SC4MP_DELAY)

			set_thread_name("DbThread")

			#report("Monitoring database for changes...", self) #TODO why is the spacing wrong?
			
			old_data = str(self.data)
			
			while sc4mp_server_running: #TODO pretty dumb way of checking if a dictionary has been modified. also this thread probably needs to stop at some point
				try:
					time.sleep(SC4MP_DELAY)
					new_data = str(self.data)
					if old_data != new_data:
						#report('Updating "' + self.filename + '"...', self) #TODO make verbose
						self.update_json(self.filename, self.data)
						#report("- done.", self) #TODO make verbose
					old_data = new_data
				except Exception as e:
					show_error(e)

		except Exception as e:

			fatal_error(e)


	def load_json(self, filename):
		
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except Exception:
			return {}

	
	def update_json(self, filename, data):
		
		with open(filename, 'w') as file:
			file.seek(0)
			json.dump(data, file, indent=4)
			file.truncate()


class RegionsManager(th.Thread):
	

	
	def __init__(self):
		

		super().__init__()

		self.regions_modified = False
		self.export_regions = False
		self.tasks = []
		self.outputs = {}
		#self.lastmtime = self.get_mtime()


	def run(self):
		

		try:

			global sc4mp_server_running

			while not sc4mp_server_running:
				
				time.sleep(SC4MP_DELAY)

			set_thread_name("RgnThread", enumerate=False)
			
			while sc4mp_server_running:

				try:

					# Mark regions as modified if modification time changes
					#mtime = self.get_mtime()
					#if mtime != self.lastmtime:
					#	self.lastmtime = mtime
					#	self.regions_modified = True

					# Export regions if requested, otherwise check for new tasks
					if self.export_regions:

						report("Exporting regions as requested...", self)

						export("regions")

						report("- done.", self)

						self.regions_modified = False
						self.export_regions = False

					else:

						# Check for the next task
						if len(self.tasks) > 0:

							# Get the next task
							task = self.tasks.pop(0)

							# Read values from tuple
							save_id, user_id, region, savegame = task

							report('Processing task "' + save_id + '"...', self)

							# Another layer of exception handling so that the request handler isn't waiting around in the event of an error
							try:

								# Get values from savegame
								filename = savegame.filename
								savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
								savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
								savegameSizeX = savegame.SC4ReadRegionalCity["citySizeX"]
								savegameSizeY = savegame.SC4ReadRegionalCity["citySizeY"]
								savegameModeFlag = savegame.SC4ReadRegionalCity["modeFlag"]
								savegameCityName = savegame.SC4ReadRegionalCity["cityName"]
								savegameMayorName = savegame.SC4ReadRegionalCity["mayorName"]

								# Set "coords" variable. Used as a key in the region database and also for the name of the new save file
								coords = f'{savegameX}_{savegameY}'

								# Get region database
								data_filename = os.path.join(sc4mp_server_path, "Regions", region, "_Database", "region.json")
								data = self.load_json(data_filename)
								
								# Get city entry or get & set as empty dict if key does not exist
								entry = data.setdefault(coords, {})

								# Filter out claims on locked tiles
								if entry.get("locked", False):
									self.outputs[save_id] = "Tile is locked."

								# Filter out godmode savegames if required
								if sc4mp_config["RULES"]["godmode_filter"]:
									if savegameModeFlag == 0:
										self.outputs[save_id] = "You must establish a city before claiming a tile."
								
								# Filter out cities that don't match the region configuration
								if entry is None:
									self.outputs[save_id] = "Invalid city location."

								# Filter out cities of the wrong size
								if "size" in entry:
									if (savegameSizeX != savegameSizeY or savegameSizeX != entry["size"]):
										self.outputs[save_id] = "Invalid city size."

								# Filter out claims on tiles with unexpired claims of other users
								reclaimed = False
								if "owner" in entry:
									owner = entry["owner"]
									if (owner is not None and owner != user_id):
										if sc4mp_config["RULES"]["claim_duration"] is None:
											self.outputs[save_id] = "City already claimed."
										else:
											expires = datetime.strptime(entry["modified"], "%Y-%m-%d %H:%M:%S") + timedelta(days=sc4mp_config["RULES"]["claim_duration"])
											if expires > datetime.now():
												self.outputs[save_id] = "City already claimed."
										reclaimed = True

								# Filter out cliams of users who have exhausted their region claims
								if ("owner" not in entry or entry["owner"] != user_id):
									if sc4mp_config["RULES"]["max_region_claims"] is not None:
										claims = len(list(filter(lambda x: x is not None and x.get("owner") == user_id, data.values())))
										if claims >= sc4mp_config["RULES"]["max_region_claims"]:
											self.outputs[save_id] = "Claim limit reached in this region."

								# Filter out claims of users who have exhausted their total claims
								#TODO

								# Proceed if save push has not been filtered out
								if save_id not in self.outputs:

									# Delete previous save file if it exists
									if "filename" in entry and entry["filename"] is not None:
										previous_filename = os.path.join(sc4mp_server_path, "Regions", region, entry["filename"])
										if os.path.exists(previous_filename):
											os.remove(previous_filename)

									# Set new filename
									new_filename = set_savegame_filename(savegameX, savegameY, savegameCityName, savegameMayorName, savegameModeFlag)
									new_filename_oldscheme = f"{coords}.sc4"

									# Copy save file from temporary directory to regions directory (use old naming scheme if new one causes an error)
									destination_directory = os.path.join(sc4mp_server_path, "Regions", region)
									try:
										destination = os.path.join(destination_directory, new_filename)
										if os.path.exists(destination):
											os.remove(destination)
										shutil.copy(filename, destination)
									except Exception:
										destination = os.path.join(destination_directory, new_filename_oldscheme)
										if os.path.exists(destination):
											os.remove(destination)
										shutil.copy(filename, destination)

									# Copy save file from temporary directory to backup directory
									backup_directory = os.path.join(sc4mp_server_path, "Regions", region, "_Backups", coords)
									if not os.path.exists(backup_directory):
										os.makedirs(backup_directory)
									while (sc4mp_config["BACKUPS"]["max_savegame_backups"] is not None and len(os.listdir(backup_directory)) > sc4mp_config["BACKUPS"]["max_savegame_backups"]):
										delete_filename = random.choice(os.listdir(backup_directory))
										if delete_filename == "reset.sc4":
											continue
										os.remove(os.path.join(backup_directory, delete_filename))
									destination = os.path.join(backup_directory, datetime.now().strftime("%Y%m%d%H%M%S") + ".sc4")
									shutil.copy(filename, destination)
									#TODO delete old backups

									# Set entry values
									entry["filename"] = new_filename
									entry["owner"] = user_id
									entry["modified"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
									entry["reclaimed"] = reclaimed or entry.get("reclaimed", False)
									if reclaimed:
										entry["last_mayor_name"] = entry.get("mayor_name", None)
									set_savegame_data(entry, savegame)

									# Update database
									self.update_json(data_filename, data)

									# Mark regions as modified
									self.regions_modified = True

									# Report success
									self.outputs[save_id] = "ok"

							except Exception as e:

								# Report an error to the request handler
								self.outputs[save_id] = "Unexpected server-side error."

								# Raise the exception so that it appears in the server's output
								raise e

							report("- done.", self)

						else:

							# Clean up inbound temporary files and outputs
							try:
								path = os.path.join(sc4mp_server_path, "_Temp", "inbound")
								for directory in os.listdir(path):
									if directory in self.outputs:

										shutil.rmtree(os.path.join(path, directory))

										# sleep to allow RequestHandler.save() time to check for success #TODO better solution needed, but this works for now
										time.sleep(2 * SC4MP_DELAY)

										self.outputs.pop(directory)

							except Exception as e:
								pass
							
							time.sleep(SC4MP_DELAY)

				except Exception as e:

					show_error(e)

					time.sleep(5)

		except Exception as e:

			fatal_error(e)


	def load_json(self, filename):
		
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except Exception:
			return {}

	
	def update_json(self, filename, data):
		
		with open(filename, 'w') as file:
			file.seek(0)
			json.dump(data, file, indent=4)
			file.truncate()


	def get_mtime(self):

		os.path.getmtime(os.path.join(sc4mp_server_path, "Regions"))
			

class FileTablesManager(th.Thread):


	def __init__(self):

		super().__init__()

		self.filetables = {}


	def run(self):

		try:

			while (not sc4mp_server_running):

				time.sleep(SC4MP_DELAY)

			set_thread_name("FtThread")

			while (sc4mp_server_running):

				try:

					time.sleep(sc4mp_config["PERFORMANCE"]["filetable_update_interval"])
					self.update()

				except Exception as e:

					show_error(e)

		except Exception as e:
	
			fatal_error(e)	
	

	def update(self):

		# Loop through all file tables
		for rootpath, filetable in self.filetables.items():
			
			# Loop through file table and check for missing files and files which have changed size
			for entry in filetable:
				checksum, size, relpath = entry
				fullpath = os.path.join(rootpath, relpath)
				if not os.path.exists(fullpath):
					filetable.remove(entry)
					print(f"Removed deleted file \"{fullpath}\" from file table.")
				elif os.path.getsize(fullpath) != size:
					filetable.remove(entry)
					print(f"Removed old file \"{fullpath}\" from file table.")

			# Get all files in rootpath
			fullpaths = []
			for path, directories, files in os.walk(rootpath):
				for file in files:
					fullpaths.append(os.path.join(path, file))

			# Add new files to the file table
			relpaths = [entry[2] for entry in filetable]
			for fullpath in fullpaths:
				relpath = os.path.relpath(fullpath, rootpath)
				if not relpath in relpaths:
					filetable.append((md5(fullpath), os.path.getsize(fullpath), Path(relpath).as_posix()))
					print(f"Added new file \"{fullpath}\" to file table.")
				

	def generate(self, rootpath):

		print(f"Generating file table for \"{rootpath}\"...")

		fullpaths = []
		for path, directories, files in os.walk(rootpath):
			for file in files:
				fullpaths.append(os.path.join(path, file))

		self.filetables[rootpath] = [(md5(fullpath), os.path.getsize(fullpath), os.path.relpath(fullpath, rootpath)) for fullpath in fullpaths]

		#print(self.filetables[path])

		print("- done.")


	def erase(self, rootpath):

		print(f"Erasing file table for \"{rootpath}\"...")

		self.filetables.pop(rootpath)

		print("- done.")


class RequestHandler(BaseRequestHandler):
	

	def __init__(self, c):
		
		super().__init__(c, private=sc4mp_config["SECURITY"]["private"])


	def run(self):

		try:

			global sc4mp_server_running, sc4mp_request_threads

			set_thread_name("ReqThread")

			try:

				while sc4mp_server_running:

					try:

						self.recv_request()

						print(f"{self.address} - {self.command}")

						self.handle_request()

					except ConnectionClosedException:

						break

			except Exception as e:

				show_error(e)

			sc4mp_request_threads -= 1

		except Exception as e:

			fatal_error(e)


	def authenticate(self):

		version = self.get_header('version', str)
		if unformat_version(version)[:2] < unformat_version(SC4MP_VERSION)[:2]:
			self.error("Incorrect version.")

		if sc4mp_config["SECURITY"]["password_enabled"]:
			password = self.get_header('password', str)
			if password != sc4mp_config["SECURITY"]["password"]:
				self.error("Incorrect password.")

		self.user_id = \
			self.authenticate_user(self.c, self.get_header('user_id', str))


	def authenticate_user(self, c, user_id):

		# Use a hashcode of the user id for extra security
		user_id = hashlib.sha256(user_id.encode()).hexdigest()[:32]

		# Get the ip
		user_ip = c.getpeername()[0]
		
		# Get clients database
		clients_data = sc4mp_clients_database_manager.data
		
		# Get data entry that matches ip
		client_entry = clients_data[user_ip]

		# Check if the client has exceeded the user limit
		if user_id not in client_entry["users"]:
			if (sc4mp_config["SECURITY"]["max_ip_users"] is None or len(client_entry["users"]) < sc4mp_config["SECURITY"]["max_ip_users"]):
				client_entry["users"].append(user_id)
			else:
				self.error("User limit exceeded.")

		# Get users database
		users_data = sc4mp_users_database_manager.data
		
		# Get data entry that matches user id or get & set to {}
		user_entry = users_data.setdefault(user_id, {})

		# Set default values if missing
		user_entry.setdefault("clients", [])
		user_entry.setdefault("mayors", [])
		user_entry.setdefault("ban", False)
		user_entry.setdefault("first_contact", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

		# Close connection and throw error if the user is banned
		if (user_entry["ban"] or client_entry["ban"]): #TODO check for client bans in server loop
			self.error("You are banned from this server.")
		
		# Log the time
		user_entry["last_contact"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

		# Log the IP
		clients_entry = user_entry["clients"]
		if user_ip not in clients_entry:
			clients_entry.append(user_ip)
		
		# Return the user id
		return user_id


	def error(self, message='An error occurred.'):

		self.respond(error=message)

		raise ServerException(message)


	def res_user_id(self):

		in_hash = self.get_header('hash', str)

		# Get database
		data = sc4mp_users_database_manager.data

		# Get the user_id that matches the hash
		found = False
		user_id = None
		for user_id in data:
			try:
				token = data[user_id]["token"]
				if hashlib.sha256((user_id + token).encode()).hexdigest() == in_hash:
					found = True
					break
			except Exception:
				pass

		# Send it if found, otherwise return failure
		if found:
			self.respond(status='success', user_id=user_id)
		else:
			self.respond(status='failure')


	def res_token(self):
		
		user_id = self.user_id

		token = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for i in range(32))

		# Get database
		data = sc4mp_users_database_manager.data

		# Get database entry for user
		key = user_id
		entry = data.get(key, {})
		if entry is None:
			entry = {}
		data[key] = entry

		# Set token in database entry
		entry["token"] = token

		# Send token
		self.respond(token=token)


	def res_plugins_table(self):

		self.respond()
		self.c.send_json(
			get_file_table(os.path.join(sc4mp_server_path, "Plugins"))
		)


	def res_plugins_data(self):

		self.respond()
		send_filestream(self.c, os.path.join(sc4mp_server_path, "Plugins"))


	def res_regions_data(self):

		if sc4mp_regions_manager.regions_modified:
			sc4mp_regions_manager.export_regions = True
			while sc4mp_regions_manager.export_regions:
				time.sleep(SC4MP_DELAY)
			time.sleep(SC4MP_DELAY * 2)

		self.respond()
		send_filestream(self.c, os.path.join(sc4mp_server_path, "_Temp", "outbound", "Regions"))


	def res_regions_table(self):
	
		self.respond()
		self.c.send_json(
			get_file_table(
				os.path.join(sc4mp_server_path, "_Temp", "outbound", "Regions")
			)
		)


	def res_save(self):
		
		c = self.c
		user_id = self.user_id

		self.respond()

		# Receive region name, file sizes
		region, file_sizes = c.recv_json()
		region = sanitize_directory_name(region)
		file_sizes = [int(file_size) for file_size in file_sizes]

		# Enforce max file count and file sizes
		if len(file_sizes) > 17 or max(file_sizes) > 500000000:
			return

		# Set save id
		save_id = sanitize_directory_name(datetime.now().strftime("%Y%m%d%H%M%S") + "_" + user_id)

		# Receive files
		count = 0
		for file_size in file_sizes:

			# Receive file
			path = os.path.join(sc4mp_server_path, "_Temp", "inbound", save_id, region)
			if not os.path.exists(path):
				os.makedirs(path)
			filename = os.path.join(path, str(count) + ".sc4")
			receive_file(c, filename, file_size)

			count += 1

		# Get path to save directory
		path = os.path.join(sc4mp_server_path, "_Temp", "inbound", save_id)

		# Get regions in save directory
		regions = os.listdir(path)

		# Only allow save pushes of one region
		if len(regions) > 1:
			self.respond("Too many regions.")	

		# Loop through regions. Should only loop once since save pushes of multiple regions are filtered out.
		for region in regions:

			# Get region path
			region_path = os.path.join(path, region)

			# Create DBPF objects for each file
			savegames = []
			for filename in os.listdir(region_path):
				filename = os.path.join(region_path, filename)
				savegames.append(SC4Savegame(filename, error_callback=show_error))

			# Extract the region subfile from each DBPF
			for savegame in savegames:
				savegame.get_SC4ReadRegionalCity()
			
			# Filter out tiles that do not border every other tile
			report("Savegame filter 1", self)
			new_savegames = []
			for savegame in savegames:
				add = True
				savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
				savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
				savegameSizeX = savegame.SC4ReadRegionalCity["citySizeX"]
				savegameSizeY = savegame.SC4ReadRegionalCity["citySizeY"]
				for neighbor in savegames:
					if neighbor == savegame:
						continue
					neighborX = neighbor.SC4ReadRegionalCity["tileXLocation"]
					neighborY = neighbor.SC4ReadRegionalCity["tileYLocation"]
					neighborSizeX = neighbor.SC4ReadRegionalCity["citySizeX"]
					neighborSizeY = neighbor.SC4ReadRegionalCity["citySizeY"]
					conditionX1 = (neighborX == savegameX - neighborSizeX)
					conditionX2 = (neighborX == savegameX + savegameSizeX)
					conditionY1 = (neighborY == savegameY - neighborSizeY)
					conditionY2 = (neighborY == savegameY + savegameSizeY)
					conditionX = xor(conditionX1, conditionX2) and ((neighborY + neighborSizeY > savegameY) or (neighborY < savegameY + savegameSizeY))
					conditionY = xor(conditionY1, conditionY2) and ((neighborX + neighborSizeX > savegameX) or (neighborX < savegameX + savegameSizeX))
					condition = xor(conditionX, conditionY)
					if not condition:
						add = False
				if add:
					new_savegames.append(savegame)
					report("YES (" + str(savegameX) + ", " + str(savegameY) + ")", self)
				else:
					report("NO (" + str(savegameX) + ", " + str(savegameY) + ")", self)
			savegames = new_savegames

			# Filter out tiles which have identical date subfiles as their previous versions
			if len(savegames) > 1:
				report("Savegame filter 2", self)
				new_savegames = []
				for savegame in savegames:
					savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
					savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
					coords = str(savegameX) + "_" + str(savegameY)
					data = load_json(os.path.join(sc4mp_server_path, "Regions", region, "_Database", "region.json"))
					if coords in data:
						entry = data[coords]
						date_subfile_hashes = entry["date_subfile_hashes"]
						new_date_subfile_hash = file_md5(savegame.decompress_subfile("2990c1e5"))
						if new_date_subfile_hash not in date_subfile_hashes:
							new_savegames.append(savegame)
							report("YES (" + str(savegameX) + ", " + str(savegameY) + ")", self)
						else:
							report("NO (" + str(savegameX) + ", " + str(savegameY) + ")", self)
					else:
						new_savegames.append(savegame)
						report("YES (" + str(savegameX) + ", " + str(savegameY) + ")", self)
					savegame = None
				savegames = new_savegames
			else:
				report("Skipping savegame filter 2", self)

			# If one savegame remains, pass it to the regions manager, otherwise report to the client that the save push is invalid
			if len(savegames) == 1:

				# Get the savegame
				savegame = savegames[0]

				# Send the task to the regions manager
				sc4mp_regions_manager.tasks.append((save_id, user_id, region, savegame))

				# Wait for the output
				while save_id not in sc4mp_regions_manager.outputs:
					time.sleep(SC4MP_DELAY)

				# Send the output to the client
				self.respond(result=sc4mp_regions_manager.outputs[save_id])

			else:

				# Report to the client that the save push is invalid
				self.respond(result="Unpause the game, then retry.")

			# Delete savegame arrays to avoid file deletion errors
			savegames = None
			new_savegames = None


	def res_add_server(self):
		
		if sc4mp_config["NETWORK"]["discoverable"]:

			host = self.get_header('host', str) or self.c.getpeername()[0]
			port = self.get_header('port', int)

			server = (host, port)

			if len(sc4mp_server_list.server_queue) < sc4mp_server_list.SERVER_LIMIT:
				sc4mp_server_list.server_queue.enqueue(server, left=True) # skip to the front of the queue

			self.respond(status='success')

		else:

			self.error("Server is not discoverable.")


	def res_server_list(self):

		if sc4mp_config["NETWORK"]["discoverable"]:
			self.respond()
		else:
			self.error("Server is not discoverable.")

		server_dict = sc4mp_server_list.servers.copy()
		
		servers = set()
		for server_info in server_dict.values():
			servers.add((server_info["host"], server_info["port"]))

		self.c.send_json(list(servers))


	def res_check_password(self):

		password = self.get_header('password', str)

		if password == sc4mp_config["SECURITY"]["password"]:
			status = 'success'
		else:
			status = 'failure'

		self.respond(status=status)


	def res_loading_background(self):

		background_image_filename = \
			os.path.join(sc4mp_server_path, "background.png")

		if os.path.exists(background_image_filename):
			data = open(background_image_filename, "rb").read()
			self.respond(size=len(data))
			self.c.sendall(data)
		else:
			self.error("Server has no loading background.")


class ServerList(th.Thread):


	class ServerQueue:
		"""
		Queue for server scanning that implements membership check before enqueuing.
		Can optionally enqueue to the front (left) of the queue.
		The queue contains (host, port) tuples.
		"""

		def __init__(self, servers: Iterable[tuple[str,int]]) -> None:
			self._queue = deque(servers)

		def __len__(self):
			return len(self._queue)

		def enqueue(self, server: tuple[str,int], left=False) -> None:
			"""
			Adds a server to the queue, defaulting to the tail end (right).
			left=True adds the server to the front of the queue.
			Servers are only enqueued if they are not already in queue.
			"""
			if server in self._queue:
				return
			if left:
				self._queue.appendleft(server)
				return
			self._queue.append(server)

		def dequeue(self) -> tuple[str,int]:
			"""Gets the server at the front of the queue"""
			return self._queue.popleft()


	def __init__(self):

		super().__init__()

		self.SERVER_LIMIT = 1 + len(SC4MP_SERVERS) + 100 #TODO make configurable

		try:
			self.servers = load_json(os.path.join(sc4mp_server_path, "_Database", "servers.json"))
		except Exception:
			self.servers = {}

		self.servers["root"] = {"host": SC4MP_SERVERS[0][0], "port": SC4MP_SERVERS[0][1]}

		self.server_queue = self.ServerQueue(SC4MP_SERVERS.copy())


	def run(self):

		try:

			# Wait until the server starts
			while not sc4mp_server_running:
				time.sleep(SC4MP_DELAY)

			set_thread_name("SLThread", enumerate=False)

			# Run while the server is running
			while sc4mp_server_running:
				
				# Wait to ping the next server
				time.sleep(random.randint(1,60))

				# Remove servers from the server list if the limit has been reached
				while len(self.servers) > self.SERVER_LIMIT:
					server_id = random.choice(list(self.servers.keys()))
					if (self.servers[server_id]["host"], self.servers[server_id]["port"]) not in SC4MP_SERVERS:
						self.servers.pop(server_id)

				if len(self.server_queue) > 0 or len(self.servers) > 0:

					# Get the next server
					server = None
					if len(self.server_queue) > 0:
						server = self.server_queue.dequeue()
					else:
						server_id = random.choice(list(self.servers.keys()))
						server_entry = self.servers.pop(server_id)
						server = (server_entry["host"], server_entry["port"])
					print("Synchronizing server list with " + server[0] + ":" + str(server[1]) + "...")

					# Ping the next server
					try:

						# Get the server's server id
						server_id = self.request_server_id(server)

						# Skip it if it matches the server id of this server
						if server_id == sc4mp_config["INFO"]["server_id"]:
							#print("- \"" + server_id + "\" is our server_id!")
							continue

						# Resolve server id confilcts
						if server_id in self.servers:
							#print("- \"" + server_id + "\" already found in our server list")
							old_server = (self.servers[server_id]["host"], self.servers[server_id]["port"])

							if server != old_server:
								
								print(f"[WARNING] The server at {server[0]}:{server[1]} is using a server ID, \"{server_id}\", which is already used by {old_server[0]}:{old_server[1]}. Resolving server ID conflict...")
								
								try:
									old_server_id = self.request_server_id(old_server)
								except Exception:
									old_server_id = None

								if old_server_id == server_id:
									print(f"[WARNING] - keeping the old server ({old_server[0]}:{old_server[1]}) and discarding the new one ({server[0]}:{server[1]}).")
								else:
									print(f"[WARNING] - keeping the new server ({server[0]}:{server[1]}) and discarding the old one ({old_server[0]}:{old_server[1]}).")
									self.servers[server_id] = {"host": server[0], "port": server[1]}

						else:
							#print("- adding \"" + server_id + "\" to our server list")
							self.servers[server_id] = {"host": server[0], "port": server[1]}

						# Request to be added to the server's server list
						#print("- requesting to be added to their server list...")
						self.add_server(server)

						# Get the server's server list
						#print("- receiving their server list...")
						self.server_list(server)

						#print("- done.")

					except Exception as e:
						
						#show_error(e)

						print(f"[WARNING] Failed to synchronize server list with {server[0]}:{server[1]}! " + str(e))
				
				# Update database
				#report('Updating "' + os.path.join(sc4mp_server_path, "_Database", "servers.json") + '"...')
				update_json(os.path.join(sc4mp_server_path, "_Database", "servers.json"), self.servers)
				#print("- done.")

		except Exception as e:
			
			show_error(e)


	def create_socket(self, server):

		try:
			s = ClientSocket(server)
			set_headers(s)
			return s
		except Exception as e:
			raise ServerException("Server not found.") from e

	
	def request_server_id(self, server):
		
		SERVER_ID = 'server_id'

		with self.create_socket(server) as s:
			server_id = s.info().get(SERVER_ID)

		if server_id:
			return server_id
		else:
			raise ServerException(f"Headers missing {SERVER_ID!r}")


	def ping(self, server):

		try:
			with self.create_socket(server) as s:
				start = time.time()
				s.ping()
				end = time.time()
				return round(1000 * (end - start))
		except (NetworkException, OSError):
			return None


	def add_server(self, server):

		with self.create_socket(server) as s:
			s.add_server(
				host=sc4mp_config['NETWORK']['domain'],
				port=SC4MP_PORT
			)



	def server_list(self, server):

		with self.create_socket(server) as s:
			server_list = s.server_list()
			for host, port in server_list:
				self.server_queue.enqueue((host, port))


class SystemTrayIconManager(th.Thread):


	def __init__(self):
		
		super().__init__()

		if sc4mp_server_path == "_SC4MP":
			self.helper_batch_directory = os.getcwd()
		else:
			self.helper_batch_directory = sc4mp_server_path

		Menu = pystray.Menu
		Item = pystray.MenuItem
		Icon = pystray.Icon

		# details = []
		# for section in sc4mp_config.data.keys():
		# 	details += [Item(section, None, enabled=False)]
		# 	for key, value in sc4mp_config.data[section].items():
		# 		details += [Item(f"{key}: {value}", None, enabled=False)]
		# 	details += [Item("", None, enabled=False)]
		# details.pop(-1)

		self.server_name = sc4mp_config['INFO']['server_name']

		address = "localhost"
		if sc4mp_config['NETWORK']['host'] != "127.0.0.1":
			public_address = get_public_ip_address(timeout=5)
			if public_address:
				address = public_address

		port = sc4mp_config["NETWORK"]['port']

		if address == "localhost":
			connect = Item("Connect", lambda: self.connect("localhost"))
		else:
			connect = Item("Connect...", Menu(
				Item("Via LAN", lambda: self.connect("localhost")),
				Item("Via internet", lambda: self.connect(address)),
			))

		name = "system_tray_icon"
		icon = Image.open(SC4MP_ICON)
		title = self.server_name
		menu = Menu(
			# Item("Details...", Menu(*details)),
			Item("Actions...", Menu(
				connect,
				# Item("Trigger FATAL ERROR", lambda: fatal_error(Exception())),
				# Item("Update", self.update),
				Item("Restart", self.restart),
				Item("Stop", self.stop),
			)),
			Item("Manage...", Menu(
				Item("Plugins", self.plugins),
				Item("Regions", self.regions),
			)),
			Item("Edit...", Menu(
				Item("Config", self.config),
				# Item("Router settings", self.router),
				# Item("Firewall settings", self.firewall),
			)),
			Item("View...", Menu(
				Item("Logs", self.logs),
				# Item("Invite", self.invite),
				Item("Readme", self.readme),
			)),
			# Item("Help...", Menu(
			# 	Item("Readme", self.readme),
			# )),
		)

		self.icon = Icon(name, icon, title, menu)


	def status(self, status="", notification=""):

		title = self.icon.title

		if notification and self.icon.HAS_NOTIFICATION:
			self.icon.title = self.server_name
			self.icon.notify(notification)
		if status:
			self.icon.title = f"{self.server_name} ({status})"
		else:
			self.icon.title = title


	def error(self, e, notification=""):

		show_error(e)

		if not notification:
			notification = "An error occurred. Please check the logs at \"Documents\\SimCity 4\\SC4MP Server\\sc4mpserver.log\" for more details."

		self.status(notification=notification)


	def run(self):

		try:

			set_thread_name("TrayThread")

			self.icon.run()

		except Exception as e:

			fatal_error(e)


	def restart(self, icon, item):

		try:

			subprocess.Popen([os.path.join(self.helper_batch_directory, "start.bat")])

		except Exception as e:

			self.error(e)
	

	def stop(self, icon, item):

		try:

			subprocess.Popen([os.path.join(self.helper_batch_directory, "stop.bat")])

		except Exception as e:

			fatal_error(e)

	
	def connect(self, address="localhost"):

		try:

			os.startfile(f"sc4mp://{address}:{sc4mp_config['NETWORK']['port']}")

		except Exception as e:

			self.error(e, notification="Unable to connect. Ensure the SC4MP Launcher is installed, then try again.")


	def logs(self, icon, item):

		try:

			logs_bat = os.path.join(self.helper_batch_directory, "logs.bat")

			if int(platform.version().split('.')[0]) >= 10 and os.path.exists(logs_bat):
				os.startfile(logs_bat)
			else:
				os.startfile(SC4MP_LOG_PATH)

		except Exception as e:

			self.error(e)


	def plugins(self, icon, item):

		try:

			self.status(notification="Add plugins by pasting the plugin files here.")

			os.startfile(os.path.join(sc4mp_server_path, "Plugins"))

		except Exception as e:

			self.error(e)


	def regions(self, icon, item):

		try:

			self.status(notification="Add regions by pasting the region folders here. When you're done, restart the server for the changes to take effect.")

			os.startfile(os.path.join(sc4mp_server_path, "Regions"))

		except Exception as e:

			self.error(e)


	def config(self, icon, item):

		try:

			self.status(notification="Edit the server configuration settings here, then restart the server for the changes to take effect.")

			os.startfile(os.path.join(sc4mp_server_path, "serverconfig.ini"))

		except Exception as e:

			self.error(e)


	def invite(self, icon, item):

		try:

			os.startfile(f"https://{SC4MP_INVITES_DOMAIN}/{sc4mp_config['INFO']['server_id']}")

		except Exception as e:

			self.error(e)


	def readme(self, icon, item):

		try:

			os.startfile("Readme.html")

		except Exception as e:

			self.error(e)


	def update(self, icon, item):

		try:

			subprocess.Popen(["update.bat"])

		except Exception as e:

			self.error(e)


	def router(self):

		try:

			# Run 'ipconfig' and capture the output
			output = subprocess.run("ipconfig", capture_output=True, text=True, check=True)

			# Search for 'Default Gateway' in the output
			match = re.search(r"Default Gateway[ .:]+([\d.]+)", output.stdout)
			
			if match:
				router_ip = match.group(1)
				os.startfile(f"http://{router_ip}")
			
		except Exception as e:
			
			self.error(e)
	

	def firewall(self):

		try:

			os.startfile("C:\Windows\system32\WF.msc")
	
		except Exception as e:

			self.error(e)


# Exceptions

class ServerException(Exception):
	


	def __init__(self, message, *args):
		
		super().__init__(args)
		self.message = message
	

	def __str__(self):
		
		return self.message


# Logger

class Logger():
	
	

	def __init__(self):
		
		self.terminal = sys.stdout
		self.log = SC4MP_LOG_PATH if sc4mp_server_path == "_SC4MP" else os.path.join(sc4mp_server_path, SC4MP_LOG_PATH)
		if os.path.exists(self.log):
			os.remove(self.log)
   

	def write(self, message):
		

		output = message

		if message != "\n":

			# Timestamp
			timestamp = datetime.now().strftime("[%H:%M:%S] ")

			# Label
			label = "[SC4MP/" + th.current_thread().getName() + "] "
			for item in inspect.stack()[1:]:
				try:
					label += "(" + item[0].f_locals["self"].__class__.__name__ + ") "
					break
				except Exception:
					pass
			

			# Type and color
			msg_type = "[INFO] "
			color = '\033[90m '
			TYPES_COLORS = [
				("[INFO] ", '\033[90m '), #'\033[94m '
				("[PROMPT]", '\033[01m '),
				("[WARNING] ", '\033[93m '),
				("[ERROR] ", '\033[91m '),
				("[FATAL] ", '\033[91m ')
			]
			for index in range(len(TYPES_COLORS)):
				current_type = TYPES_COLORS[index][0]
				current_color = TYPES_COLORS[index][1]
				if message[:len(current_type)] == current_type:
					message = message[len(current_type):]
					msg_type = current_type
					color = current_color
					break
			if (th.current_thread().getName() == "Main" and msg_type == "[INFO] "):
				color = '\033[00m '
			
			# Assemble
			output = color + timestamp + label + msg_type + message

		# Print
		self.terminal.write(output)
		with open(self.log, "a", encoding='utf-8') as log:
			log.write(output)
			log.close()  


	def flush(self):
		
		self.terminal.flush()


# Main

if __name__ == '__main__':
	main()
