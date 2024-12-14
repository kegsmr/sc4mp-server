from __future__ import annotations

import getpass
import hashlib
import inspect
import json
import os
import random
import shutil
import socket
import string
import struct
import subprocess
import sys
import threading as th
import time
import traceback
from argparse import ArgumentParser, Namespace
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable
import re
import urllib.request

from core.config import *
from core.dbpf import *
from core.networking import *
from core.util import *


# Header

SC4MP_VERSION = "0.7.0"

SC4MP_SERVERS = [("servers.sc4mp.org", port) for port in range(7240, 7250)]

SC4MP_URL = "www.sc4mp.org"
SC4MP_CONTRIBUTORS_URL = "https://github.com/kegsmr/sc4mp-client/contributors/"
SC4MP_ISSUES_URL = "https://github.com/kegsmr/sc4mp-client/issues/"
SC4MP_RELEASES_URL = "https://github.com/kegsmr/sc4mp-client/releases/"

SC4MP_AUTHOR_NAME = "SimCity 4 Multiplayer Project"
SC4MP_WEBSITE_NAME = "www.sc4mp.org"
SC4MP_LICENSE_NAME = "MIT-0"

SC4MP_CONFIG_PATH = None
SC4MP_LOG_PATH = "sc4mpserver.log" #-" + datetime.now().strftime("%Y%m%d%H%M%S") + ".log"
SC4MP_README_PATH = "readme.html"
SC4MP_RESOURCES_PATH = "resources"

SC4MP_TITLE = "SC4MP Server v" + SC4MP_VERSION + (" (x86)" if 8 * struct.calcsize('P') == 32 else "")
SC4MP_ICON = os.path.join(SC4MP_RESOURCES_PATH, "icon.ico")

SC4MP_HOST = None
SC4MP_PORT = None

SC4MP_BUFFER_SIZE = 4096

SC4MP_DELAY = .1

SC4MP_CONFIG_DEFAULTS = [
	("NETWORK", [
		("host", "0.0.0.0"),
		("port", 7240),
		#("domain", None),					#TODO for servers hosted on a DDNS or other specific domain
		("discoverable", True),
	]),
	("INFO", [
		("server_id", ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for i in range(32))),
		("server_name", getpass.getuser() + " on " + socket.gethostname()),
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

SC4MP_SERVER_ID = None
SC4MP_SERVER_NAME = None
SC4MP_SERVER_DESCRIPTION = None

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

	parser.add_argument("-k", "--skip-update", help="skip the update check at startup", action="store_true")

	parser.add_argument("-u", "--force-update", help="force update at startup", action="store_true")

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

	Arguments:
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
	"""TODO"""
	hash_md5 = hashlib.md5()
	for chunk in iter(lambda: file.read(4096), b""):
		hash_md5.update(chunk)
	return hash_md5.hexdigest()


def create_empty_json(filename):
	"""TODO"""
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


def set_savegame_data(entry, savegame):
	"""TODO entry values"""

	# No overwrite
	entry.setdefault("owner", None)
	entry.setdefault("modified", None)
	entry.setdefault("locked", False)
	entry.setdefault("filename", os.path.basename(os.path.normpath(savegame.filename)))
	entry.setdefault("reset_filename", None)
	entry.setdefault("date_subfile_hashes", [])

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

	# Log mayor name
	if sc4mp_server_running:
		owner = entry["owner"]
		if owner is not None and not entry.get("reclaimed", False):
			mayor_name = entry["mayor_name"]
			mayor_names = sc4mp_users_database_manager.data[owner]["mayors"]
			if mayor_name not in mayor_names:
				mayor_names.append(mayor_name)


def update_json(filename, data):
	"""TODO"""
	with open(filename, 'w') as file:
		file.seek(0)
		json.dump(data, file, indent=4)
		file.truncate()


def package_plugins_and_regions():
	"""TODO"""

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
	"""TODO"""

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
	"""TODO"""

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
									print(f"[WARNING] - resetting claim...")
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
			raise ServerException('Failed to delete "' + file_path + '" because the file is being used by another process.') #\n\n' + str(e)


def send_filestream(c, rootpath):
	"""TODO"""

	# Loop through all files in path and append them to a list
	#fullpaths = []
	#for path, directories, files in os.walk(rootpath):
	#	for file in files:
	#		fullpaths.append(os.path.join(path, file))

	# Get fullpaths to files in rootpath
	#fullpaths = rootpath.rglob("*")

	# Get file table
	while sc4mp_server_running:
		try:
			filetable = sc4mp_filetables_manager.filetables[rootpath]
			break
		except KeyError:
			print("[WARNING] Waiting for file table to generate...")
			time.sleep(SC4MP_DELAY * 10)

	#filetable = [(md5(fullpath), os.path.getsize(fullpath), os.path.relpath(fullpath, rootpath)) for fullpath in fullpaths]

	# Send the file table to the client
	send_json(c, filetable)

	# Receive the modified filetable from the client and verify it
	ft = [tuple(item) for item in recv_json(c)]
	for item in ft:
		if not item in filetable:
			c.close()
	filetable = ft

	# Loop through the filetable and send the respective data
	for checksum, size, relpath in filetable:
		with open(os.path.join(rootpath, relpath), "rb") as file:
			size_read = 0
			while True:
				size_remaining = size - size_read
				buffer_size = SC4MP_BUFFER_SIZE if size_remaining > SC4MP_BUFFER_SIZE else size_remaining
				data = file.read(buffer_size)
				if not data:
					break
				size_read += len(data)
				c.sendall(data)


def send_tree(c, rootpath):
	"""TODO"""

	# Loop through all files in path and append them to a list
	fullpaths = []
	for path, directories, files in os.walk(rootpath):
		for file in files:
			fullpaths.append(os.path.join(path, file))

	# Send file count
	c.sendall(str(len(fullpaths)).encode())

	# Separator
	c.recv(SC4MP_BUFFER_SIZE)

	# Send size
	size = 0
	for fullpath in fullpaths:
		size += os.path.getsize(fullpath)
	c.sendall(str(size).encode())

	# Loop through the file list and send each one to the client
	for fullpath in fullpaths:

		# Separator
		c.recv(SC4MP_BUFFER_SIZE)

		# Get relative path to file 
		relpath = os.path.relpath(fullpath, rootpath)

		# Send hashcode
		c.sendall(md5(fullpath).encode())

		# Separator
		c.recv(SC4MP_BUFFER_SIZE)

		# Send filesize
		c.sendall(str(os.path.getsize(fullpath)).encode())

		# Separator
		c.recv(SC4MP_BUFFER_SIZE)

		# Send relative path
		c.sendall(relpath.encode())

		# Send the file if not cached
		if c.recv(SC4MP_BUFFER_SIZE).decode() != "y":
			with open(fullpath, "rb") as file:
				while True:
					bytes_read = file.read(SC4MP_BUFFER_SIZE)
					if not bytes_read:
						break
					c.sendall(bytes_read)


def send_or_cached(c, filename):
	"""TODO"""
	c.sendall(md5(filename).encode())
	if c.recv(SC4MP_BUFFER_SIZE).decode() == "n":
		send_file(c, filename)
	else:
		c.close()


def send_file(c, filename):
	"""TODO"""

	report("Sending file " + filename + "...")

	filesize = os.path.getsize(filename)
	c.sendall(str(filesize).encode())

	with open(filename, "rb") as f:
		while True:
			bytes_read = f.read(SC4MP_BUFFER_SIZE)
			if not bytes_read:
				break
			c.sendall(bytes_read)


def receive_file(c, filename, filesize):
	"""TODO"""

	#if (filesize is None):
	#
	#	filesize = int(c.recv(SC4MP_BUFFER_SIZE).decode())
	#
	#	c.sendall(SC4MP_SEPARATOR)

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
	"""TODO"""
	'''color = '\033[94m '
	output = datetime.now().strftime("[%H:%M:%S] [SC4MP")
	obj = None
	for item in inspect.stack():
		if (obj != None):
			break
		try:
			obj = item[0].f_locals["self"]
		except:
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
	"""TODO"""

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
	"""TODO"""
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
	"""TODO"""
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
	"""TODO"""

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
	#sys.exit()


def set_savegame_filename(savegameX, savegameY, savegameCityName, savegameMayorName, savegameModeFlag):

	prefix = f"({savegameX:0>{3}}-{savegameY:0>{3}})"

	if savegameModeFlag == 0:

		return f"{prefix} - (Empty).sc4"
	
	else:

		city_name = filter_non_alpha_numeric(savegameCityName)
		if len(city_name) < 1:
			city_name = "New City"

		mayor_name = filter_non_alpha_numeric(savegameMayorName)
		if len(mayor_name) < 1:
			mayor_name = "Defacto"
		
		return f"{prefix} - {city_name} - {mayor_name}"[:252] + ".sc4"


def filter_non_alpha_numeric(text):
	return " ".join(re.sub('[^0-9a-zA-Z ]+', " ", text).split())


# Workers

class Server(th.Thread):
	"""TODO"""


	def __init__(self):
		"""TODO"""

		super().__init__()

		self.BIND_RETRY_DELAY = 5

		#self.check_version() #TODO
		#TODO lock server directory
		self.create_subdirectories()
		self.load_config()
		self.check_updates()
		self.prep_database()
		self.clear_temp()
		self.prep_filetables()
		self.prep_regions() 
		self.prep_backups()
		self.prep_server_list()

	
	def run(self):
		"""TODO"""

		try:

			global sc4mp_server_running, sc4mp_request_threads

			report("Starting server...")

			report("- creating socket...")
			s = socket.socket()

			report("- binding host " + SC4MP_HOST + " and port " + str(SC4MP_PORT) + "...")
			while True:
				try:
					s.bind((SC4MP_HOST, SC4MP_PORT))
					break
				except OSError as e:
					show_error(e)
					print(f"[WARNING] - failed to bind socket, retrying in {self.BIND_RETRY_DELAY} seconds...")
					time.sleep(self.BIND_RETRY_DELAY)

			report("- listening for connections...")
			s.listen(5)
			
			sc4mp_server_running = True

			try:

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

							report("Connection accepted with " + str(host) + ":" + str(port) + ".")

							self.log_client(c)

							sc4mp_request_threads += 1

							RequestHandler(c).start()	

						except Exception as e: #socket.error as e:

							show_error(e)
				
					else:

						print("[WARNING] Request thread limit reached!")

						while not (sc4mp_request_threads < max_request_threads):
							time.sleep(SC4MP_DELAY)
				
			except (SystemExit, KeyboardInterrupt) as e:

				pass

			while True:
				try:
					report("Shutting down...")
					sc4mp_server_running = False
					break
				except:
					time.sleep(SC4MP_DELAY)

		except Exception as e:

			fatal_error(e)


	def log_client(self, c):
		"""TODO"""

		# Get ip
		ip = c.getpeername()[0]

		# Get clients database
		clients_data = sc4mp_clients_database_manager.data
		
		# Get data entry that matches ip
		client_entry = None
		try:
			client_entry = clients_data[ip]
		except:
			client_entry = {}
			clients_data[ip] = client_entry

		# Set values
		client_entry.setdefault("users", [])
		client_entry.setdefault("ban", False)
		client_entry.setdefault("first_contact", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
		client_entry["last_contact"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


	def create_subdirectories(self):
		"""TODO"""

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
			if exec_file == "sc4mpserver.exe":
				with open("logs.bat" if sc4mp_server_path == "_SC4MP" else os.path.join(sc4mp_server_path, "logs.bat"), "w") as batch_file:
					batch_file.writelines([
						f"@echo off\n",
						(f"title {SC4MP_TITLE}\n" if sc4mp_server_path == "_SC4MP" else f"title {SC4MP_TITLE} - {sc4mp_server_path}\n"),
						f"PowerShell -NoProfile -ExecutionPolicy Bypass -Command \"gc sc4mpserver.log -wait -tail 1000\"\n",
					])
				with open(os.path.join(sc4mp_server_path, "run.bat"), "w") as batch_file:
					batch_file.writelines([
						f"@echo off\n",
						f"cd \"{exec_dir}\"\n",
						f"sc4mpserver.exe -s \"{sc4mp_server_path}\"\n",
					])
				with open(os.path.join(sc4mp_server_path, "prep.bat"), "w") as batch_file:
					batch_file.writelines([
						f"@echo off\n",
						f"cd \"{exec_dir}\"\n",
						f"sc4mpserver.exe -s \"{sc4mp_server_path}\" --prep\n",
					])
				with open(os.path.join(sc4mp_server_path, "restore.bat"), "w") as batch_file:
					batch_file.writelines([
						f"@echo off\n",
						f"cd \"{exec_dir}\"\n",
						f"set /p backup=\"Enter a backup to restore...\"\n",
						f"sc4mpserver.exe -s \"{sc4mp_server_path}\" --restore %backup%\n",
					])
		except Exception as e:
			show_error(f"Failed to create helper batch files.\n\n{e}")


	def load_config(self):
		"""TODO"""

		global sc4mp_config, SC4MP_CONFIG_PATH
		SC4MP_CONFIG_PATH = os.path.join(sc4mp_server_path, "serverconfig.ini")

		report("Loading config...")
		
		sc4mp_config = Config(SC4MP_CONFIG_PATH, SC4MP_CONFIG_DEFAULTS, error_callback=show_error, update_constants_callback=update_config_constants)

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

		except:

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
						with urllib.request.urlopen(f"https://api.github.com/repos/kegsmr/sc4mp-server/releases/latest", timeout=10) as url:
							latest_release_info = json.load(url)
					except urllib.error.URLError:
						raise ServerException("GitHub API call timed out.")

					# Download the update if the version doesn't match
					if sc4mp_force_update or latest_release_info["tag_name"] != f"v{SC4MP_VERSION}":

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
								except:
									pass

								# Delete uninstaller if exists
								try:
									for filename in ["unins000.dat", "unins000.exe"]:
										if os.path.exists(filename):
											os.unlink(filename)
								except:
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
										f"@echo off\n",
										f"cd \"{os.getcwd()}\"\n",
										f"echo Running installer...\n",
										f"cd {destination.parent}\n",
										f"{destination.stem} /dir=\"{os.getcwd()}\" /verysilent\n",
										f"cd ..\n",
										f"echo Relaunching server...\n",
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
		"""TODO"""

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
			except:
				data = {}
			
			# Get savegame paths
			savegame_paths = []
			items = os.listdir(region_directory)
			for item in items:
				path = os.path.join(region_directory, item)
				if (os.path.isfile(path) and path[-4:] == ".sc4"):
					savegame_paths.append(path)

			# Open savegames as DBPF objects
			savegames = []
			for savegame_path in savegame_paths:
				savegames.append(SC4Savegame(savegame_path, error_callback=show_error))

			# Get the region subfile of each DBPF object and update the database
			for savegame in savegames:

				# Get region subfile
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
				if entry["filename"] != new_filename:
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
		"""TODO"""

		report("Clearing temporary files...")

		try:
			purge_directory(os.path.join(sc4mp_server_path, "_Temp"))
		except Exception as e:
			show_error(e)


	def prep_regions(self):
		"""TODO"""

		if sc4mp_nostart:
			return

		report("Preparing regions...")

		export("regions")

		# Regions manager
		global sc4mp_regions_manager
		sc4mp_regions_manager = RegionsManager()
		sc4mp_regions_manager.start()


	def prep_backups(self):
		"""TODO"""

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
		"""TODO"""

		if sc4mp_nostart:
			return

		if not sc4mp_config["NETWORK"]["discoverable"]:
			return

		report("Preparing server list...")

		global sc4mp_server_list
		sc4mp_server_list = ServerList()
		sc4mp_server_list.start()


class BackupsManager(th.Thread):
	"""TODO"""


	def __init__(self):
		"""TODO"""

		self.backup_dir = Path(sc4mp_server_path) / "_Backups"
		super().__init__()


	def run(self):
		"""TODO"""

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
		"""TODO"""
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except:
			return {}


	def update_json(self, filename, data):
		"""TODO"""
		with open(filename, 'w') as file:
			file.seek(0)
			json.dump(data, file, indent=4)
			file.truncate()


	def backup(self): #TODO stop backing up the backups subdirectory
		"""TODO"""

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
	"""TODO"""

	
	def __init__(self, filename):
		"""TODO"""

		super().__init__()
	
		self.filename = filename #os.path.join(sc4mp_server_path, "_Database", "users.json")
		self.data = self.load_json(self.filename)


	def run(self):
		"""TODO"""
	
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
		"""TODO"""
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except:
			return {}

	
	def update_json(self, filename, data):
		"""TODO"""
		with open(filename, 'w') as file:
			file.seek(0)
			json.dump(data, file, indent=4)
			file.truncate()


class RegionsManager(th.Thread):
	"""TODO"""

	
	def __init__(self):
		"""TODO"""

		super().__init__()

		self.regions_modified = False
		self.export_regions = False
		self.tasks = []
		self.outputs = {}
		#self.lastmtime = self.get_mtime()


	def run(self):
		"""TODO"""

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
									if "filename" in entry:
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
									except:
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
									entry["reclaimed"] = reclaimed
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
		"""TODO"""
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except:
			return {}

	
	def update_json(self, filename, data):
		"""TODO"""
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
					filetable.append((md5(fullpath), os.path.getsize(fullpath), relpath))
					print(f"Added new file \"{fullpath}\" to file table.")
				

	def generate(self, rootpath):

		print(f"Generating file table for \"{rootpath}\"...")

		fullpaths = []
		for path, directories, files in os.walk(rootpath):
			for file in files:
				fullpaths.append(os.path.join(path, file))

		self.filetables[rootpath] = [(md5(fullpath), os.path.getsize(fullpath), os.path.relpath(fullpath, rootpath)) for fullpath in fullpaths]

		#print(self.filetables[path])

		print(f"- done.")


	def erase(self, rootpath):

		print(f"Erasing file table for \"{rootpath}\"...")

		self.filetables.pop(rootpath)

		print(f"- done.")


class RequestHandler(th.Thread):
	"""TODO"""


	def __init__(self, c):
		"""TODO"""

		super().__init__()
		
		self.c = c


	def run(self):
		"""TODO"""

		try:

			global sc4mp_server_running, sc4mp_request_threads

			set_thread_name("ReqThread")

			try:

				c = self.c

				args = c.recv(SC4MP_BUFFER_SIZE).decode().split(" ")

				request = args[0]

				report("Request: " + request, self)

				if request == "ping":
					self.ping(c)
				elif request == "server_id":
					self.send_server_id(c)
				elif request == "server_name":
					self.send_server_name(c)
				elif request == "server_description":
					self.send_server_description(c)
				elif request == "server_url":
					self.send_server_url(c)
				elif request == "server_version":
					self.send_server_version(c)
				elif request == "user_id":
					self.send_user_id(c, args[1])
				elif request == "token":
					self.request_header(c, args)
					self.send_token(c)
				elif request == "plugins":
					if sc4mp_config["SECURITY"]["private"]:
						self.request_header(c, args)
					self.send_plugins(c)
				elif request == "regions":
					if sc4mp_config["SECURITY"]["private"]:
						self.request_header(c, args)
					self.send_regions(c)
				elif request == "save":
					self.request_header(c, args)
					self.save(c)
				elif request == "add_server":
					try:
						self.add_server(c, args[1])
					except IndexError as e:
						print("[WARNING] Unable to add outdated server to server list")
				elif request == "server_list":
					self.server_list(c)
				elif request == "password_enabled":
					self.password_enabled(c)
				elif request == "check_password":
					self.check_password(c, " ".join(args[1:]))
				elif request == "user_plugins_enabled":
					self.user_plugins_enabled(c)
				elif request == "private":
					self.private(c)
				elif request == "time":
					c.sendall(datetime.now().strftime("%Y-%m-%d %H:%M:%S").encode())
				elif request == "info":
					send_json(c, {  
						"server_id": sc4mp_config["INFO"]["server_id"],  
						"server_name": sc4mp_config["INFO"]["server_name"],
						"server_description": sc4mp_config["INFO"]["server_description"],
						"server_url": sc4mp_config["INFO"]["server_url"],
						"server_version": SC4MP_VERSION,
						"private": sc4mp_config["SECURITY"]["private"],
						"password_enabled": sc4mp_config["SECURITY"]["password_enabled"],
						"user_plugins_enabled": sc4mp_config["RULES"]["user_plugins"],
					})
				else:
					print(f"[WARNING] Invalid request!") # (\"{request}\")!")

				c.close()
			
				#report("- connection closed.", self)

			except Exception as e:

				show_error(e)

			sc4mp_request_threads -= 1

		except Exception as e:

			fatal_error(e)


	def request_header(self, c, args):
		"""TODO"""

		if unformat_version(args[1])[:2] < unformat_version(SC4MP_VERSION)[:2]:
			c.close()
			raise ServerException("Invalid version.")

		if sc4mp_config["SECURITY"]["password_enabled"]:
			if " ".join(args[3:]) != sc4mp_config["SECURITY"]["password"]:
				c.close()
				raise ServerException("Incorrect password.")

		self.user_id = self.log_user(c, args[2])


	def ping(self, c):
		"""TODO"""
		c.sendall(b"pong")


	def send_server_id(self, c):
		"""TODO"""
		c.sendall(SC4MP_SERVER_ID.encode())


	def send_server_name(self, c):
		"""TODO"""
		c.sendall(SC4MP_SERVER_NAME.encode())


	def send_server_description(self, c):
		"""TODO"""
		c.sendall(SC4MP_SERVER_DESCRIPTION.encode())


	def send_server_url(self, c):
		"""TODO"""
		c.sendall(sc4mp_config["INFO"]["server_url"].encode())


	def send_server_version(self, c):
		"""TODO"""
		c.sendall(SC4MP_VERSION.encode())


	def send_user_id(self, c, in_hash):
		"""TODO"""

		# Get database
		data = sc4mp_users_database_manager.data

		# Send the user_id that matches the hash
		for user_id in data:
			try:
				token = data[user_id]["token"]
				if hashlib.sha256((user_id + token).encode()).hexdigest() == in_hash:
					c.sendall(user_id.encode())
					break
			except:
				pass


	def send_token(self, c):
		"""TODO"""
		
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
		c.sendall(token.encode())


	def send_plugins(self, c):
		"""TODO"""

		#filename = os.path.join(sc4mp_server_path, os.path.join("_Temp", os.path.join("outbound", "Plugins.zip")))
		#send_or_cached(c, filename)

		send_filestream(c, os.path.join(sc4mp_server_path, "Plugins"))
		#send_tree(c, os.path.join(sc4mp_server_path, "Plugins"))


	def send_regions(self, c):
		"""TODO"""

		if sc4mp_regions_manager.regions_modified:
			sc4mp_regions_manager.export_regions = True
			while sc4mp_regions_manager.export_regions:
				time.sleep(SC4MP_DELAY)
			time.sleep(SC4MP_DELAY * 2)

		#filename = os.path.join(sc4mp_server_path, os.path.join("_Temp", os.path.join("outbound", "Regions.zip")))
		#send_or_cached(c, filename)

		send_filestream(c, os.path.join(sc4mp_server_path, "_Temp", "outbound", "Regions"))
		#send_tree(c, os.path.join(sc4mp_server_path, "_Temp", "outbound", "Regions"))


	'''def delete(self, c):
		"""TODO"""

		c.sendall(SC4MP_SEPARATOR)

		user_id = self.log_user(c)
		c.sendall(SC4MP_SEPARATOR)
		region = c.recv(SC4MP_BUFFER_SIZE).decode()
		c.sendall(SC4MP_SEPARATOR)
		city = c.recv(SC4MP_BUFFER_SIZE).decode()

		c.sendall(SC4MP_SEPARATOR) #TODO verify that the user can make the deletion

		#TODO only delete file if user is authorized

		filename = os.path.join(sc4mp_server_path, os.path.join("Regions", os.path.join(region, city)))

		os.remove(filename)'''


	def save(self, c):
		"""TODO"""
		
		user_id = self.user_id

		# Separator
		c.sendall(b"ok")

		# Receive region name, file sizes
		region, file_sizes = recv_json(c)
		file_sizes = [int(file_size) for file_size in file_sizes]

		# Separator
		c.sendall(b"ok")

		# Set save id
		save_id = datetime.now().strftime("%Y%m%d%H%M%S") + "_" + user_id

		# Receive files
		count = 0
		for file_size in file_sizes:

			# Receive region name
			#region = c.recv(SC4MP_BUFFER_SIZE).decode()
			#.sendall(b"ok")

			# Receive city name
			#city = c.recv(SC4MP_BUFFER_SIZE).decode()
			#c.sendall(b"ok")

			# Receive file
			path = os.path.join(sc4mp_server_path, "_Temp", "inbound", save_id, region)
			if not os.path.exists(path):
				os.makedirs(path)
			filename = os.path.join(path, str(count) + ".sc4")
			receive_file(c, filename, file_size)

			count += 1

			#c.sendall(b"ok")

		# Separator
		#c.sendall(b"ok")
		#c.recv(SC4MP_BUFFER_SIZE)

		# Get path to save directory
		path = os.path.join(sc4mp_server_path, "_Temp", "inbound", save_id)

		# Get regions in save directory
		regions = os.listdir(path)

		# Only allow save pushes of one region
		if len(regions) > 1:
			c.sendall(b"Too many regions.")
			return		

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
				c.sendall((sc4mp_regions_manager.outputs[save_id]).encode())

			else:

				# Report to the client that the save push is invalid
				c.sendall(b"Unpause the game, then retry.")

			# Delete savegame arrays to avoid file deletion errors
			savegames = None
			new_savegames = None

		# Try to delete temporary files
		#try:
		#	shutil.rmtree(path)
		#except:
		#	pass


	def add_server(self, c, port):
		"""TODO"""
		if not sc4mp_config["NETWORK"]["discoverable"]:
			return
		host = c.getpeername()[0]
		port = int(port)
		server = (host, port)
		if len(sc4mp_server_list.server_queue) < sc4mp_server_list.SERVER_LIMIT:
			sc4mp_server_list.server_queue.enqueue(server, left=True) # skip to the front of the queue


	def server_list(self, c):
		"""TODO"""

		if not sc4mp_config["NETWORK"]["discoverable"]:
			return
		
		server_dict = sc4mp_server_list.servers.copy()
		
		servers = set()
		for server_info in server_dict.values():
			servers.add((server_info["host"], server_info["port"]))

		send_json(c, list(servers))


	def log_user(self, c, user_id):
		"""TODO"""

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
				c.close()
				raise ServerException("Authentication error.")

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
			c.close()
			raise ServerException("Authentication error.")
		
		# Log the time
		user_entry["last_contact"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

		# Log the IP
		clients_entry = user_entry["clients"]
		if user_ip not in clients_entry:
			clients_entry.append(user_ip)
		
		# Return the user id
		return user_id


	def password_enabled(self, c):
		"""TODO"""
		if sc4mp_config['SECURITY']['password_enabled']:
			c.sendall(b"y")
		else:
			c.sendall(b"n")


	def check_password(self, c, password):
		"""TODO"""
		if password == sc4mp_config["SECURITY"]["password"]:
			c.sendall(b'y')
		else:
			c.sendall(b'n')


	def user_plugins_enabled(self, c):
		"""TODO"""
		if sc4mp_config['RULES']['user_plugins']:
			c.sendall(b"y")
		else:
			c.sendall(b"n")


	def private(self, c):
		"""TODO"""
		if sc4mp_config['SECURITY']['private']:
			c.sendall(b"y")
		else:
			c.sendall(b"n")


	def refresh(self, c):
		"""TODO"""

		user_id = self.user_id

		# Loop through regions
		regions_directory = os.path.join(sc4mp_server_path, "Regions")
		for region in os.listdir(regions_directory):
			if os.path.isdir(os.path.join(regions_directory, region)):
				#print(region)
				region_data = load_json(os.path.join(sc4mp_server_path, "Regions", region, "_Database", "region.json"))
				for city_entry in region_data.values():
					if (city_entry is not None and city_entry["owner"] != user_id):
						c.sendall(city_entry["hashcode"].encode())
						if c.recv(SC4MP_BUFFER_SIZE).decode() == "missing":
							c.sendall(region.encode())
							c.recv(SC4MP_BUFFER_SIZE)
							send_file(c, os.path.join(sc4mp_server_path, "Regions", region, city_entry["filename"]))
							c.recv(SC4MP_BUFFER_SIZE)
		c.sendall(b'done')


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


class ServerList(th.Thread):


	def __init__(self):

		super().__init__()

		self.SERVER_LIMIT = 1 + len(SC4MP_SERVERS) + 100 #TODO make configurable

		try:
			self.servers = load_json(os.path.join(sc4mp_server_path, "_Database", "servers.json"))
		except:
			self.servers = {}

		self.servers["root"] = {"host": SC4MP_SERVERS[0][0], "port": SC4MP_SERVERS[0][1]}

		self.server_queue = ServerQueue(SC4MP_SERVERS.copy())


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
								except:
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
		"""TODO"""
		host = server[0]
		port = server[1]
		try:
			s = socket.socket()
			s.settimeout(10)
			s.connect((host, port))
			return s
		except:
			raise ServerException("Server not found.")

	
	def request_server_id(self, server):
		"""TODO"""
		s = self.create_socket(server)
		s.sendall(b"server_id")
		return s.recv(SC4MP_BUFFER_SIZE).decode()


	def ping(self, server):
		"""TODO"""
		s = self.create_socket(server)
		try:
			start = time.time()
			s.sendall(b"ping")
			s.recv(SC4MP_BUFFER_SIZE)
			end = time.time()
			s.close()
			return round(1000 * (end - start))
		except socket.error as e:
			return None


	def add_server(self, server):
		"""TODO"""
		s = self.create_socket(server)
		s.sendall(b"add_server " + str(SC4MP_PORT).encode())


	def server_list(self, server):
		"""TODO"""
		s = self.create_socket(server)
		s.sendall(b"server_list")
		servers = recv_json(s)
		try:
			for host, port in servers:
				self.server_queue.enqueue((host, port))
		except TypeError as e:
			raise ServerException("Unable to receive server list from outdated server")


# Exceptions

class ServerException(Exception):
	"""TODO"""


	def __init__(self, message, *args):
		"""TODO"""
		super().__init__(args)
		self.message = message
	

	def __str__(self):
		"""TODO"""
		return self.message


# Logger

class Logger():
	"""TODO"""
	

	def __init__(self):
		"""TODO"""
		self.terminal = sys.stdout
		self.log = SC4MP_LOG_PATH if sc4mp_server_path == "_SC4MP" else os.path.join(sc4mp_server_path, SC4MP_LOG_PATH)
		if os.path.exists(self.log):
			os.remove(self.log)
   

	def write(self, message):
		"""TODO"""

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
				except:
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
		with open(self.log, "a") as log:
			log.write(output)
			log.close()  


	def flush(self):
		"""TODO"""
		self.terminal.flush()


# Main

if __name__ == '__main__':
	main()
