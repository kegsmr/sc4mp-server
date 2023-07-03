import configparser
import hashlib
import inspect
import io
import json
import os
import random
import shutil
import socket
import string
import struct
import sys
import threading as th
import time
import traceback
from datetime import datetime, timedelta

SC4MP_VERSION = (0,1,0)

SC4MP_SERVERS = [("servers.sc4mp.org", 7240)]

SC4MP_URL = "https://sc4mp.org/"
SC4MP_RELEASES_URL = "https://github.com/keggre/sc4mp-client/releases/"

SC4MP_CONFIG_PATH = None
SC4MP_LOG_PATH = "sc4mpserver-" + datetime.now().strftime("%Y%m%d%H%M%S") + ".log"
SC4MP_RESOURCES_PATH = "resources"

SC4MP_TITLE = "SC4MP Server v" + str(SC4MP_VERSION[0]) + "." + str(SC4MP_VERSION[1]) + "." + str(SC4MP_VERSION[2])
SC4MP_ICON = os.path.join(SC4MP_RESOURCES_PATH, "icon.ico")

SC4MP_SEPARATOR = b"<SEPARATOR>"
SC4MP_BUFFER_SIZE = 4096

SC4MP_DELAY = .1

SC4MP_CONFIG_DEFAULTS = [
	("NETWORK", [
		("host", "0.0.0.0"),
		("port", 7240),
		#("discoverable", True), #TODO
	]),
	("INFO", [
		("server_id", ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for i in range(32))),
		("server_name", os.getlogin() + " on " + socket.gethostname()),
		("server_description", "Join and build your city.\n\nRules:\n- Feed the llamas\n- Balance your budget\n- Do uncle Vinny some favors"),
	]),
	("SECURITY", [
		("password_enabled", False),
		("password", "maxis2003"),
		("max_ip_users", 3),
	]),
	("RULES", [
		("claim_duration", 30),
		("claim_delay", 60),
		("max_region_claims", 1),
		#("max_total_claims", None), #TODO
		("godmode_filter", True),
		("user_plugins", False),
	]),
	("PERFORMANCE", [
		("request_limit", 20),
		("max_request_threads", 100),
	]),
	("BACKUPS", [
		("server_backup_interval", 24),
		("backup_server_on_startup", True),
		("max_server_backups", 720),
		("max_savegame_backups", 10),
	])
]

SC4MP_HOST = None
SC4MP_PORT = None
SC4MP_SERVER_ID = None
SC4MP_SERVER_NAME = None
SC4MP_SERVER_DESCRIPTION = None

sc4mp_args = sys.argv

sc4mp_server_path = "_SC4MP"

sc4mp_server_running = False

sc4mp_request_threads = 0


# Methods

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


'''def string_md5(text):
	"""TODO"""
	return hashlib.md5(text.encode()).hexdigest()'''


def file_md5(file):
	"""TODO"""
	hash_md5 = hashlib.md5()
	for chunk in iter(lambda: file.read(4096), b""):
		hash_md5.update(chunk)
	return hash_md5.hexdigest()


def create_empty_json(filename):
	"""TODO"""
	with open(filename, 'w') as file:
		data = dict()
		file.seek(0)
		json.dump(data, file, indent=4)
		file.truncate()


def load_json(filename):
	"""TODO"""
	with open(filename, 'r') as file:
		return json.load(file)


def set_savegame_data(entry, savegame):
	"""TODO entry values"""

	# No overwrite
	entry.setdefault("filename", os.path.basename(os.path.normpath(savegame.filename)))
	entry.setdefault("owner", None)
	entry.setdefault("modified", None)
	entry.setdefault("reset_filename", None)
	entry.setdefault("date_subfile_hashes", [])

	# Append
	entry["date_subfile_hashes"].append(file_md5(savegame.decompress_subfile("2990c1e5")))

	# Overwrite
	entry["hashcode"] = md5(savegame.filename)
	entry["size"] = savegame.SC4ReadRegionalCity["citySizeX"] 
	entry["gamemode"] = savegame.SC4ReadRegionalCity["modeFlag"]
	entry["difficulty"] = savegame.SC4ReadRegionalCity["starCount"]
	entry["mayor_rating"] = savegame.SC4ReadRegionalCity["mayorRating"]
	entry["residential_population"] = savegame.SC4ReadRegionalCity["residentialPopulation"]
	entry["commercial_population"] = savegame.SC4ReadRegionalCity["commercialPopulation"]
	entry["industrial_population"] = savegame.SC4ReadRegionalCity["industrialPopulation"]
	entry["population"] = entry["residential_population"] + entry["commercial_population"] + entry["industrial_population"]
	entry["population_density"] = round(entry["population"] / (entry["size"] * entry["size"]))
	entry["residential_population_density"] = round(entry["residential_population"] / (entry["size"] * entry["size"]))


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


def package(type):
	"""TODO"""

	directory = None
	if (type == "plugins"):
		directory = "Plugins"
	elif (type == "regions"):
		directory = "Regions"

	target = os.path.join(sc4mp_server_path, directory)
	destination = os.path.join(sc4mp_server_path, "_Temp", "outbound", directory)

	if (os.path.exists(destination)):
		os.remove(destination)

	shutil.make_archive(destination, "zip", target)


def export(type):
	"""TODO"""

	# Select directory name from input
	directory = None
	if (type == "plugins"):
		directory = "Plugins"
	elif (type == "regions"):
		directory = "Regions"

	# Set target and destination directories
	target = os.path.join(sc4mp_server_path, directory)
	destination = os.path.join(sc4mp_server_path, "_Temp", "outbound", directory)

	# Delete destination directory if it exists 
	if (os.path.exists(destination)):
		shutil.rmtree(destination)
	
	# Create the parent directories if they do not yet exist
	#if (not os.path.exists(destination)):
	#	os.makedirs(destination)
	
	# Copy recursively
	shutil.copytree(target, destination, ignore=shutil.ignore_patterns('_Backups', '_Database'))	


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
			raise CustomException('Failed to delete "' + file_path + '" because the file is being used by another process.') #\n\n' + str(e)


def send_tree(c, rootpath):
	"""TODO"""

	# Loop through all files in path and append them to a list
	fullpaths = []
	for path, directories, files in os.walk(rootpath):
		for file in files:
			fullpaths.append(os.path.join(path, file))

	# Send file count
	c.send(str(len(fullpaths)).encode())

	# Separator
	c.recv(SC4MP_BUFFER_SIZE)

	# Send size
	size = 0
	for fullpath in fullpaths:
		size += os.path.getsize(fullpath)
	c.send(str(size).encode())

	# Loop through the file list and send each one to the client
	for fullpath in fullpaths:

		# Separator
		c.recv(SC4MP_BUFFER_SIZE)

		# Get relative path to file 
		relpath = os.path.relpath(fullpath, rootpath)

		# Send hashcode
		c.send(md5(fullpath).encode())

		# Separator
		c.recv(SC4MP_BUFFER_SIZE)

		# Send filesize
		c.send(str(os.path.getsize(fullpath)).encode())

		# Separator
		c.recv(SC4MP_BUFFER_SIZE)

		# Send relative path
		c.send(relpath.encode())

		# Send the file if not cached
		if (c.recv(SC4MP_BUFFER_SIZE).decode() != "cached"):
			with open(fullpath, "rb") as file:
				while True:
					bytes_read = file.read(SC4MP_BUFFER_SIZE)
					if not bytes_read:
						break
					c.sendall(bytes_read)


def send_or_cached(c, filename):
	"""TODO"""
	c.send(md5(filename).encode())
	if (c.recv(SC4MP_BUFFER_SIZE).decode() == "not cached"):
		send_file(c, filename)
	else:
		c.close()


def send_file(c, filename):
	"""TODO"""

	report("Sending file " + filename + "...")

	filesize = os.path.getsize(filename)
	c.send(str(filesize).encode())

	with open(filename, "rb") as f:
		while True:
			bytes_read = f.read(SC4MP_BUFFER_SIZE)
			if not bytes_read:
				break
			c.sendall(bytes_read)


def receive_file(c, filename):
	"""TODO"""

	filesize = int(c.recv(SC4MP_BUFFER_SIZE).decode())

	c.send(SC4MP_SEPARATOR)

	report("Receiving " + str(filesize) + " bytes...")
	report("writing to " + filename)

	if (os.path.exists(filename)):
		os.remove(filename)

	filesize_read = 0
	with open(filename, "wb") as f:
		while (filesize_read < filesize):
			bytes_read = c.recv(SC4MP_BUFFER_SIZE)
			if not bytes_read:    
				break
			f.write(bytes_read)
			filesize_read += len(bytes_read)
			#print('Downloading "' + filename + '" (' + str(filesize_read) + " / " + str(filesize) + " bytes)...", int(filesize_read), int(filesize)) #os.path.basename(os.path.normpath(filename))


def xor(conditionA, conditionB):
	return (conditionA or conditionB) and (not (conditionA and conditionB))


def report(message, object=None, type="INFO", ): #TODO do this in the logger to make sure output prints correctly
	"""TODO"""
	'''color = '\033[94m '
	output = datetime.now().strftime("[%H:%M:%S] [SC4MP")
	object = None
	for item in inspect.stack():
		if (object != None):
			break
		try:
			object = item[0].f_locals["self"]
		except:
			pass
	if (object != None):
		output += "/" + object.__class__.__name__
		color = '\033[0m '
	output+= "] [" + type + "] " + message
	if (type=="WARNING"):
		color = '\033[93m '
	elif (type == "ERROR" or type == "FATAL"):
		color = '\033[91m '
	print(color + output)'''
	print("[" + type + "] " + message)


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


def format_version(version):
	"""TODO"""
	return str(version[0]) + "." + str(version[1]) + "." + str(version[2])


def unformat_version(version):
	"""TODO"""
	strings = version.split(".")
	ints = []
	for string in strings:
		ints.append(int(string))
	return tuple(ints)


# Objects

class Config:
	"""TODO"""


	def __init__(self, path, defaults):
		"""TODO"""

		# Parameters
		self.PATH = path
		self.DEFAULTS = defaults

		# Create dictionary with default config settings
		self.data = dict()
		for section in self.DEFAULTS:
			section_name = section[0]
			section_items = section[1]
			self.data.setdefault(section_name, dict())
			for item in section_items:
				item_name = item[0]
				item_value = item[1]
				self.data[section_name].setdefault(item_name, item_value)
		
		# Try to read settings from the config file and update the dictionary accordingly
		parser = configparser.RawConfigParser()
		try:
			parser.read(self.PATH)
			for section_name in self.data.keys():
				section = self.data[section_name]
				try:
					for item_name in section.keys():
						try:
							from_file = parser.get(section_name, item_name)
							if (from_file == "True"):
								self.data[section_name][item_name] = True
							elif (from_file == "False"):
								self.data[section_name][item_name] = False
							elif (from_file == "None"):
								self.data[section_name][item_name] = None
							else:
								t = type(self.data[section_name][item_name])
								self.data[section_name][item_name] = t(from_file)
						except:
							pass
				except:
					pass
		except:
			pass

		# Update config file
		self.update()


	def __getitem__(self, key):
		"""TODO"""
		return self.data.__getitem__(key)


	def __setitem__(self, key, value):
		"""TODO"""
		return self.data.__setitem__(key, value)


	def update(self):
		"""TODO"""
		parser = configparser.RawConfigParser()
		for section_name in self.data.keys():
			parser.add_section(section_name)
			section = self.data[section_name]
			for item_name in section.keys():
				item_value = section[item_name]
				parser.set(section_name, item_name, item_value)
		with open(self.PATH, 'wt') as file:
			parser.write(file)
		try:
			update_config_constants(self)
		except:
			pass


class DBPF:
	"""TODO include credits to original php file"""


	def __init__(self, filename, offset=0):
		"""TODO"""

		report('Parsing "' + filename + '"...', self)

		self.filename = filename
		self.offset = offset

		self.NONSENSE_BYTE_OFFSET = 9

		# Try opening the file to read bytes
		try:
			self.file = open(self.filename, 'rb')
		except Exception as e:
			raise e #TODO

		# Advance to offset
		start = self.offset
		if (self.offset > 0):
			self.file.seek(self.offset)

		# Verify that the file is a DBPF
		test = self.file.read(4)
		if (test != b"DBPF"):
			return #TODO raise exception

		# Read the header
		self.majorVersion = self.read_UL4()
		self.minorVersion = self.read_UL4()
		self.reserved = self.file.read(12)
		self.dateCreated = self.read_UL4()
		self.dateModified = self.read_UL4()
		self.indexMajorVersion = self.read_UL4()
		self.indexCount = self.read_UL4()
		self.indexOffset = self.read_UL4()
		self.indexSize = self.read_UL4()
		self.holesCount = self.read_UL4()
		self.holesOffset = self.read_UL4()
		self.holesSize = self.read_UL4()
		self.indexMinorVersion = self.read_UL4() - 1
		self.reserved2 = self.file.read(32)
		self.header_end = self.file.tell()

		# Seek to index table
		self.file.seek(offset + self.indexOffset)

		# Read index table
		self.indexData = []
		for index in range(0, self.indexCount):
			self.indexData.append(dict())
			self.indexData[index]['typeID'] = self.read_ID()
			self.indexData[index]['groupID'] = self.read_ID()
			self.indexData[index]['instanceID'] = self.read_ID()
			if ((self.indexMajorVersion == "7") and (self.indexMinorVersion == "1")):
				self.indexData[index]['instanceID2'] = self.read_ID()
			self.indexData[index]['offset'] = self.read_UL4()
			self.indexData[index]['filesize'] = self.read_UL4()
			self.indexData[index]['compressed'] = False
			self.indexData[index]['truesize'] = 0


	def decompress(self, length):

		#report('Decompressing ' + str(length) + ' bytes...', self)

		buf = ""
		answer = bytes()
		answerlen = 0
		numplain = ""
		numcopy = ""
		offset = ""

		while (length > 0):
			try:
				cc = self.read_UL1(self.file)
			except Exception as e:
				report(str(e), self, "ERROR")
				break
			length -= 1
			#print("Control char is " + str(cc) + ", length remaining is " + str(length) + ".\n")
			if (cc >= 252): #0xFC
				numplain = cc & 3 #0x03
				if (numplain > length):
					numplain = length
				numcopy = 0
				offset = 0
			elif (cc >= 224): #0xE0
				numplain = (cc - 223) << 2 #223 = 0xdf
				numcopy = 0
				offset = 0
			elif (cc >= 192): #0xC0
				length -= 3
				byte1 = self.read_UL1(self.file)
				byte2 = self.read_UL1(self.file)
				byte3 = self.read_UL1(self.file)
				numplain = cc & 3 #0x03
				numcopy = ((cc & 12) << 6) + 5 + byte3 #12 = 0x0c
				offset = ((cc & 16) << 12) + (byte1 << 8) + byte2 #16 = 0x10
			elif (cc >= 128): #0x80
				length -= 2
				byte1 = self.read_UL1(self.file)
				byte2 = self.read_UL1(self.file)
				numplain = (byte1 & 192) >> 6 #192 = 0xc0
				numcopy = (cc & 63) + 4 #63 = 0x3f
				offset = ((byte1 & 63) << 8) + byte2 #63 = 0x3f
			else:
				length -= 1
				byte1 = self.read_UL1(self.file)
				numplain = (cc & 3) #3 = 0x03
				numcopy = ((cc & 28) >> 2) + 3 #28 = 0x1c
				offset = ((cc & 96) << 3) + byte1 #96 = 0x60
			length -= numplain

			# This section basically copies the parts of the string to the end of the buffer:
			if (numplain > 0):
				buf = self.file.read(numplain)
				answer = answer + buf
			fromoffset = len(answer) - (offset + 1)  # 0 == last char
			for index in range(numcopy):
				#print(str(answer))
				#print(str(cc))
				#print(str(offset))
				#print(str(fromoffset))
				#TODO remove try and except block. decompression algorithm breaks with a control char of 206. the offset becomes larger than the length of the answer, causing a negative fromindex and an indexing error. for now it does not seem to affect city coordinates
				try:
					answer = answer + (answer[fromoffset + index]).to_bytes(1, 'little') #substr(fromoffset + index, 1)
				except Exception as e:
					report(str(e), self, "ERROR")
					return io.BytesIO(answer)
			answerlen += numplain
			answerlen += numcopy

		return io.BytesIO(answer)


	def read_UL1(self, file=None):
		"""TODO"""
		if (file == None):
			file = self.file
		return struct.unpack('<B', file.read(1))[0]


	def read_UL2(self, file=None):
		"""TODO"""
		if (file == None):
			file = self.file
		return struct.unpack('<H', file.read(2))[0]
	
	
	def read_UL4(self, file=None):
		"""TODO"""
		if (file == None):
			file = self.file
		return struct.unpack('<L', file.read(4))[0]


	def read_ID(self, file=None):
		"""TODO"""
		if (file == None):
			file = self.file
		return file.read(4)[::-1].hex()


	def get_indexData_entry_by_type_ID(self, type_id):
		"""TODO"""
		for entry in self.indexData:
			if (entry['typeID'] == type_id):
				return entry


	def goto_subfile(self, type_id):
		"""TODO"""
		entry = self.get_indexData_entry_by_type_ID(type_id)
		self.file.seek(entry['offset'])
		#print(entry['offset'] + 9)


	def get_subfile_size(self, type_id):
		"""TODO"""
		entry = self.get_indexData_entry_by_type_ID(type_id)
		return entry['filesize']


	#def get_subfile_header(self, type_id):
	#	"""TODO"""
	#	self.goto_subfile(type_id)
	#	return (self.read_UL4(), self.read_ID(), ) #TODO how to read these values?


	def decompress_subfile(self, type_id):
		"""TODO"""
		#report('Decompressing "' + type_id + '"...', self)
		self.goto_subfile(type_id)
		self.file.read(self.NONSENSE_BYTE_OFFSET)
		return self.decompress(self.get_subfile_size(type_id))


	def get_SC4ReadRegionalCity(self):
		"""TODO"""

		report('Parsing region view subfile of "' + self.filename + '"...', self)

		data = self.decompress_subfile("ca027edb")
	
		#print(data.read())
		#data.seek(0)

		self.SC4ReadRegionalCity = dict()

		self.SC4ReadRegionalCity['majorVersion'] = self.read_UL2(data)
		self.SC4ReadRegionalCity['minorVersion'] = self.read_UL2(data)
		
		self.SC4ReadRegionalCity['tileXLocation'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['tileYLocation'] = self.read_UL4(data)
		
		self.SC4ReadRegionalCity['citySizeX'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['citySizeY'] = self.read_UL4(data)
		
		self.SC4ReadRegionalCity['residentialPopulation'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['commercialPopulation'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['industrialPopulation'] = self.read_UL4(data)

		self.SC4ReadRegionalCity['unknown1'] = data.read(4) #TODO read float

		self.SC4ReadRegionalCity['mayorRating'] = self.read_UL1(data)
		self.SC4ReadRegionalCity['starCount'] = self.read_UL1(data)
		self.SC4ReadRegionalCity['tutorialFlag'] = self.read_UL1(data)

		self.SC4ReadRegionalCity['cityGUID'] = self.read_UL4(data)

		self.SC4ReadRegionalCity['unknown5'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['unknown6'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['unknown7'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['unknown8'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['unknown9'] = self.read_UL4(data)

		self.SC4ReadRegionalCity['modeFlag'] = self.read_UL1(data)

		#TODO keep reading file

		return self.SC4ReadRegionalCity

	
	def get_cSC4Simulator(self):
		"""TODO"""

		data = self.decompress_subfile("2990c1e5")

		print(data.read())
		data.seek(0)

		self.cSC4Simulator = dict()

		#TODO


# Workers

class Server(th.Thread):
	"""TODO"""


	def __init__(self):
		"""TODO"""

		super().__init__()

		#self.check_version() #TODO
		self.create_subdirectories()
		self.load_config()
		self.prep_database()
		self.clear_temp()
		self.prep_regions() 
		self.prep_backups()

	
	def run(self):
		"""TODO"""

		try:

			global sc4mp_server_running, sc4mp_request_threads

			report("Starting server...")
			sc4mp_server_running = True

			report("- creating socket...")
			s = socket.socket()

			report("- binding host " + SC4MP_HOST + " and port " + str(SC4MP_PORT) + "...")
			s.bind((SC4MP_HOST, SC4MP_PORT))

			report("- listening for connections...")
			s.listen(5)

			try:

				max_request_threads = sc4mp_config["PERFORMANCE"]["max_request_threads"]

				while (sc4mp_server_running):

					if (max_request_threads == None or sc4mp_request_threads < max_request_threads):

						try:

							c, address = s.accept()
							report("Connection accepted with " + str(address[0]) + ":" + str(address[1]) + ".")

							sc4mp_request_threads += 1

							RequestHandler(c).start()	

						except socket.error as e:

							report(str(e), None, "ERROR")
				
					else:

						print("[WARNING] Request thread limit reached!")

						time.sleep(SC4MP_DELAY)
				
			except (SystemExit, KeyboardInterrupt) as e:

				pass

			report("Shutting down...")
			sc4mp_server_running = False

		except Exception as e:

			print("[FATAL] " + str(e))

			sc4mp_server_running = False


	def check_version(self): #TODO doesnt work
		"""TODO"""

		report("Checking for updates...")

		version = []
		for server in SC4MP_SERVERS:
			host = server[0]
			port = server[1]
			try:
				s = socket.socket()
				s.settimeout(5)
				s.connect((host, port))
				s.send(b"server_version")
				bytes = s.recv(SC4MP_BUFFER_SIZE)
				if (len(bytes) > 0):
					split_bytes = bytes.split(SC4MP_SEPARATOR)
					for bytes in split_bytes:
						version.append(int(bytes.decode()))
					break
			except Exception as e:
				print("[ERROR] " + str(e))

		new_version_available = False
		if (len(version) == 3):
			version = tuple(version)
			new_version_available = version > SC4MP_VERSION

		if (new_version_available):
			print("[WARNING] Version v" + '.'.join(version) + " is available!")


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
					report(str(e), None, "ERROR")
					#report("Failed to create " + directory + " subdirectory.", None, "WARNING")
					#report('(this may have been printed by error, check your sc4mp_server_path subdirectory)', None, "WARNING")


	def load_config(self):
		"""TODO"""

		global sc4mp_config, SC4MP_CONFIG_PATH
		SC4MP_CONFIG_PATH = os.path.join(sc4mp_server_path, "serverconfig.ini")

		report("Loading config...")
		
		sc4mp_config = Config(SC4MP_CONFIG_PATH, SC4MP_CONFIG_DEFAULTS)

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


	def prep_database(self):
		"""TODO"""

		report("Preparing database...")

		# Database directory
		database_directory = os.path.join(sc4mp_server_path, "_Database")

		# Users database
		filename = os.path.join(database_directory, "users.json")
		if (not os.path.exists(filename)):
			create_empty_json(filename)

		# Get region directory names
		regions = []
		regions_directory = os.path.join(sc4mp_server_path, "Regions")
		items = os.listdir(regions_directory)
		for item in items:
			path = os.path.join(regions_directory, item)
			if (not os.path.isfile(path)):
				regions.append(item)

		# Create databases for each region
		for region in regions:
			
			# Region directory
			region_directory = os.path.join(regions_directory, region)

			# Create subdirectories in region directory
			region_subdirectories = ["_Database", "_Backups"]
			for region_subdirectory in region_subdirectories:
				directory = os.path.join(region_directory, region_subdirectory)
				if (not os.path.exists(directory)):
					os.makedirs(directory)

			# Get database
			filename = os.path.join(region_directory, "_Database", "region.json")
			data = None
			try:
				data = load_json(filename)
			except:
				data = dict()
			
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
				savegames.append(DBPF(savegame_path))

			# Get the region subfile of each DBPF object and update the database
			for savegame in savegames:

				# Get region subfile
				savegame.get_SC4ReadRegionalCity()

				# Get values from region subfile
				savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
				savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
				savegameSize = savegame.SC4ReadRegionalCity["citySizeX"]

				# Get md5 hashcode of date subfile
				#savegame_date_subfile_hash = file_md5(savegame.decompress_subfile("2990c1e5"))

				# Get dictionary for savegame data
				coords = str(savegameX) + "_" + str(savegameY)
				entry = data.get(coords, dict())
				if (entry == None):
					entry = dict()
				data[coords] = entry

				# Create reset savegame file if needed
				if (not "reset_filename" in entry.keys()):
					reset_directory = os.path.join(region_directory, "_Backups", coords)
					if (not os.path.exists(reset_directory)):
						os.makedirs(reset_directory)
					reset_filename = os.path.join(reset_directory, "reset.sc4")
					shutil.copy(savegame.filename, reset_filename)
					entry["reset_filename"] = reset_filename

				# Set entry values
				set_savegame_data(entry, savegame)

				# Reserve tiles which the savegame occupies
				for offsetX in range(savegameSize):
					x = savegameX + offsetX
					for offsetY in range(savegameSize):
						y = savegameY + offsetY
						data.setdefault(str(x) + "_" + str(y), None)

			# Cleanup DBPF objects to avoid errors when attempting to delete save files
			savegames = None

			update_json(filename, data)

		if (sc4mp_nostart):
			return

		# Database manager
		global sc4mp_database_manager
		sc4mp_database_manager = DatabaseManager()
		sc4mp_database_manager.start()


	def clear_temp(self):
		"""TODO"""

		report("Clearing temporary files...")

		purge_directory(os.path.join(sc4mp_server_path, "_Temp"))


	def prep_regions(self):
		"""TODO"""

		if (sc4mp_nostart):
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
		if (sc4mp_config["BACKUPS"]["backup_server_on_startup"]):
			sc4mp_backups_manager.backup()
		if (not sc4mp_nostart):
			sc4mp_backups_manager.start()


class BackupsManager(th.Thread):
	"""TODO"""

	
	def __init__(self):
		"""TODO"""

		super().__init__()
	

	def run(self):
		"""TODO"""

		try:

			global sc4mp_server_running

			while(not sc4mp_server_running):
				
				time.sleep(SC4MP_DELAY)

			while (sc4mp_server_running):

				try:

					# Delay
					time.sleep(3600 * sc4mp_config["BACKUPS"]["server_backup_interval"])

					# Create backup
					self.backup()

				except Exception as e:

					# Report error
					report(str(e), self, "ERROR")

					# Delay until retrying backup
					time.sleep(60)

		except Exception as e:

			print("[FATAL] " + str(e))

			sc4mp_server_running = False


	def load_json(self, filename):
		"""TODO"""
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except:
			return dict()

	
	def update_json(self, filename, data):
		"""TODO"""
		with open(filename, 'w') as file:
			file.seek(0)
			json.dump(data, file, indent=4)
			file.truncate()


	def backup(self): #TODO stop backing up the backups subdirectory
		"""TODO"""

		# Report creating backups
		report("Creating backup...", self)
				
		# Loop through all files in server directory and append them to a list
		fullpaths = []
		for path, directories, files in os.walk(sc4mp_server_path):
			for file in files:
				fullpaths.append(os.path.join(path, file))

		# Create a files entry for the backup dictionary
		files_entry = dict()

		# Loop through fullpaths and backup the files and add them to the files entry
		for fullpath in fullpaths:
			hashcode = md5(fullpath)
			filesize = os.path.getsize(fullpath)
			directory = os.path.join(sc4mp_server_path, "_Backups", "data")
			if (not os.path.exists(directory)):
				os.makedirs(directory)
			filename = os.path.join(directory, hashcode + "_" + str(filesize))
			if (not os.path.exists(filename) or (not hashcode == md5(filename)) or (not filesize == os.path.getsize(filename))):
				report('- copying "' + fullpath + '"...', self)
				if (os.path.exists(filename)):
					os.remove(filename)
				shutil.copy(fullpath, filename)
			fullpath_entry = dict()
			fullpath_entry["hashcode"] = hashcode
			fullpath_entry["size"] = filesize
			#fullpath_entry["backup_filename"] = filename
			files_entry[fullpath] = fullpath_entry

		# Create dictionary for backup and add the files entry
		backup_data = dict()
		backup_data["files"] = files_entry

		# Update database
		backup_filename = os.path.join(sc4mp_server_path, "_Backups", datetime.now().strftime("%Y%m%d%H%M%S") + ".json")
		self.update_json(backup_filename, backup_data)

		# Report done
		report("Done.", self)


class DatabaseManager(th.Thread):
	"""TODO"""

	
	def __init__(self):
		"""TODO"""

		super().__init__()
	
		self.filename = os.path.join(sc4mp_server_path, "_Database", "users.json")
		self.data = self.load_json(self.filename)


	def run(self):
		"""TODO"""
	
		try:

			global sc4mp_server_running

			while(not sc4mp_server_running):
				
				time.sleep(SC4MP_DELAY)

			#report("Monitoring database for changes...", self) #TODO why is the spacing wrong?
			
			old_data = str(self.data)
			
			while (sc4mp_server_running): #TODO pretty dumb way of checking if a dictionary has been modified. also this thread probably needs to stop at some point
				try:
					time.sleep(SC4MP_DELAY)
					new_data = str(self.data)
					if (old_data != new_data):
						report('Updating "' + self.filename + '"...', self)
						self.update_json(self.filename, self.data)
						report("Done.", self)
					old_data = new_data
				except Exception as e:
					report(str(e), self, "ERROR")

		except Exception as e:

			print("[FATAL] " + str(e))

			sc4mp_server_running = False


	def load_json(self, filename):
		"""TODO"""
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except:
			return dict()

	
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
		self.outputs = dict()
	

	def run(self):
		"""TODO"""

		try:

			global sc4mp_server_running

			while(not sc4mp_server_running):
				
				time.sleep(SC4MP_DELAY)
			
			while (sc4mp_server_running):

				try:

					# Package regions if requested, otherwise check for new tasks
					if (self.export_regions):

						report("Exporting regions as requested...", self)

						export("regions")

						report("Done.", self)

						self.regions_modified = False
						self.export_regions = False

					else:

						# Check for the next task
						if (len(self.tasks) > 0):

							# Get the next task
							task = self.tasks.pop()

							# Read values from tuple
							save_id = task[0]
							user_id = task[1]
							region = task[2]
							savegame = task[3]

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

								# Set "coords" variable. Used as a key in the region database and also for the name of the new save file
								coords = str(savegameX) + "_" + str(savegameY)

								# Get region database
								data_filename = os.path.join(sc4mp_server_path, "Regions", region, "_Database", "region.json")
								data = self.load_json(data_filename)
								
								# Get city entry
								entry = None
								try:
									entry = data[coords]
								except:
									entry = dict()
									data[coords] = entry

								# Filter out godmode savegames if required
								if (sc4mp_config["RULES"]["godmode_filter"]):
									if (savegameModeFlag == 0):
										self.outputs[save_id] = "You must establish a city before claiming a tile."
								
								# Filter out cities that don't match the region configuration
								if (entry == None):
									self.outputs[save_id] = "Invalid city location."

								# Filter out cities of the wrong size
								if ("size" in entry.keys()):
									if (savegameSizeX != savegameSizeY or savegameSizeX != entry["size"]):
										self.outputs[save_id] = "Invalid city size."

								# Filter out claims on tiles with unexpired claims of other users
								if ("owner" in entry.keys()):
									owner = entry["owner"]
									if (owner != None and owner != user_id):
										if (sc4mp_config["RULES"]["claim_duration"] == None):
											self.outputs[save_id] = "City already claimed."
										else:
											expires = datetime.strptime(entry["modified"], "%Y-%m-%d %H:%M:%S") + timedelta(days=sc4mp_config["RULES"]["claim_duration"])
											if (expires > datetime.now()):
												self.outputs[save_id] = "City already claimed."

								# Filter out cliams of users who have exhausted their region claims
								if (sc4mp_config["RULES"]["max_region_claims"] != None):
									claims = 0
									for key in data.keys():
										if (data[key]["owner"] == user_id):
											claims += 1
									if (claims >= sc4mp_config["RULES"]["max_region_claims"]):
										self.outputs[save_id] = "Claim limit reached in this region."

								# Filter out claims of users who have exhausted their total claims
								#TODO

								# Proceed if save push has not been filtered out
								if (not save_id in self.outputs.keys()):

									# Delete previous save file if it exists
									if ("filename" in entry.keys()):
										previous_filename = os.path.join(sc4mp_server_path, "Regions", region, entry["filename"])
										if (os.path.exists(previous_filename)):
											os.remove(previous_filename)

									# Copy save file from temporary directory to regions directory
									destination = os.path.join(sc4mp_server_path, "Regions", region, coords + ".sc4") #TODO include city name?
									if (os.path.exists(destination)):
										os.remove(destination)
									shutil.copy(filename, destination)

									# Copy save file from temporary directory to backup directory
									backup_directory = os.path.join(sc4mp_server_path, "Regions", region, "_Backups", coords)
									if (not os.path.exists(backup_directory)):
										os.makedirs(backup_directory)
									destination = os.path.join(backup_directory, datetime.now().strftime("%Y%m%d%H%M%S") + ".sc4")
									shutil.copy(filename, destination)
									#TODO delete old backups

									# Set entry values
									entry["filename"] = coords + ".sc4"
									entry["owner"] = user_id
									entry["modified"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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

							report("Done.", self)

						else:

							# Clean up inbound temporary files and outputs
							try:
								path = os.path.join(sc4mp_server_path, "_Temp", "inbound")
								for directory in os.listdir(path):
									if (directory in self.outputs.keys()):
										shutil.rmtree(os.path.join(path, directory))
										self.outputs.pop(directory)
							except Exception as e:
								pass
							
							time.sleep(SC4MP_DELAY)

				except Exception as e:

					report(str(e), self, "ERROR")

		except Exception as e:

			print("[FATAL] " + str(e))

			sc4mp_server_running = False


	def load_json(self, filename):
		"""TODO"""
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except:
			return dict()

	
	def update_json(self, filename, data):
		"""TODO"""
		with open(filename, 'w') as file:
			file.seek(0)
			json.dump(data, file, indent=4)
			file.truncate()


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

			try:

				c = self.c

				request = c.recv(SC4MP_BUFFER_SIZE).decode()

				report("Request: " + request, self)

				if (request == "ping"):
					self.ping(c)
				elif (request == "server_id"):
					self.send_server_id(c)
				elif (request == "server_name"):
					self.send_server_name(c)
				elif (request == "server_description"):
					self.send_server_description(c)
				elif (request == "server_version"):
					self.send_server_version(c)
				elif (request == "user_id"):
					self.send_user_id(c)
				elif (request == "token"):
					self.request_header(c)
					self.send_token(c)
				elif (request == "plugins"):
					self.request_header(c)
					self.send_plugins(c)
				elif (request == "regions"):
					self.request_header(c)
					self.send_regions(c)
				elif (request == "save"):
					self.request_header(c)
					self.save(c)
				elif (request == "add_server"):
					self.add_server(c)
				elif (request == "password_enabled"):
					self.password_enabled(c)
				elif (request == "check_password"):
					self.check_password(c)
				elif (request == "user_plugins_enabled"):
					self.user_plugins_enabled(c)
				elif (request == "refresh"):
					self.request_header(c)
					self.refresh(c)

				c.close()
			
				#report("- connection closed.", self)

			except Exception as e:

				print("[ERROR] " + str(e))

			sc4mp_request_threads -= 1

		except Exception as e:

			print("[FATAL] " + str(e))

			sc4mp_server_running = False


	def request_header(self, c):
		"""TODO"""

		c.send(SC4MP_SEPARATOR)
		version = unformat_version(c.recv(SC4MP_BUFFER_SIZE).decode())
		if (version < SC4MP_VERSION):
			c.close()
			raise CustomException("Invalid version.")

		if (sc4mp_config["SECURITY"]["password_enabled"]):
			c.send(SC4MP_SEPARATOR)
			if (c.recv(SC4MP_BUFFER_SIZE).decode() != sc4mp_config["SECURITY"]["password"]):
				c.close()
				raise CustomException("Incorrect password.")

		c.send(SC4MP_SEPARATOR)
		self.user_id = self.log_user(c)


	def ping(self, c):
		"""TODO"""
		c.send(b"pong")


	def send_server_id(self, c):
		"""TODO"""
		c.send(SC4MP_SERVER_ID.encode())


	def send_server_name(self, c):
		"""TODO"""
		c.send(SC4MP_SERVER_NAME.encode())


	def send_server_description(self, c):
		"""TODO"""
		c.send(SC4MP_SERVER_DESCRIPTION.encode())

	
	def send_server_version(self, c):
		"""TODO"""
		c.send(format_version(SC4MP_VERSION).encode())


	def send_user_id(self, c):
		"""TODO"""
		
		c.send(SC4MP_SEPARATOR)
		
		hash = c.recv(SC4MP_BUFFER_SIZE).decode()

		# Get database
		data = sc4mp_database_manager.data

		# Send the user_id that matches the hash
		for user_id in data.keys():
			try:
				token = data[user_id]["token"]
				if (hashlib.sha256((user_id + token).encode()).hexdigest() == hash):
					c.send(user_id.encode())
					break
			except:
				pass


	def send_token(self, c):
		"""TODO"""
		
		user_id = self.user_id

		token = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for i in range(32))

		# Get database
		data = sc4mp_database_manager.data

		# Get database entry for user
		key = user_id
		entry = data.get(key, dict())
		if (entry == None):
			entry = dict()
		data[key] = entry

		# Set token in database entry
		entry["token"] = token

		# Send token
		c.send(token.encode())


	def send_plugins(self, c):
		"""TODO"""

		#filename = os.path.join(sc4mp_server_path, os.path.join("_Temp", os.path.join("outbound", "Plugins.zip")))
		#send_or_cached(c, filename)

		send_tree(c, os.path.join(sc4mp_server_path, "Plugins"))


	def send_regions(self, c):
		"""TODO"""

		if (sc4mp_regions_manager.regions_modified):
			sc4mp_regions_manager.export_regions = True
			while (sc4mp_regions_manager.export_regions):
				time.sleep(SC4MP_DELAY)

		#filename = os.path.join(sc4mp_server_path, os.path.join("_Temp", os.path.join("outbound", "Regions.zip")))
		#send_or_cached(c, filename)

		send_tree(c, os.path.join(sc4mp_server_path, "_Temp", "outbound", "Regions"))


	'''def delete(self, c):
		"""TODO"""

		c.send(SC4MP_SEPARATOR)

		user_id = self.log_user(c)
		c.send(SC4MP_SEPARATOR)
		region = c.recv(SC4MP_BUFFER_SIZE).decode()
		c.send(SC4MP_SEPARATOR)
		city = c.recv(SC4MP_BUFFER_SIZE).decode()

		c.send(SC4MP_SEPARATOR) #TODO verify that the user can make the deletion

		#TODO only delete file if user is authorized

		filename = os.path.join(sc4mp_server_path, os.path.join("Regions", os.path.join(region, city)))

		os.remove(filename)'''


	def save(self, c):
		"""TODO"""
		
		user_id = self.user_id

		# Separator
		c.send(SC4MP_SEPARATOR)

		# Receive file count
		file_count = int(c.recv(SC4MP_BUFFER_SIZE).decode())
		c.send(SC4MP_SEPARATOR)

		# Set save id
		save_id = datetime.now().strftime("%Y%m%d%H%M%S") + "_" + user_id

		# Receive files
		for count in range(file_count):

			# Receive region name
			region = c.recv(SC4MP_BUFFER_SIZE).decode()
			c.send(SC4MP_SEPARATOR)

			# Receive city name
			city = c.recv(SC4MP_BUFFER_SIZE).decode()
			c.send(SC4MP_SEPARATOR)

			# Receive file
			path = os.path.join(sc4mp_server_path, "_Temp", "inbound", save_id, region)
			if (not os.path.exists(path)):
				os.makedirs(path)
			filename = os.path.join(path, str(count) + ".sc4")
			receive_file(c, filename)
			c.send(SC4MP_SEPARATOR)

		# Separator
		c.recv(SC4MP_BUFFER_SIZE)

		# Get path to save directory
		path = os.path.join(sc4mp_server_path, "_Temp", "inbound", save_id)

		# Get regions in save directory
		regions = os.listdir(path)

		# Only allow save pushes of one region
		if (len(regions) > 1):
			c.send(b"Too many regions.")
			return		

		# Loop through regions. Should only loop once since save pushes of multiple regions are filtered out.
		for region in regions:

			# Get region path
			region_path = os.path.join(path, region)

			# Create DBPF objects for each file
			savegames = []
			for filename in os.listdir(region_path):
				filename = os.path.join(region_path, filename)
				savegames.append(DBPF(filename))

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
					if (neighbor == savegame):
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
					if (not condition):
						add = False
				if (add):
					new_savegames.append(savegame)
					report("YES (" + str(savegameX) + ", " + str(savegameY) + ")", self)
				else:
					report("NO (" + str(savegameX) + ", " + str(savegameY) + ")", self)
			savegames = new_savegames

			# Filter out tiles which have identical date subfiles as their previous versions
			if(len(savegames) > 1):
				report("Savegame filter 2", self)
				new_savegames = []
				for savegame in savegames:
					savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
					savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
					coords = str(savegameX) + "_" + str(savegameY)
					data = load_json(os.path.join(sc4mp_server_path, "Regions", region, "_Database", "region.json"))
					if (coords in data.keys()):
						entry = data[coords]
						date_subfile_hashes = entry["date_subfile_hashes"]
						new_date_subfile_hash = file_md5(savegame.decompress_subfile("2990c1e5"))
						if (not new_date_subfile_hash in date_subfile_hashes):
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
			if (len(savegames) == 1):

				# Get the savegame
				savegame = savegames[0]

				# Send the task to the regions manager
				sc4mp_regions_manager.tasks.append((save_id, user_id, region, savegame))

				# Wait for the output
				while (not save_id in sc4mp_regions_manager.outputs.keys()):
					time.sleep(SC4MP_DELAY)

				# Send the output to the client
				c.send((sc4mp_regions_manager.outputs[save_id]).encode())

			else:

				# Report to the client that the save push is invalid
				c.send(b"Unpause the game, then retry.")

			# Delete savegame arrays to avoid file deletion errors
			savegames = None
			new_savegames = None

		# Try to delete temporary files
		#try:
		#	shutil.rmtree(path)
		#except:
		#	pass


	def add_server(self, c):
		"""TODO"""

		if (not sc4mp_config["NETWORK"]["discoverable"]):
			return

		c.send(SC4MP_SEPARATOR)

		#TODO


	def log_user(self, c):
		"""TODO"""

		# Use a hashcode of the user id for extra security
		user_id = hashlib.sha256(c.recv(SC4MP_BUFFER_SIZE)).hexdigest()[:32]
		
		# Get profile database
		data = sc4mp_database_manager.data
		
		# Get data entry that matches user id
		entry = None
		try:
			entry = data[user_id]
		except:
			entry = dict()
			data[user_id] = entry

		# Set default values if missing
		entry.setdefault("IPs", [])
		entry.setdefault("ban", False)
		entry.setdefault("first_contact", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
		#entry.setdefault("banIPs", False) #TODO implement

		# Close connection and throw error if the user is banned
		if (entry["ban"]):
			c.close()
			raise CustomException("Authentication error.")
		
		# Log the time
		entry["last_contact"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

		# Log the IP
		ip = c.getpeername()[0]
		IPs_entry = entry["IPs"]
		if (not ip in IPs_entry):
			IPs_entry.append(ip)
		
		# Return the user id
		return user_id


	def password_enabled(self, c):
		"""TODO"""
		if (sc4mp_config['SECURITY']['password_enabled']):
			c.send(b'yes')
		else:
			c.send(b'no')


	def check_password(self, c):
		"""TODO"""
		c.send(SC4MP_SEPARATOR)
		if (c.recv(SC4MP_BUFFER_SIZE).decode() == sc4mp_config["SECURITY"]["password"]):
			c.send(b'yes')
		else:
			c.send(b'no')


	def user_plugins_enabled(self, c):
		"""TODO"""
		if (sc4mp_config['RULES']['user_plugins']):
			c.send(b'yes')
		else:
			c.send(b'no')


	def refresh(self, c):
		"""TODO"""

		user_id = self.user_id

		# Loop through regions
		regions_directory = os.path.join(sc4mp_server_path, "Regions")
		for region in os.listdir(regions_directory):
			if (os.path.isdir(os.path.join(regions_directory, region))):
				#print(region)
				region_data = load_json(os.path.join(sc4mp_server_path, "Regions", region, "_Database", "region.json"))
				for coords in region_data.keys():
					#print(coords)
					city_entry = region_data[coords]
					if (city_entry != None and city_entry["owner"] != user_id):
						c.send(city_entry["hashcode"].encode())
						if (c.recv(SC4MP_BUFFER_SIZE).decode() == "missing"):
							c.send(region.encode())
							c.recv(SC4MP_BUFFER_SIZE)
							send_file(c, os.path.join(sc4mp_server_path, "Regions", region, city_entry["filename"]))
							c.recv(SC4MP_BUFFER_SIZE)
		c.send(b'done')


# Exceptions

class CustomException(Exception):
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
		self.log = SC4MP_LOG_PATH
		if (os.path.exists(self.log)):
			os.remove(self.log)
   

	def write(self, message):
		"""TODO"""

		output = message

		if (message != "\n"):

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
			type = "[INFO] "
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
				if (message[:len(current_type)] == current_type):
					message = message[len(current_type):]
					type = current_type
					color = current_color
					break
			if (th.current_thread().getName() == "Main" and type == "[INFO] "):
				color = '\033[00m '
			
			# Assemble
			output = color + timestamp + label + type + message

		# Print
		self.terminal.write(output)
		with open(self.log, "a") as log:
			log.write(output)
			log.close()  


	def flush(self):
		"""TODO"""
		self.terminal.flush()


# Main Method

def main():
	"""The main method."""

	try:

		# Output
		sys.stdout = Logger()
		th.current_thread().name = "Main"

		# Title
		report(SC4MP_TITLE)

		# "-prep" argument
		global sc4mp_nostart
		sc4mp_nostart = "-prep" in sc4mp_args

		# "--server-path" argument
		global sc4mp_server_path
		try:
			ARGUMENT = "--server-path"
			if (ARGUMENT in sc4mp_args):
				sc4mp_server_path = sc4mp_args[sc4mp_args.index(ARGUMENT) + 1]
		except Exception as e:
			raise CustomException("Invalid arguments.")

		# Server
		global sc4mp_server
		sc4mp_server = Server()
		if (not sc4mp_nostart):
			sc4mp_server.run()

	except Exception as e:

		report(str(e), None, "FATAL")
		traceback.print_exc()

		global sc4mp_server_running
		sc4mp_server_running = False

if __name__ == '__main__':
	main()
